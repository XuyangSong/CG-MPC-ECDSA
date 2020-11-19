use cg_ecdsa_core::{
    CLGroup, Ciphertext as CLCipher, ClKeyPair, DlogCommitment, DlogCommitmentOpen, EcKeyPair,
    PromiseCipher, PromiseProof, PromiseState, PromiseWit, ProofError, Signature, SECURITY_BITS,
    SK as CLSK,
};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};

#[derive(Clone, Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

#[derive(Clone, Debug)]
pub struct KeyGen {
    pub party_index: usize,
    pub params: Parameters,
    pub ec_keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub private_signing_key: EcKeyPair, // (u_i, u_iP)
    pub public_signing_key: GE,         // Q
    pub share_private_key: FE,          // x_i
}

#[derive(Clone, Debug)]
pub struct SignPhase {
    pub party_index: usize,
    pub params: Parameters,
    pub omega: FE,
    pub party_num: usize,
    pub k: FE,
    pub gamma: FE,
}

#[derive(Clone, Debug)]
pub struct SignPhaseOneMsg {
    pub commitment: BigInt,
    pub promise_state: PromiseState,
    pub proof: PromiseProof,
}

#[derive(Clone, Debug)]
pub struct SignPhaseTwoMsg {
    pub party_index: usize,
    pub homocipher: CLCipher,
    pub homocipher_plus: CLCipher,
    pub t_p: FE,
    pub t_p_plus: FE,
    pub b: GE,
}

#[derive(Clone, Debug)]
pub struct SignPhaseThreeMsg {
    pub delta: FE,
}

#[derive(Clone, Debug)]
pub struct SignPhaseFourMsg {
    pub open: DlogCommitmentOpen,
}

#[derive(Clone, Debug)]
pub struct SignPhaseFiveStepOneMsg {
    commitment: BigInt,
}

#[derive(Clone, Debug)]
pub struct SignPhaseFiveStepTwoMsg {
    v_i: GE,
    a_i: GE,
    b_i: GE,
    blind: BigInt,
    dl_proof: DLogProof,
    proof: HomoELGamalProof,
}

#[derive(Clone, Debug)]
pub struct SignPhaseFiveStepFourMsg {
    commitment: BigInt,
}

#[derive(Clone, Debug)]
pub struct SignPhaseFiveStepFiveMsg {
    blind: BigInt,
    u_i: GE,
    t_i: GE,
}

#[derive(Clone, Debug)]
pub struct SignPhaseFiveStepSevenMsg {
    pub s_i: FE,
}

impl KeyGen {
    pub fn phase_one_init(group: &CLGroup, party_index: usize, params: Parameters) -> Self {
        let ec_keypair = EcKeyPair::new(); // Generate ec key pair.
        let cl_keypair = ClKeyPair::new(group); // Generate cl key pair.
        let private_signing_key = EcKeyPair::new(); // Generate private key pair.
        let public_signing_key = private_signing_key.get_public_key().clone(); // Init public key, compute later.
        let share_private_key = ECScalar::zero(); // Init share private key, compute later.
        Self {
            party_index,
            params,
            ec_keypair,
            cl_keypair,
            private_signing_key,
            public_signing_key,
            share_private_key,
        }
    }

    pub fn phase_two_generate_dl_com(&self) -> DlogCommitment {
        DlogCommitment::new(&self.private_signing_key.get_public_key())
    }

    pub fn phase_three_verify_dl_com_and_generate_signing_key(
        &mut self,
        dl_com_vec: &Vec<DlogCommitment>,
    ) -> Result<(), ProofError> {
        assert_eq!(dl_com_vec.len(), self.params.share_count - 1);

        for element in dl_com_vec.iter() {
            element.verify()?;
            self.public_signing_key = self.public_signing_key + element.get_public_share();
        }

        Ok(())
    }

    pub fn phase_four_generate_vss(&self) -> (VerifiableSS, Vec<FE>, usize) {
        let (vss_scheme, secret_shares) = VerifiableSS::share(
            self.params.threshold as usize,
            self.params.share_count as usize,
            self.private_signing_key.get_secret_key(),
        );

        (vss_scheme, secret_shares, self.party_index)
    }

    pub fn phase_five_verify_vss_and_generate_pok_dlog(
        &mut self,
        q_vec: &Vec<GE>,
        secret_shares_vec: &Vec<FE>,
        vss_scheme_vec: &Vec<VerifiableSS>,
    ) -> Result<DLogProof, ProofError> {
        assert_eq!(q_vec.len(), self.params.share_count);
        assert_eq!(secret_shares_vec.len(), self.params.share_count);
        assert_eq!(vss_scheme_vec.len(), self.params.share_count);

        // Check VSS
        for i in 0..q_vec.len() {
            if !(vss_scheme_vec[i]
                .validate_share(&secret_shares_vec[i], self.party_index + 1)
                .is_ok()
                && vss_scheme_vec[i].commitments[0] == q_vec[i])
            {
                // TBD: use new error type
                return Err(ProofError);
            }
        }

        // Compute share private key(x_i)
        self.share_private_key = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
        let dlog_proof = DLogProof::prove(&self.share_private_key);

        Ok(dlog_proof)
    }

    pub fn phase_six_verify_dlog_proof(
        &self,
        dlog_proofs: &Vec<DLogProof>,
    ) -> Result<(), ProofError> {
        assert_eq!(dlog_proofs.len(), self.params.share_count);
        for i in 0..self.params.share_count {
            DLogProof::verify(&dlog_proofs[i]).unwrap();
        }

        Ok(())
    }
}

impl SignPhase {
    pub fn init(
        party_index: usize,
        params: Parameters,
        vss_scheme: &VerifiableSS,
        subset: &[usize],
        x: &FE,
        party_num: usize,
    ) -> Result<Self, ProofError> {
        let lamda = vss_scheme.map_share_to_new_params(party_index, subset);
        let omega = lamda * x;

        Ok(Self {
            party_index,
            params,
            omega,
            party_num,
            k: FE::zero(),  // Init k, generate later.
            gamma: FE::zero(), // Init gamma, generate later.
        })
    }

    pub fn phase_one_generate_promise_sigma_and_com(
        &mut self,
        group: &CLGroup,
        cl_keypair: &ClKeyPair,
        ec_keypair: &EcKeyPair,
    ) -> (SignPhaseOneMsg, SignPhaseFourMsg) {
        // Generate promise sigma
        self.k = FE::new_random();

        let cipher = PromiseCipher::encrypt(
            group,
            cl_keypair.get_public_key(),
            ec_keypair.get_public_key(),
            &self.k,
        );

        let promise_state = PromiseState {
            cipher: cipher.0.clone(),
            ec_pub_key: ec_keypair.public_share,
            cl_pub_key: cl_keypair.cl_pub_key.clone(),
        };
        let promise_wit = PromiseWit {
            x: self.k,
            r1: cipher.1,
            r2: cipher.2,
        };
        let proof = PromiseProof::prove(group, &promise_state, &promise_wit);

        // Generate commitment
        let gamma_pair = EcKeyPair::new();
        self.gamma = gamma_pair.get_secret_key().clone();
        let dl_com = DlogCommitment::new(&gamma_pair.get_public_key());

        (
            SignPhaseOneMsg {
                commitment: dl_com.commitment,
                promise_state: promise_state,
                proof,
            },
            SignPhaseFourMsg { open: dl_com.open },
        )
    }

    pub fn phase_two_generate_homo_cipher(
        &self,
        group: &CLGroup,
        sign_phase_one_msg_vec: &Vec<SignPhaseOneMsg>,
    ) -> (Vec<SignPhaseTwoMsg>, Vec<(FE, FE)>) {
        assert_eq!(sign_phase_one_msg_vec.len(), self.party_num);
        let mut msgs: Vec<SignPhaseTwoMsg> = Vec::new();
        let mut randoms: Vec<(FE, FE)> = Vec::new();
        let zero = FE::zero();
        for msg in sign_phase_one_msg_vec.iter() {
            // Verify promise proof
            msg.proof.verify(group, &msg.promise_state).unwrap();

            // Homo
            let cipher = &msg.promise_state.cipher;
            let homocipher;
            let homocipher_plus;
            let t_p;
            let t_p_plus;
            let b;

            let beta = FE::new_random();
            {
                // Generate random.
                let t = BigInt::sample_below(&(&group.stilde * BigInt::from(2).pow(40) * &FE::q()));
                t_p = ECScalar::from(&t.mod_floor(&FE::q()));
                let rho_plus_t = self.gamma.to_big_int() + t;

                // Handle CL cipher.
                let (r_cipher, _r_blind) =
                    CLCipher::encrypt_without_r(&group, &zero.sub(&beta.get_element()));
                let c11 = cipher.c1.exp(&rho_plus_t);
                let c21 = cipher.c2.exp(&rho_plus_t);
                let c1 = c11.compose(&r_cipher.c1).reduce();
                let c2 = c21.compose(&r_cipher.c2).reduce();
                homocipher = CLCipher { c1, c2 };
            }

            let v = FE::new_random();
            {
                // Generate random.
                let t = BigInt::sample_below(&(&group.stilde * BigInt::from(2).pow(40) * &FE::q()));
                t_p_plus = ECScalar::from(&t.mod_floor(&FE::q()));
                let omega_plus_t = self.omega.to_big_int() + t;

                // Handle CL cipher.
                let (r_cipher, _r_blind) =
                    CLCipher::encrypt_without_r(&group, &zero.sub(&v.get_element()));
                let c11 = cipher.c1.exp(&omega_plus_t);
                let c21 = cipher.c2.exp(&omega_plus_t);
                let c1 = c11.compose(&r_cipher.c1).reduce();
                let c2 = c21.compose(&r_cipher.c2).reduce();
                homocipher_plus = CLCipher { c1, c2 };

                let base: GE = ECPoint::generator();
                b = base * v;
            }

            let msg = SignPhaseTwoMsg {
                party_index: self.party_index,
                homocipher,
                homocipher_plus,
                t_p,
                t_p_plus,
                b,
            };
            msgs.push(msg);
            randoms.push((beta, v));
        }

        (msgs, randoms)
    }

    pub fn phase_two_decrypt_and_verify(
        &self,
        group: &CLGroup,
        sk: &CLSK,
        random_vec: &Vec<(FE, FE)>,
        msg_vec: &Vec<SignPhaseTwoMsg>,
        omega_big_vec: &Vec<GE>,
    ) -> (SignPhaseThreeMsg, FE) {
        assert_eq!(msg_vec.len(), self.party_num - 1);
        assert_eq!(random_vec.len(), self.party_num - 1);
        assert_eq!(omega_big_vec.len(), self.party_num - 1);
        let mut delta = self.k * self.gamma;
        let mut sigma = self.k * self.omega;
        for i in 0..msg_vec.len() {
            // Compute delta
            let k_mul_t = self.k * msg_vec[i].t_p;
            let alpha =
                CLCipher::decrypt(&group, &sk, &msg_vec[i].homocipher).sub(&k_mul_t.get_element());
            delta = delta + alpha + random_vec[i].0;

            // Compute sigma
            let k_mul_t_plus = self.k * msg_vec[i].t_p_plus;
            let miu = CLCipher::decrypt(&group, &sk, &msg_vec[i].homocipher_plus)
                .sub(&k_mul_t_plus.get_element());
            sigma = sigma + miu + random_vec[i].1;

            // Check kW = uP + B
            let k_omega = omega_big_vec[i] * self.k;
            let base: GE = ECPoint::generator();
            let up_plus_b = base * miu + msg_vec[i].b;
            assert_eq!(k_omega, up_plus_b);
        }

        (SignPhaseThreeMsg { delta }, sigma)
    }

    pub fn phase_two_compute_delta_sum(&self, delta_vec: &Vec<SignPhaseThreeMsg>) -> FE {
        assert_eq!(delta_vec.len(), self.party_num);
        delta_vec.iter().fold(FE::zero(), |acc, x| acc + x.delta)
    }

    // TBD: put r and r_x in self.
    pub fn phase_four_verify_dl_com(
        &self,
        delta: &FE,
        dl_com_vec: &Vec<SignPhaseOneMsg>,
        dl_open_vec: &Vec<SignPhaseFourMsg>,
    ) -> Result<(FE, GE), ProofError> {
        assert_eq!(dl_com_vec.len(), self.party_num);
        assert_eq!(dl_open_vec.len(), self.party_num);
        for i in 0..dl_com_vec.len() {
            DlogCommitment::verify_dlog(&dl_com_vec[i].commitment, &dl_open_vec[i].open)?;
        }

        let (head, tail) = dl_open_vec.split_at(1);
        let mut r = tail.iter().fold(head[0].open.public_share, |acc, x| {
            acc + x.open.public_share
        });

        r = r * delta.invert();
        let r_x: FE = ECScalar::from(&r.x_coor().unwrap().mod_floor(&FE::q()));
        Ok((r_x, r))
    }

    pub fn phase_five_step_onetwo_generate_com_and_zk(
        &self,
        message: &FE,
        sigma: &FE,
        r_x: &FE,
        r: &GE,
    ) -> (
        SignPhaseFiveStepOneMsg,
        SignPhaseFiveStepTwoMsg,
        SignPhaseFiveStepSevenMsg,
        FE,
        FE,
    ) {
        let s_i = (*message) * self.k + (*sigma) * r_x;
        let l_i: FE = ECScalar::new_random();
        let rho_i: FE = ECScalar::new_random();
        let l_i_rho_i = l_i * rho_i;

        let base: GE = ECPoint::generator();
        let v_i = r * &s_i + base * l_i;
        let a_i = base * rho_i;
        let b_i = base * l_i_rho_i;

        // Generate com
        let blind = BigInt::sample(SECURITY_BITS);
        let input_hash = HSha256::create_hash_from_ge(&[&v_i, &a_i, &b_i]).to_big_int();
        let commitment =
            HashCommitment::create_commitment_with_user_defined_randomness(&input_hash, &blind);

        // Generate zk proof
        let witness = HomoElGamalWitness { r: l_i, x: s_i };
        let delta = HomoElGamalStatement {
            G: a_i,
            H: *r,
            Y: base,
            D: v_i,
            E: b_i,
        };
        let dl_proof = DLogProof::prove(&rho_i);
        let proof = HomoELGamalProof::prove(&witness, &delta);

        let msg_step_one = SignPhaseFiveStepOneMsg { commitment };
        let msg_step_two = SignPhaseFiveStepTwoMsg {
            v_i,
            a_i,
            b_i,
            blind,
            dl_proof,
            proof,
        };
        let msg_step_seven = SignPhaseFiveStepSevenMsg { s_i };

        (msg_step_one, msg_step_two, msg_step_seven, rho_i, l_i)
    }

    pub fn phase_five_step_three_verify_com_and_zk(
        message: &FE,
        q: &GE,
        r_x: &FE,
        r: &GE,
        rho_i: &FE,
        l_i: &FE,
        msgs_step_one: &Vec<SignPhaseFiveStepOneMsg>,
        msgs_step_two: &Vec<SignPhaseFiveStepTwoMsg>,
    ) -> Result<(SignPhaseFiveStepFourMsg, SignPhaseFiveStepFiveMsg), ProofError> {
        // TBD: check the size

        let base: GE = ECPoint::generator();

        for i in 0..msgs_step_one.len() {
            // TBD: skip my own check

            // Verify commitment
            let input_hash = HSha256::create_hash_from_ge(&[
                &msgs_step_two[i].v_i,
                &msgs_step_two[i].a_i,
                &msgs_step_two[i].b_i,
            ])
            .to_big_int();

            if HashCommitment::create_commitment_with_user_defined_randomness(
                &input_hash,
                &msgs_step_two[i].blind,
            ) != msgs_step_one[i].commitment
            {
                return Err(ProofError);
            }

            // Verify zk proof
            let delta = HomoElGamalStatement {
                G: msgs_step_two[i].a_i,
                H: *r,
                Y: base,
                D: msgs_step_two[i].v_i,
                E: msgs_step_two[i].b_i,
            };

            msgs_step_two[i].proof.verify(&delta).unwrap();
            DLogProof::verify(&msgs_step_two[i].dl_proof).unwrap();
        }

        // Compute V = -mP -rQ + sum (vi)
        let (head, tail) = msgs_step_two.split_at(1);
        let v_sum = tail.iter().fold(head[0].v_i, |acc, x| acc + x.v_i);
        let a_sum = tail.iter().fold(head[0].a_i, |acc, x| acc + x.a_i);
        let mp = base * message;
        let rq = q * r_x;
        let v_big = v_sum
            .sub_point(&mp.get_element())
            .sub_point(&rq.get_element());

        let u_i = v_big * rho_i;
        let t_i = a_sum * l_i;
        let input_hash = HSha256::create_hash_from_ge(&[&u_i, &t_i]).to_big_int();
        let blind = BigInt::sample(SECURITY_BITS);
        let commitment =
            HashCommitment::create_commitment_with_user_defined_randomness(&input_hash, &blind);

        let msg_step_four = SignPhaseFiveStepFourMsg { commitment };
        let msg_step_five = SignPhaseFiveStepFiveMsg { blind, u_i, t_i };

        Ok((msg_step_four, msg_step_five))
    }

    pub fn phase_five_step_six_verify_com_and_check_sum_a_t(
        msgs_step_four: &Vec<SignPhaseFiveStepFourMsg>,
        msgs_step_five: &Vec<SignPhaseFiveStepFiveMsg>,
    ) -> Result<(), ProofError> {
        assert_eq!(msgs_step_four.len(), msgs_step_five.len());
        assert_eq!(msgs_step_four.len(), msgs_step_five.len());
        let test_com = (0..msgs_step_four.len())
            .map(|i| {
                let input_hash =
                    HSha256::create_hash_from_ge(&[&msgs_step_five[i].u_i, &msgs_step_five[i].t_i])
                        .to_big_int();
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &input_hash,
                    &msgs_step_five[i].blind,
                ) == msgs_step_four[i].commitment
            })
            .all(|x| x);

        let t_vec = (0..msgs_step_four.len())
            .map(|i| msgs_step_five[i].t_i)
            .collect::<Vec<GE>>();
        let u_vec = (0..msgs_step_four.len())
            .map(|i| msgs_step_five[i].u_i)
            .collect::<Vec<GE>>();

        let base: GE = ECPoint::generator();
        let biased_sum_ti = t_vec.iter().fold(base, |acc, x| acc + *x);
        let biased_sum_ti_minus_ui = u_vec
            .iter()
            .fold(biased_sum_ti, |acc, x| acc.sub_point(&x.get_element()));

        if !test_com || base != biased_sum_ti_minus_ui {
            return Err(ProofError);
        }

        Ok(())
    }

    pub fn phase_five_step_eight_generate_signature(
        msgs_step_seven: &Vec<SignPhaseFiveStepSevenMsg>,
        r_x: &FE,
    ) -> Signature {
        let mut s = msgs_step_seven
            .iter()
            .fold(FE::zero(), |acc, x| acc + x.s_i);
        let s_bn = s.to_big_int();
        let s_tag_bn = FE::q() - &s_bn;
        if s_bn > s_tag_bn {
            s = ECScalar::from(&s_tag_bn);
        }

        Signature { s, r: *r_x }
    }
}
