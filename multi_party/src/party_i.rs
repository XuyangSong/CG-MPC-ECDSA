use cg_ecdsa_core::{
    CLGroup, Ciphertext as CLCipher, ClKeyPair, CommWitness, DLComZK, DLCommitments, EcKeyPair,
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

impl KeyGen {
    pub fn phase_one_init(group: &CLGroup, party_index: usize, params: Parameters) -> Self {
        let ec_keypair = EcKeyPair::new();
        let cl_keypair = ClKeyPair::new(group);
        let private_signing_key = EcKeyPair::new();
        let public_signing_key = ECPoint::generator();
        let share_private_key = ECScalar::zero();
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

    pub fn phase_two_generate_dl_com_zk(&self) -> DLComZK {
        DLComZK::new(&self.private_signing_key)
    }

    pub fn phase_three_verify_dl_com_zk_and_generate_signing_key(
        &mut self,
        dl_com_zk_vec: &Vec<DLComZK>,
    ) -> Result<(), ProofError> {
        // TBD: add size test

        let mut signing_key = *self.private_signing_key.get_public_key();
        for element in dl_com_zk_vec.iter() {
            element.verify_commitments_and_dlog_proof()?;
            signing_key = signing_key + element.get_public_share();
        }

        self.public_signing_key = signing_key;

        Ok(())
    }

    pub fn phase_four_generate_vss(&self) -> (VerifiableSS, Vec<FE>) {
        VerifiableSS::share(
            self.params.threshold as usize,
            self.params.share_count as usize,
            self.private_signing_key.get_secret_key(),
        )
    }

    pub fn phase_five_verify_vss_and_generate_pok_dlog(
        &mut self,
        q_vec: &Vec<GE>,
        secret_shares_vec: &Vec<FE>,
        vss_scheme_vec: &Vec<&VerifiableSS>,
    ) -> Result<DLogProof, ProofError> {
        // TBD: add size test
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

        // let (head, tail) = q_vec.split_at(1);
        // let y = tail.iter().fold(head[0], |acc, x| acc + x);
        let x_i = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
        let dlog_proof = DLogProof::prove(&x_i);
        self.share_private_key = x_i;
        Ok(dlog_proof)
    }

    pub fn phase_six_verify_dlog_proof(
        &self,
        dlog_proofs: &Vec<DLogProof>,
    ) -> Result<(), ProofError> {
        // TBD: add size test
        for i in 0..((self.params.share_count - 1) as usize) {
            DLogProof::verify(&dlog_proofs[i]).unwrap();
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SignPhase {
    pub party_index: usize,
    pub params: Parameters,
    pub omega: FE,
    // pub party_num: u16,
}

#[derive(Clone, Debug)]
pub struct SignPhaseOneMsg {
    pub commitment: DLCommitments,
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
    pub witness: CommWitness,
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

impl SignPhase {
    pub fn init(
        party_index: usize,
        params: Parameters,
        vss_scheme: &VerifiableSS,
        subset: &[usize],
        x: &FE,
        // party_num: u16,
    ) -> Result<Self, ProofError> {
        // if party_num > params.share_count || party_num <= params.threshold {
        //     return Err(ProofError);
        // }
        let lamda = vss_scheme.map_share_to_new_params(party_index, subset);
        let omega = lamda * x;

        Ok(Self {
            party_index,
            params,
            omega,
            // party_num,
        })
    }

    pub fn phase_one_generate_promise_sigma_and_com(
        group: &CLGroup,
        cl_keypair: &ClKeyPair,
        ec_keypair: &EcKeyPair,
    ) -> (SignPhaseOneMsg, FE, FE, SignPhaseFourMsg) {
        // Generate promise sigma
        let k: FE = FE::new_random();
        let cipher = PromiseCipher::encrypt(
            group,
            cl_keypair.get_public_key(),
            ec_keypair.get_public_key(),
            &k,
        );

        let promise_state = PromiseState {
            cipher: cipher.0.clone(),
            ec_pub_key: ec_keypair.public_share,
            cl_pub_key: cl_keypair.cl_pub_key.clone(),
        };
        let promise_wit = PromiseWit {
            x: k,
            r1: cipher.1,
            r2: cipher.2,
        };
        let proof = PromiseProof::prove(group, &promise_state, &promise_wit);

        // Generate commitment
        let gamma_pair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&gamma_pair);
        // let commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        // let commitment = HashCommitment::create_commitment_with_user_defined_randomness(
        //     &gamma_pair.get_public_key().bytes_compressed_to_big_int(),
        //     &commitment_blind_factor,
        // );

        let msg = SignPhaseOneMsg {
            commitment: dl_com_zk.commitments,
            promise_state: promise_state,
            proof,
        };

        (
            msg,
            k,
            gamma_pair.secret_share,
            SignPhaseFourMsg {
                witness: dl_com_zk.witness,
            },
        )
    }

    pub fn phase_two_generate_homo_cipher(
        &self,
        group: &CLGroup,
        gamma: &FE,
        omega: &FE,
        sign_phase_one_msg_vec: &Vec<SignPhaseOneMsg>,
    ) -> (Vec<SignPhaseTwoMsg>, Vec<(FE, FE)>) {
        let mut msgs: Vec<SignPhaseTwoMsg> = Vec::new();
        let mut randoms: Vec<(FE, FE)> = Vec::new();
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
                let rho_plus_t = gamma.to_big_int() + t;

                // Handle CL cipher.
                let (r_cipher, _r_blind) = CLCipher::encrypt_without_r(&group, &beta.invert());
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
                let rho_plus_t = omega.to_big_int() + t;

                // Handle CL cipher.
                let (r_cipher, _r_blind) = CLCipher::encrypt_without_r(&group, &v.invert());
                let c11 = cipher.c1.exp(&rho_plus_t);
                let c21 = cipher.c2.exp(&rho_plus_t);
                let c1 = c11.compose(&r_cipher.c1).reduce();
                let c2 = c21.compose(&r_cipher.c2).reduce();
                homocipher_plus = CLCipher { c1, c2 };

                let base: GE = ECPoint::generator();
                b = base.scalar_mul(&v.get_element());
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
        group: &CLGroup,
        sk: &CLSK,
        k: &FE,
        gamma: &FE,
        omega: &FE,
        random_vec: &Vec<(FE, FE)>,
        msg_vec: &Vec<SignPhaseTwoMsg>,
    ) -> (SignPhaseThreeMsg, FE) {
        let mut delta = (*k) * (*gamma);
        let mut sigma = (*k) * (*omega);
        for i in 0..msg_vec.len() {
            // Compute delta
            let k_mul_t = (*k) * msg_vec[i].t_p;
            let alpha =
                CLCipher::decrypt(&group, &sk, &msg_vec[i].homocipher).sub(&k_mul_t.get_element());
            delta = delta + alpha + random_vec[i].0;

            // Compute sigma
            let k_mul_t_plus = (*k) * msg_vec[i].t_p_plus;
            let miu = CLCipher::decrypt(&group, &sk, &msg_vec[i].homocipher_plus)
                .sub(&k_mul_t_plus.get_element());
            sigma = sigma + miu + random_vec[i].1;

            // TBD: Check kW = uP + B
            // let base: GE = ECPoint::generator();
        }

        (SignPhaseThreeMsg { delta }, sigma)
    }

    pub fn phase_two_compute_delta_sum(delta_vec: &Vec<SignPhaseThreeMsg>) -> FE {
        // TBD: use acc
        let mut delta_sum = delta_vec[0].delta;
        for i in delta_vec.iter().skip(1) {
            delta_sum = delta_sum + i.delta;
        }

        delta_sum
    }

    pub fn phase_four_verify_dl_com_zk(
        // gamma_i: &GE,
        delta: &FE,
        dl_com_zk_vec: &Vec<DLComZK>,
    ) -> Result<(FE, GE), ProofError> {
        // TBD: fix it
        for dl_com_zk in dl_com_zk_vec.iter() {
            dl_com_zk.verify_commitments_and_dlog_proof()?;
            // r = r + dl_com_zk.witness.public_share;
        }

        let (head, tail) = dl_com_zk_vec.split_at(1);
        let mut r = tail.iter().fold(head[0].get_public_share(), |acc, x| {
            acc + x.get_public_share()
        });

        r = r * delta.invert();
        let r_x: FE = ECScalar::from(&r.x_coor().unwrap().mod_floor(&FE::q()));
        Ok((r_x, r))
    }

    pub fn phase_five_step_onetwo_generate_com_and_zk(
        message: &FE,
        k: &FE,
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
        let s_i = (*message) * k + (*sigma) * r_x;
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
        // v_i: &GE,
        // a_i: &GE,
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

            // v_sum = v_sum + msgs_step_two[i].v_i;
            // a_sum = a_sum + msgs_step_two[i].a_i;
        }
        // V = -mP -rQ + sum (vi)
        let (head, tail) = msgs_step_two.split_at(1);
        let v_sum = tail.iter().fold(head[0].v_i, |acc, x| acc + x.v_i);
        let a_sum = tail.iter().fold(head[0].a_i, |acc, x| acc + x.a_i);
        let mp = base * message;
        let rq = q * r_x;
        let v_big = v_sum
            .sub_point(&mp.get_element())
            .sub_point(&rq.get_element());
        // let mut v_sum = (*v_i)
        //     .sub_point(&mp.get_element())
        //     .sub_point(&rq.get_element());
        // let mut a_sum = *a_i;

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
            .map(|i| &msgs_step_five[i].t_i)
            .collect::<Vec<&GE>>();
        let u_vec = (0..msgs_step_four.len())
            .map(|i| &msgs_step_five[i].u_i)
            .collect::<Vec<&GE>>();

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
        // s_i: &FE,
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
