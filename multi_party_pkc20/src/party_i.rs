use cg_ecdsa_core::{
    CLGroup, Ciphertext as CLCipher, ClKeyPair, DlogCommitment, DlogCommitmentOpen, EcKeyPair,
    CLEncProof, CLEncState, CLEncWit, ProofError, Signature, SECURITY_BITS,
    SK as CLSK, BinaryQF,
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
pub struct Setup {
    pub k: usize,
    pub r: BigInt,
    pub t: BigInt,
    pub gi: BinaryQF,
    pub gp: BinaryQF,
}

#[derive(Clone, Debug)]
pub struct SetupPhaseOneMsg {
    pub commitment: BigInt,
}

#[derive(Clone, Debug)]
pub struct SetupPhaseTwoMsg {
    pub open: (BigInt, BigInt),
}

#[derive(Clone, Debug)]
pub struct SetupPhaseThreeMsg {
    pub commitment: BigInt,
}

#[derive(Clone, Debug)]
pub struct SetupPhaseFourMsg {
    pub open: (BinaryQF, BigInt),
}

#[derive(Clone, Debug)]
pub struct SetupPhaseFiveMsg {
    // TBD: remove h
    pub h: BinaryQF,
    pub t: BinaryQF,
    pub u: BigInt,
}

#[derive(Clone, Debug)]
pub struct KeyGen {
    pub party_index: usize,
    pub params: Parameters,
    // pub ec_keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub private_signing_key: EcKeyPair, // (u_i, u_iP)
    pub public_signing_key: GE,         // Q
    pub share_private_key: FE,          // x_i
    pub share_public_key: Vec<GE>,      // X_i
    pub vss_scheme_vec: Vec<VerifiableSS>,
}

#[derive(Clone, Debug)]
pub struct SignPhase {
    pub party_index: usize,
    pub party_num: usize,
    pub params: Parameters,
    pub omega: FE,
    pub big_omega_vec: Vec<GE>,
    pub k: FE,
    pub gamma: FE,
    pub sigma: FE,
    pub delta_sum: FE,
    pub r_x: FE,
    pub r_point: GE,
    pub rho: FE,
    pub l: FE,
    pub beta_vec: Vec<FE>,
    pub v_vec: Vec<FE>,
}

#[derive(Clone, Debug)]
pub struct SignPhaseOneMsg {
    pub commitment: BigInt,
    pub cl_enc_state: CLEncState,
    pub proof: CLEncProof,
}

#[derive(Clone, Debug)]
pub struct SignPhaseTwoMsg {
    pub party_index: usize,
    pub homocipher: CLCipher,
    pub homocipher_plus: CLCipher,
    // pub t_p: FE,
    // pub t_p_plus: FE,
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

impl Setup {
    pub fn init(&mut self, discriminant: usize) -> Self {
        let q = &FE::q();
        let mu = q.bit_length();
        assert!(discriminant > (mu + 2));
        let k = discriminant - mu;
        let two = BigInt::from(2);
        let r = BigInt::sample_range(
            &two.pow((k - 1) as u32),
            &(two.pow(k as u32) - BigInt::one()),
        );
        let gi = BinaryQF {
            a: BigInt::zero(),
            b: BigInt::zero(),
            c: BigInt::zero(),
        };
        let gp = gi.clone();

        Self {k, r, t: BigInt::zero(), gi, gp}
    }

    pub fn phase_one_generate_commitment(&self) -> (SetupPhaseOneMsg, SetupPhaseTwoMsg){
        let blind_factor = BigInt::sample(self.k);
        let commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &self.r,
            &blind_factor,
        );

        let msg_one = SetupPhaseOneMsg {commitment};
        let msg_two = SetupPhaseTwoMsg {open: (self.r.clone(), blind_factor)};
        (msg_one, msg_two)
    }

    pub fn phase_two_verify_commitment_and_generate_qtilde(&self, msg_one_vec: &Vec<SetupPhaseOneMsg>, msg_two_vec: &Vec<SetupPhaseTwoMsg>) -> Result<BigInt, ProofError> {
        // TBD: check msg size
        let mut qtilde = self.r.clone();

        for i in 0..msg_one_vec.len() {
            if HashCommitment::create_commitment_with_user_defined_randomness(
                &msg_two_vec[i].open.0,
                &msg_two_vec[i].open.1,
            ) != msg_one_vec[i].commitment
            {
                return Err(ProofError);
            } else {
                qtilde = qtilde ^ &(msg_two_vec[i].open.0);
            }
        }

        qtilde = cg_ecdsa_core::eccl_setup::next_probable_prime(&qtilde);

        Ok(qtilde)
    }

    pub fn cl_setup(seed: &BigInt, qtilde: &BigInt) -> CLGroup {
        CLGroup::new_from_qtilde(seed, qtilde)
    }

    pub fn phase_three_generate_gi_and_commitment(&mut self, group: &CLGroup) -> (SetupPhaseThreeMsg, SetupPhaseFourMsg) {
        self.t = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)));

        self.gi = group.gq.exp(&self.t);
        self.gp = self.gi.clone();

        let blind = BigInt::sample(SECURITY_BITS);
        let input_hash = HSha256::create_hash_from_slice(&self.gi.to_bytes());
        let commitment =
            HashCommitment::create_commitment_with_user_defined_randomness(&input_hash, &blind);

        let msg_three = SetupPhaseThreeMsg { commitment };
        let msg_four = SetupPhaseFourMsg {open: (self.gi.clone(), blind) };
        (msg_three, msg_four)
    }

    pub fn phase_four_verify_commitment_and_generate_gp(msg_three_vec: &Vec<SetupPhaseThreeMsg>, msg_four_vec: &Vec<SetupPhaseFourMsg>) -> Result<(), ProofError> {
        for i in 0..msg_three_vec.len() {
            let input_hash = HSha256::create_hash_from_slice(&msg_four_vec[i].open.0.to_bytes());
            if HashCommitment::create_commitment_with_user_defined_randomness(
                &input_hash,
                &msg_four_vec[i].open.1,
            ) != msg_three_vec[i].commitment
            {
                return Err(ProofError);
            }
        }
        Ok(())
    }

    pub fn phase_five_generate_zkpok(&self, group: &CLGroup) -> SetupPhaseFiveMsg {
        let r = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(90)));
        let t = group.gq.exp(&r);
        let challenge_k = Self::challenge(&self.gi, &group.gq, &t);
        let u = r + challenge_k * &self.t;

        // TBD: remove h
        SetupPhaseFiveMsg {h: self.gi.clone(), t, u}
    }

    pub fn challenge(
        h: &BinaryQF,
        gq: &BinaryQF,
        r: &BinaryQF,
    ) -> BigInt {
        let hash256 = HSha256::create_hash(&[
            &BigInt::from(h.to_bytes().as_ref()),
            &BigInt::from(gq.to_bytes().as_ref()),
            &BigInt::from(r.to_bytes().as_ref()),
        ]);

        // lcm = 10
        hash256.mod_floor(&BigInt::from(1024))
    }


    pub fn phase_five_verify_zkpok_and_generate_gq(&mut self, group: &CLGroup, msg_five_vec: &Vec<SetupPhaseFiveMsg>) -> Result<(), ProofError> {
        for element in msg_five_vec.iter() {
            element.verify(group)?;
            self.gp = self.gp.compose(&element.h).reduce();
        }

        Ok(())
    }
}

impl SetupPhaseFiveMsg {
    pub fn verify(&self, group: &CLGroup) -> Result<(), ProofError> {
        let left = group.gq.exp(&self.u);
        let challenge_k = Setup::challenge(&self.h, &group.gq, &self.t);
        let right = self.h.exp(&challenge_k).compose(&self.t).reduce();
        if left != right {
            return Err(ProofError);
        }

        Ok(())
    }
}

impl KeyGen {
    pub fn phase_one_init(group: &CLGroup, party_index: usize, params: Parameters) -> Self {
        // let ec_keypair = EcKeyPair::new(); // Generate ec key pair.
        let cl_keypair = ClKeyPair::new(group); // Generate cl key pair.
        let private_signing_key = EcKeyPair::new(); // Generate private key pair.
        let public_signing_key = private_signing_key.get_public_key().clone(); // Init public key, compute later.
        let share_public_key = Vec::with_capacity(params.share_count); // Init share public key, receive later.
        let share_private_key = ECScalar::zero(); // Init share private key, compute later.
        let vss_scheme_vec = Vec::with_capacity(params.share_count); // Init vss_scheme_vec, receive later.
        Self {
            party_index,
            params,
            // ec_keypair,
            cl_keypair,
            private_signing_key,
            public_signing_key,
            share_private_key,
            share_public_key,
            vss_scheme_vec,
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

        // Assign vss_scheme_vec
        self.vss_scheme_vec = vss_scheme_vec.clone();

        // Compute share private key(x_i)
        self.share_private_key = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
        let dlog_proof = DLogProof::prove(&self.share_private_key);

        Ok(dlog_proof)
    }

    pub fn phase_six_verify_dlog_proof(
        &mut self,
        dlog_proofs: &Vec<DLogProof>,
    ) -> Result<(), ProofError> {
        assert_eq!(dlog_proofs.len(), self.params.share_count);
        for i in 0..self.params.share_count {
            DLogProof::verify(&dlog_proofs[i]).unwrap();
            self.share_public_key.push(dlog_proofs[i].pk);
        }

        Ok(())
    }
}

impl SignPhase {
    pub fn init(
        party_index: usize,
        params: Parameters,
        vss_scheme_vec: &Vec<VerifiableSS>,
        subset: &[usize],
        share_public_key: &Vec<GE>,
        x: &FE,
        party_num: usize,
    ) -> Result<Self, ProofError> {
        assert!(party_num > params.threshold);
        assert_eq!(vss_scheme_vec.len(), params.share_count);
        assert_eq!(share_public_key.len(), params.share_count);

        let lamda = vss_scheme_vec[party_index].map_share_to_new_params(party_index, subset);
        let omega = lamda * x;
        let big_omega_vec = subset
            .iter()
            .filter_map(|&i| {
                if i != party_index {
                    Some(share_public_key[i] * vss_scheme_vec[i].map_share_to_new_params(i, subset))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(Self {
            party_index,
            party_num,
            params,
            omega,
            big_omega_vec,
            k: FE::zero(),                               // Init k, generate later.
            gamma: FE::zero(),                           // Init gamma, generate later.
            sigma: FE::zero(),                           // Init sigma, generate later.
            delta_sum: FE::zero(),                       // Init delta_sum, compute later.
            r_x: FE::zero(),                             // Init r_x, compute later.
            r_point: GE::generator(),                    // Init r_point, compute later.
            rho: FE::zero(),                             // Init rho, generate later.
            l: FE::zero(),                               // Init l, generate later.
            beta_vec: Vec::with_capacity(party_num - 1), // Init random beta, generate later.
            v_vec: Vec::with_capacity(party_num - 1),    // Init random v, generate later.
        })
    }

    pub fn phase_one_generate_cl_enc_proof_and_com(
        &mut self,
        group: &CLGroup,
        cl_keypair: &ClKeyPair,
        // ec_keypair: &EcKeyPair,
    ) -> (SignPhaseOneMsg, SignPhaseFourMsg) {
        // Generate promise sigma
        self.k = FE::new_random();

        let (cipher, r) = CLCipher::encrypt(
            group,
            cl_keypair.get_public_key(),
            &self.k,
        );

        let cl_enc_state = CLEncState {
            cipher: cipher,
            cl_pub_key: cl_keypair.cl_pub_key.clone(),
        };
        let promise_wit = CLEncWit {
            a: self.k,
            r: r.0,
        };
        let proof = CLEncProof::prove(group, &cl_enc_state, &promise_wit);

        // Generate commitment
        let gamma_pair = EcKeyPair::new();
        self.gamma = gamma_pair.get_secret_key().clone();
        let dl_com = DlogCommitment::new(&gamma_pair.get_public_key());

        (
            SignPhaseOneMsg {
                commitment: dl_com.commitment,
                cl_enc_state: cl_enc_state,
                proof,
            },
            SignPhaseFourMsg { open: dl_com.open },
        )
    }

    pub fn phase_two_generate_homo_cipher(
        &mut self,
        group: &CLGroup,
        sign_phase_one_msg_vec: &Vec<SignPhaseOneMsg>,
    ) -> Vec<SignPhaseTwoMsg> {
        assert_eq!(sign_phase_one_msg_vec.len(), self.party_num);
        let mut msgs: Vec<SignPhaseTwoMsg> = Vec::new();
        let zero = FE::zero();
        for (i, msg) in sign_phase_one_msg_vec.iter().enumerate() {
            // Verify promise proof
            msg.proof.verify(group, &msg.cl_enc_state).unwrap();

            // Homo
            let cipher = &msg.cl_enc_state.cipher;
            let homocipher;
            let homocipher_plus;
            // let t_p;
            // let t_p_plus;
            let b;

            let beta = FE::new_random();
            {
                // Generate random.
                // let t = BigInt::sample_below(&(&group.stilde * BigInt::from(2).pow(40) * &FE::q()));
                // t_p = ECScalar::from(&t.mod_floor(&FE::q()));
                // let rho_plus_t = self.gamma.to_big_int() + t;

                // Handle CL cipher.
                let (r_cipher, _r_blind) =
                    CLCipher::encrypt_without_r(&group, &zero.sub(&beta.get_element()));
                let c11 = cipher.c1.exp(&self.gamma.to_big_int());
                let c21 = cipher.c2.exp(&self.gamma.to_big_int());
                let c1 = c11.compose(&r_cipher.c1).reduce();
                let c2 = c21.compose(&r_cipher.c2).reduce();
                homocipher = CLCipher { c1, c2 };
            }

            let v = FE::new_random();
            {
                // Generate random.
                // let t = BigInt::sample_below(&(&group.stilde * BigInt::from(2).pow(40) * &FE::q()));
                // t_p_plus = ECScalar::from(&t.mod_floor(&FE::q()));
                // let omega_plus_t = self.omega.to_big_int() + t;

                // Handle CL cipher.
                let (r_cipher, _r_blind) =
                    CLCipher::encrypt_without_r(&group, &zero.sub(&v.get_element()));
                let c11 = cipher.c1.exp(&self.omega.to_big_int());
                let c21 = cipher.c2.exp(&self.omega.to_big_int());
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
                // t_p,
                // t_p_plus,
                b,
            };

            msgs.push(msg);

            if i != self.party_index {
                self.beta_vec.push(beta);
                self.v_vec.push(v);
            }
        }

        msgs
    }

    pub fn phase_two_decrypt_and_verify(
        &mut self,
        group: &CLGroup,
        sk: &CLSK,
        msg_vec: &Vec<SignPhaseTwoMsg>,
    ) -> SignPhaseThreeMsg {
        assert_eq!(msg_vec.len(), self.party_num - 1);
        assert_eq!(self.big_omega_vec.len(), self.party_num - 1);
        let mut delta = self.k * self.gamma;
        self.sigma = self.k * self.omega;
        for i in 0..msg_vec.len() {
            // Compute delta
            // let k_mul_t = self.k * msg_vec[i].t_p;
            let alpha =
                CLCipher::decrypt(&group, &sk, &msg_vec[i].homocipher); //.sub(&k_mul_t.get_element());
            delta = delta + alpha + self.beta_vec[i];

            // Compute sigma
            // let k_mul_t_plus = self.k * msg_vec[i].t_p_plus;
            let miu = CLCipher::decrypt(&group, &sk, &msg_vec[i].homocipher_plus);
                // .sub(&k_mul_t_plus.get_element());
            self.sigma = self.sigma + miu + self.v_vec[i];

            // Check kW = uP + B
            let k_omega = self.big_omega_vec[i] * self.k;
            let base: GE = ECPoint::generator();
            let up_plus_b = base * miu + msg_vec[i].b;
            assert_eq!(k_omega, up_plus_b);
        }

        SignPhaseThreeMsg { delta }
    }

    pub fn phase_two_compute_delta_sum(&mut self, delta_vec: &Vec<SignPhaseThreeMsg>) {
        assert_eq!(delta_vec.len(), self.party_num);
        self.delta_sum = delta_vec.iter().fold(FE::zero(), |acc, x| acc + x.delta);
    }

    pub fn phase_four_verify_dl_com(
        &mut self,
        dl_com_vec: &Vec<SignPhaseOneMsg>,
        dl_open_vec: &Vec<SignPhaseFourMsg>,
    ) -> Result<(), ProofError> {
        assert_eq!(dl_com_vec.len(), self.party_num);
        assert_eq!(dl_open_vec.len(), self.party_num);
        for i in 0..dl_com_vec.len() {
            DlogCommitment::verify_dlog(&dl_com_vec[i].commitment, &dl_open_vec[i].open)?;
        }

        let (head, tail) = dl_open_vec.split_at(1);
        let r = tail.iter().fold(head[0].open.public_share, |acc, x| {
            acc + x.open.public_share
        });

        self.r_point = r * self.delta_sum.invert();
        self.r_x = ECScalar::from(&self.r_point.x_coor().unwrap().mod_floor(&FE::q()));
        Ok(())
    }

    pub fn phase_five_step_onetwo_generate_com_and_zk(
        &mut self,
        message: &FE,
    ) -> (
        SignPhaseFiveStepOneMsg,
        SignPhaseFiveStepTwoMsg,
        SignPhaseFiveStepSevenMsg,
    ) {
        let s_i = (*message) * self.k + self.sigma * self.r_x;
        let l_i: FE = ECScalar::new_random();
        let rho_i: FE = ECScalar::new_random();
        let l_i_rho_i = l_i * rho_i;

        let base: GE = ECPoint::generator();
        let v_i = self.r_point * &s_i + base * l_i;
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
            H: self.r_point,
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

        self.rho = rho_i;
        self.l = l_i;
        (msg_step_one, msg_step_two, msg_step_seven)
    }

    pub fn phase_five_step_three_verify_com_and_zk(
        &self,
        message: &FE,
        q: &GE, // signing public key
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
                H: self.r_point,
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
        let rq = q * &self.r_x;
        let v_big = v_sum
            .sub_point(&mp.get_element())
            .sub_point(&rq.get_element());

        let u_i = v_big * self.rho;
        let t_i = a_sum * self.l;
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
        &self,
        msgs_step_seven: &Vec<SignPhaseFiveStepSevenMsg>,
    ) -> Signature {
        let mut s = msgs_step_seven
            .iter()
            .fold(FE::zero(), |acc, x| acc + x.s_i);
        let s_bn = s.to_big_int();
        let s_tag_bn = FE::q() - &s_bn;
        if s_bn > s_tag_bn {
            s = ECScalar::from(&s_tag_bn);
        }

        Signature { s, r: self.r_x }
    }
}
