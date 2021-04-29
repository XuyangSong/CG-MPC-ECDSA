use super::message::*;
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::ProofError;
use crate::utilities::signature::Signature;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use std::collections::HashMap;

use crate::utilities::class::update_class_group_by_p;
use crate::utilities::promise_sigma::*;
use crate::utilities::SECURITY_BITS;
use class_group::primitives::cl_dl_public_setup::{
    decrypt, encrypt_without_r, CLGroup, Ciphertext as CLCipher, PK as CLPK, SK as CLSK,
};
use class_group::BinaryQF;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;

#[derive(Clone, Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

#[derive(Clone, Debug)]
pub struct KeyGenTest {
    pub cl_group: CLGroup,
    pub party_index: usize,
    pub params: Parameters,
    pub cl_keypair: ClKeyPair,
    pub h_caret: CLPK,
    pub private_signing_key: EcKeyPair,       // (u_i, u_iP)
    pub public_signing_key: GE,               // Q
    pub share_private_key: FE,                // x_i
    pub share_public_key: HashMap<usize, GE>, // X_i
    pub vss_scheme_map: HashMap<usize, VerifiableSS>,
}

#[derive(Clone, Debug)]
pub struct SignPhaseTest {
    pub cl_group: CLGroup,
    pub party_index: usize,
    pub party_num: usize,
    pub params: Parameters,
    pub public_signing_key: GE,
    pub message: FE,
    pub omega: FE,
    pub big_omega_vec: Vec<GE>,
    pub k: FE,
    pub gamma: FE,
    pub delta: FE,
    pub sigma: FE,
    pub delta_sum: FE,
    pub r_x: FE,
    pub r_point: GE,
    pub rho: FE,
    pub l: FE,
    pub beta_vec: Vec<FE>,
    pub v_vec: Vec<FE>,
}

impl KeyGenTest {
    pub fn phase_one_init(group: &CLGroup, party_index: usize, params: Parameters) -> Self {
        // Generate cl keypair
        let mut cl_keypair = ClKeyPair::new(&group);
        let h_caret = cl_keypair.get_public_key().clone();
        cl_keypair.update_pk_exp_p();

        // Update gp
        let new_class_group = update_class_group_by_p(group);

        let private_signing_key = EcKeyPair::new(); // Generate private key pair.
        let public_signing_key = private_signing_key.get_public_key().clone(); // Init public key, compute later.
        Self {
            cl_group: new_class_group,
            party_index,
            params,
            cl_keypair,
            h_caret,
            private_signing_key,
            public_signing_key,
            share_private_key: ECScalar::zero(), // Init share private key, compute later.
            share_public_key: HashMap::new(),
            vss_scheme_map: HashMap::new(),
        }
    }

    pub fn get_class_group_pk(&self) -> (CLPK, CLPK, BinaryQF) {
        (
            self.h_caret.clone(),
            self.cl_keypair.get_public_key().clone(),
            self.cl_group.gq.clone(),
        )
    }

    pub fn verify_class_group_pk(
        &self,
        pk_vec: &Vec<(CLPK, CLPK, BinaryQF)>,
    ) -> Result<(), ProofError> {
        for element in pk_vec.iter() {
            let h_ret = element.0 .0.exp(&FE::q());
            if h_ret != element.1 .0 && element.2 != self.cl_group.gq {
                return Err(ProofError);
            }
        }
        Ok(())
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

    pub fn phase_five_verify_vss_and_generate_pok_dlog(
        &mut self,
        q_vec: &Vec<GE>,
        secret_shares_vec: &HashMap<usize, FE>,
        vss_scheme_map: &HashMap<usize, VerifiableSS>,
    ) -> Result<DLogProof, ProofError> {
        assert_eq!(q_vec.len(), self.params.share_count);
        assert_eq!(secret_shares_vec.len(), self.params.share_count);
        assert_eq!(vss_scheme_map.len(), self.params.share_count);

        // Check VSS
        for i in 0..q_vec.len() {
            let vss_scheme = vss_scheme_map.get(&i).unwrap();
            let secret_shares = secret_shares_vec.get(&i).unwrap();
            if !(vss_scheme
                .validate_share(&secret_shares, self.party_index + 1)
                .is_ok()
                && vss_scheme.commitments[0] == q_vec[i])
            {
                // TBD: use new error type
                return Err(ProofError);
            }
        }

        self.vss_scheme_map = vss_scheme_map.clone();

        // Compute share private key(x_i)
        self.share_private_key = secret_shares_vec
            .iter()
            .fold(FE::zero(), |acc, (_i, x)| acc + x);
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
            self.share_public_key.insert(i, dlog_proofs[i].pk);
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
}

impl SignPhaseTest {
    pub fn init(
        cl_group: CLGroup,
        party_index: usize,
        params: Parameters,
        vss_scheme_map: &HashMap<usize, VerifiableSS>,
        subset: &[usize],
        share_public_key_map: &HashMap<usize, GE>,
        x: &FE,
        party_num: usize,
        public_signing_key: GE,
        message: FE,
    ) -> Result<Self, ProofError> {
        assert!(party_num > params.threshold);
        assert_eq!(vss_scheme_map.len(), params.share_count);
        assert_eq!(share_public_key_map.len(), params.share_count);

        let lamda = vss_scheme_map
            .get(&party_index)
            .unwrap()
            .map_share_to_new_params(party_index, subset);
        let omega = lamda * x;
        let big_omega_vec = subset
            .iter()
            .filter_map(|i| {
                if *i != party_index {
                    let share_public_key = share_public_key_map.get(i).unwrap();
                    let vss_scheme = vss_scheme_map.get(i).unwrap();
                    let ret = share_public_key * &vss_scheme.map_share_to_new_params(*i, subset);
                    Some(ret)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(Self {
            cl_group,
            party_index,
            party_num,
            params,
            public_signing_key,
            message,
            omega,
            big_omega_vec,
            k: FE::zero(),                               // Init k, generate later.
            gamma: FE::zero(),                           // Init gamma, generate later.
            delta: FE::zero(),                           // Init delta, generate later.
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

    pub fn phase_one_generate_promise_sigma_and_com(
        &mut self,
        cl_keypair: &ClKeyPair,
    ) -> (SignPhaseOneMsg, SignPhaseFourMsg) {
        // Generate promise sigma
        self.k = FE::new_random();

        let cipher = PromiseCipher::encrypt(&self.cl_group, cl_keypair.get_public_key(), &self.k);

        let promise_state = PromiseState {
            cipher: cipher.0.clone(),
            cl_pub_key: cl_keypair.cl_pub_key.clone(),
        };
        let promise_wit = PromiseWit {
            m: self.k,
            r: cipher.1,
        };
        let proof = PromiseProof::prove(&self.cl_group, &promise_state, &promise_wit);

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
        &mut self,
        sign_phase_one_msg_vec: &Vec<SignPhaseOneMsg>,
    ) -> Vec<SignPhaseTwoMsg> {
        assert_eq!(sign_phase_one_msg_vec.len(), self.party_num);
        let mut msgs: Vec<SignPhaseTwoMsg> = Vec::new();
        let zero = FE::zero();
        for (i, msg) in sign_phase_one_msg_vec.iter().enumerate() {
            // Verify promise proof
            msg.proof
                .verify(&self.cl_group, &msg.promise_state)
                .unwrap();

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
                let t = BigInt::sample_below(
                    &(&self.cl_group.stilde * BigInt::from(2).pow(40) * &FE::q()),
                );
                t_p = ECScalar::from(&t.mod_floor(&FE::q()));
                let rho_plus_t = self.gamma.to_big_int() + t;

                // Handle CL cipher.
                let (r_cipher, _r_blind) =
                    encrypt_without_r(&self.cl_group, &zero.sub(&beta.get_element()));
                let c11 = cipher.cl_cipher.c1.exp(&rho_plus_t);
                let c21 = cipher.cl_cipher.c2.exp(&rho_plus_t);
                let c1 = c11.compose(&r_cipher.c1).reduce();
                let c2 = c21.compose(&r_cipher.c2).reduce();
                homocipher = CLCipher { c1, c2 };
            }

            let v = FE::new_random();
            {
                // Generate random.
                let t = BigInt::sample_below(
                    &(&self.cl_group.stilde * BigInt::from(2).pow(40) * &FE::q()),
                );
                t_p_plus = ECScalar::from(&t.mod_floor(&FE::q()));
                let omega_plus_t = self.omega.to_big_int() + t;

                // Handle CL cipher.
                let (r_cipher, _r_blind) =
                    encrypt_without_r(&self.cl_group, &zero.sub(&v.get_element()));
                let c11 = cipher.cl_cipher.c1.exp(&omega_plus_t);
                let c21 = cipher.cl_cipher.c2.exp(&omega_plus_t);
                let c1 = c11.compose(&r_cipher.c1).reduce();
                let c2 = c21.compose(&r_cipher.c2).reduce();
                homocipher_plus = CLCipher { c1, c2 };

                let base: GE = ECPoint::generator();
                b = base * v;
            }

            let msg = SignPhaseTwoMsg {
                homocipher,
                homocipher_plus,
                t_p,
                t_p_plus,
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
        sk: &CLSK,
        msg_vec: &Vec<SignPhaseTwoMsg>,
    ) -> SignPhaseThreeMsg {
        assert_eq!(msg_vec.len(), self.party_num - 1);
        assert_eq!(self.big_omega_vec.len(), self.party_num - 1);
        let mut delta = self.k * self.gamma;
        self.sigma = self.k * self.omega;
        for i in 0..msg_vec.len() {
            // Compute delta
            let k_mul_t = self.k * msg_vec[i].t_p;
            let alpha =
                decrypt(&self.cl_group, &sk, &msg_vec[i].homocipher).sub(&k_mul_t.get_element());
            delta = delta + alpha + self.beta_vec[i];

            // Compute sigma
            let k_mul_t_plus = self.k * msg_vec[i].t_p_plus;
            let miu = decrypt(&self.cl_group, &sk, &msg_vec[i].homocipher_plus)
                .sub(&k_mul_t_plus.get_element());
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

fn keygen_t_n_parties(group: &CLGroup, params: &Parameters) -> Vec<KeyGenTest> {
    let n = params.share_count;
    let t = params.threshold;

    let n_i32 = n as i32;

    // Key Gen Phase 1
    let key_gen_phase_one_start = time::now();
    let mut key_gen_vec = (0..n)
        .map(|i| KeyGenTest::phase_one_init(group, i, params.clone()))
        .collect::<Vec<KeyGenTest>>();
    let key_gen_phase_one_time = (time::now() - key_gen_phase_one_start) / n_i32;
    println!("key_gen_phase_one_time: {:?}", key_gen_phase_one_time);

    // Key Gen Phase 2
    let key_gen_phase_two_start = time::now();
    let dl_com_vec = key_gen_vec
        .iter()
        .map(|key_gen| key_gen.phase_two_generate_dl_com())
        .collect::<Vec<_>>();
    let key_gen_phase_two_time = (time::now() - key_gen_phase_two_start) / n_i32;
    println!("key_gen_phase_two_time: {:?}", key_gen_phase_two_time);

    // Verify class group pk and pk'
    let key_gen_phase_check_pk_start = time::now();
    let pk_vec = key_gen_vec
        .iter()
        .map(|key_gen| key_gen.get_class_group_pk())
        .collect::<Vec<_>>();
    key_gen_vec[0].verify_class_group_pk(&pk_vec).unwrap();
    let key_gen_phase_check_pk_time = (time::now() - key_gen_phase_check_pk_start) / n_i32;
    println!(
        "key_gen_phase_check_pk_time: {:?}",
        key_gen_phase_check_pk_time
    );

    let q_vec = dl_com_vec
        .iter()
        .map(|k| k.get_public_share())
        .collect::<Vec<_>>();

    // Key Gen Phase 3
    let (_, received_dl_com) = dl_com_vec.split_at(1);
    let key_gen_phase_three_start = time::now();
    key_gen_vec[0]
        .phase_three_verify_dl_com_and_generate_signing_key(&received_dl_com.to_vec())
        .unwrap();
    let key_gen_phase_three_time = (time::now() - key_gen_phase_three_start) / (n_i32 - 1);
    println!("key_gen_phase_three_time: {:?}", key_gen_phase_three_time);

    // Assign public_signing_key
    for i in 1..n {
        key_gen_vec[i].public_signing_key = key_gen_vec[0].public_signing_key;
    }

    // Key Gen Phase 4
    let key_gen_phase_four_start = time::now();
    let vss_result = key_gen_vec
        .iter()
        .map(|k| k.phase_four_generate_vss())
        .collect::<Vec<_>>();
    let key_gen_phase_four_time = (time::now() - key_gen_phase_four_start) / n_i32;
    println!("key_gen_phase_four_time: {:?}", key_gen_phase_four_time);

    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();
    for (vss_scheme, secret_shares, index) in vss_result {
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares);
        index_vec.push(index);
    }

    let party_shares = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i]
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    let mut vss_scheme_map = HashMap::new();
    for i in 0..n {
        vss_scheme_map.insert(i, vss_scheme_vec[i].clone());
    }

    // Key Gen Phase 5
    let key_gen_phase_five_start = time::now();
    let mut dlog_proof_vec = Vec::new();
    for i in 0..n {
        let mut party_shares_map = HashMap::new();
        for j in 0..n {
            party_shares_map.insert(j, party_shares[i][j]);
        }
        let dlog_proof = key_gen_vec[i]
            .phase_five_verify_vss_and_generate_pok_dlog(&q_vec, &party_shares_map, &vss_scheme_map)
            .expect("invalid vss");
        dlog_proof_vec.push(dlog_proof);
    }
    let key_gen_phase_five_time = (time::now() - key_gen_phase_five_start) / (n_i32 * n_i32);
    println!("key_gen_phase_five_time: {:?}", key_gen_phase_five_time);

    // Key Gen Phase 6
    let key_gen_phase_six_start = time::now();
    for i in 0..n {
        key_gen_vec[i]
            .phase_six_verify_dlog_proof(&dlog_proof_vec)
            .unwrap();
    }
    let key_gen_phase_six_time = (time::now() - key_gen_phase_six_start) / (n_i32 * n_i32);
    println!("key_gen_phase_six_time: {:?}", key_gen_phase_six_time);

    // test vss
    let xi_vec = (0..=t)
        .map(|i| key_gen_vec[i].share_private_key)
        .collect::<Vec<FE>>();
    let x = vss_scheme_vec[0]
        .clone()
        .reconstruct(&index_vec[0..=t], &xi_vec);
    let sum_u_i = key_gen_vec.iter().fold(FE::zero(), |acc, x| {
        acc + x.private_signing_key.get_secret_key()
    });

    assert_eq!(x, sum_u_i);

    let time_t = key_gen_phase_check_pk_time
        + key_gen_phase_three_time
        + key_gen_phase_five_time
        + key_gen_phase_six_time;
    let time_constant = key_gen_phase_one_time + key_gen_phase_two_time + key_gen_phase_four_time;
    println!(
        "key gen total time: {:?} * (n-1) + {:?}\n\n",
        time_t, time_constant
    );

    key_gen_vec
}

fn test_sign(params: &Parameters, key_gen_vec: Vec<KeyGenTest>) {
    // Sign Init
    let party_num = key_gen_vec.len();
    let t_i32 = party_num as i32;
    let subset = (0..party_num)
        .map(|i| key_gen_vec[i].party_index)
        .collect::<Vec<_>>();

    let sign_phase_init_start = time::now();
    let mut sign_vec = (0..party_num)
        .map(|i| {
            SignPhaseTest::init(
                key_gen_vec[i].cl_group.clone(),
                key_gen_vec[i].party_index,
                params.clone(),
                &key_gen_vec[i].vss_scheme_map,
                &subset,
                &key_gen_vec[i].share_public_key,
                &key_gen_vec[i].share_private_key,
                party_num,
                GE::generator(),
                FE::zero(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let sign_phase_init_time = (time::now() - sign_phase_init_start) / t_i32;
    println!("sign_phase_init_time: {:?}", sign_phase_init_time);

    // Sign phase 1
    let sign_phase_one_start = time::now();
    let phase_one_result_vec = (0..party_num)
        .map(|i| sign_vec[i].phase_one_generate_promise_sigma_and_com(&key_gen_vec[i].cl_keypair))
        .collect::<Vec<_>>();
    let sign_phase_one_time = (time::now() - sign_phase_one_start) / t_i32;
    println!("sign_phase_one_time: {:?}", sign_phase_one_time);

    let phase_one_msg_vec = (0..party_num)
        .map(|i| phase_one_result_vec[i].0.clone())
        .collect::<Vec<_>>();

    // Sign phase 2
    let sign_phase_two_homo_start = time::now();
    let phase_two_result_vec = (0..party_num)
        .map(|i| sign_vec[i].phase_two_generate_homo_cipher(&phase_one_msg_vec))
        .collect::<Vec<_>>();
    let sign_phase_two_homo_time = (time::now() - sign_phase_two_homo_start) / (t_i32 * t_i32);
    println!("sign_phase_two_homo_time: {:?}", sign_phase_two_homo_time);

    let sign_phase_two_decrypt_start = time::now();
    let mut phase_three_msg_vec: Vec<SignPhaseThreeMsg> = Vec::with_capacity(party_num);
    for index in 0..party_num {
        let phase_two_msg_vec = phase_two_result_vec
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if i != index {
                    Some(e[index].clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let msg = sign_vec[index].phase_two_decrypt_and_verify(
            key_gen_vec[index].cl_keypair.get_secret_key(),
            &phase_two_msg_vec,
        );
        phase_three_msg_vec.push(msg);
    }
    let sign_phase_two_decrypt_time =
        (time::now() - sign_phase_two_decrypt_start) / (t_i32 * t_i32);
    println!(
        "sign_phase_two_decrypt_time: {:?}",
        sign_phase_two_decrypt_time
    );

    // Sign phase 3
    let sign_phase_three_start = time::now();
    for i in 0..sign_vec.len() {
        sign_vec[i].phase_two_compute_delta_sum(&phase_three_msg_vec);
    }
    let sign_phase_three_time = (time::now() - sign_phase_three_start) / (t_i32 * t_i32);
    println!("sign_phase_three_time: {:?}", sign_phase_three_time);

    // Sign phase 4
    let message: FE = ECScalar::new_random();
    let phase_four_msg_vec = (0..party_num)
        .map(|i| phase_one_result_vec[i].1.clone())
        .collect::<Vec<_>>();

    let sign_phase_four_start = time::now();
    for i in 0..sign_vec.len() {
        sign_vec[i]
            .phase_four_verify_dl_com(&phase_one_msg_vec, &phase_four_msg_vec)
            .unwrap();
    }
    let sign_phase_four_time = (time::now() - sign_phase_four_start) / (t_i32 * t_i32);
    println!("sign_phase_four_time: {:?}", sign_phase_four_time);

    // Sign phase 5
    let mut phase_five_step_one_msg_vec: Vec<SignPhaseFiveStepOneMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_two_msg_vec: Vec<SignPhaseFiveStepTwoMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_seven_msg_vec: Vec<SignPhaseFiveStepSevenMsg> =
        Vec::with_capacity(party_num);

    let sign_phase_five_step_one_start = time::now();
    for i in 0..party_num {
        let ret = sign_vec[i].phase_five_step_onetwo_generate_com_and_zk(&message);
        phase_five_step_one_msg_vec.push(ret.0);
        phase_five_step_two_msg_vec.push(ret.1);
        phase_five_step_seven_msg_vec.push(ret.2);
    }
    let sign_phase_five_step_one_time = (time::now() - sign_phase_five_step_one_start) / t_i32;
    println!(
        "sign_phase_five_step_one_time: {:?}",
        sign_phase_five_step_one_time
    );

    let mut phase_five_step_four_msg_vec: Vec<SignPhaseFiveStepFourMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_five_msg_vec: Vec<SignPhaseFiveStepFiveMsg> =
        Vec::with_capacity(party_num);
    let sign_phase_five_step_three_start = time::now();
    for i in 0..party_num {
        let ret = sign_vec[i]
            .phase_five_step_three_verify_com_and_zk(
                &message,
                &key_gen_vec[i].public_signing_key,
                &phase_five_step_one_msg_vec,
                &phase_five_step_two_msg_vec,
            )
            .unwrap();
        phase_five_step_four_msg_vec.push(ret.0);
        phase_five_step_five_msg_vec.push(ret.1);
    }
    let sign_phase_five_step_three_time =
        (time::now() - sign_phase_five_step_three_start) / (t_i32 * t_i32);
    println!(
        "sign_phase_five_step_three_time: {:?}",
        sign_phase_five_step_three_time
    );

    let sign_phase_five_step_six_start = time::now();
    SignPhaseTest::phase_five_step_six_verify_com_and_check_sum_a_t(
        &phase_five_step_four_msg_vec,
        &phase_five_step_five_msg_vec,
    )
    .unwrap();
    let sign_phase_five_step_six_time =
        (time::now() - sign_phase_five_step_six_start) / (t_i32 * t_i32);
    println!(
        "sign_phase_five_step_six_time: {:?}",
        sign_phase_five_step_six_time
    );

    let sig = sign_vec[0].phase_five_step_eight_generate_signature(&phase_five_step_seven_msg_vec);

    let time_t = sign_phase_two_homo_time
        + sign_phase_two_decrypt_time
        + sign_phase_three_time
        + sign_phase_four_time
        + sign_phase_five_step_three_time
        + sign_phase_five_step_six_time;
    let time_constant = sign_phase_init_time + sign_phase_one_time + sign_phase_five_step_one_time;
    println!("sign total time: {:?} * t + {:?}", time_t, time_constant);

    // Verify Signature
    Signature::verify(&sig, &key_gen_vec[0].public_signing_key, &message).unwrap();
}

#[test]
fn test_multi_party() {
    let seed: BigInt = str::parse(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
    ).unwrap();
    let group = CLGroup::new_from_setup(&1827, &seed); //discriminant 1827

    let params = Parameters {
        threshold: 2,
        share_count: 3,
    };

    let key_gen_vec = keygen_t_n_parties(&group, &params);

    test_sign(&params, key_gen_vec);
}
