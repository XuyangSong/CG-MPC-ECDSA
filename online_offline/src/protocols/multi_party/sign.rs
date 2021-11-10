use multi_party_ecdsa::utilities::clkeypair::ClKeyPair;
use multi_party_ecdsa::utilities::dl_com_zk::*;
use multi_party_ecdsa::utilities::eckeypair::EcKeyPair;
use multi_party_ecdsa::utilities::error::MulEcdsaError;
use multi_party_ecdsa::utilities::promise_sigma_multi::*;
use multi_party_ecdsa::utilities::signature::Signature;
use multi_party_ecdsa::utilities::SECURITY_BITS;
use class_group::primitives::cl_dl_public_setup::{
    decrypt, encrypt_without_r, CLGroup, Ciphertext as CLCipher,
};

use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::keygen::{KenGenResult, Parameters};
use crate::protocols::multi_party::message::*;
use multi_party_ecdsa::utilities::class::{update_class_group_by_p, GROUP_128};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct SignMsgs {
    pub phase_one_msgs: HashMap<usize, SignPhaseOneMsg>,
    pub phase_two_msgs: HashMap<usize, SignPhaseTwoMsg>,
    pub phase_three_msgs: HashMap<usize, SignPhaseThreeMsg>,
    pub phase_four_msgs: HashMap<usize, SignPhaseFourMsg>,
    pub phase_five_step_one_msgs: HashMap<usize, SignPhaseFiveStepOneMsg>,
    pub phase_five_step_two_msgs: HashMap<usize, SignPhaseFiveStepTwoMsg>,
    pub phase_five_step_four_msgs: HashMap<usize, SignPhaseFiveStepFourMsg>,
    pub phase_five_step_five_msgs: HashMap<usize, SignPhaseFiveStepFiveMsg>,
    pub phase_five_step_seven_msgs: HashMap<usize, SignPhaseFiveStepSevenMsg>,
}

#[derive(Clone, Debug)]
pub struct SignPhase {
    group: CLGroup,
    pub party_index: usize,
    pub party_num: usize,
    pub params: Parameters,
    pub subset: Vec<usize>,
    pub ec_keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub public_signing_key: GE,
    pub message: FE,
    pub omega: FE,
    pub big_omega_map: HashMap<usize, GE>,
    pub k: FE,
    pub gamma: FE,
    pub delta: FE,
    pub sigma: FE,
    pub delta_sum: FE,
    pub r_x: FE,
    pub r_point: GE,
    pub rho: FE,
    pub l: FE,
    // pub beta_vec: Vec<FE>,
    // pub v_vec: Vec<FE>,
    pub beta_map: HashMap<usize, FE>,
    pub v_map: HashMap<usize, FE>,
    pub precomputation: HashMap<usize, (CLCipher, CLCipher, GE)>,
    pub msgs: SignMsgs,
    pub need_refresh: bool,
    pub a_i_vec: Vec<GE>,
}

impl SignMsgs {
    pub fn new() -> Self {
        Self {
            phase_one_msgs: HashMap::new(),
            phase_two_msgs: HashMap::new(),
            phase_three_msgs: HashMap::new(),
            phase_four_msgs: HashMap::new(),
            phase_five_step_one_msgs: HashMap::new(),
            phase_five_step_two_msgs: HashMap::new(),
            phase_five_step_four_msgs: HashMap::new(),
            phase_five_step_five_msgs: HashMap::new(),
            phase_five_step_seven_msgs: HashMap::new(),
        }
    }

    pub fn clean(&mut self) {
        self.phase_one_msgs.clear();
        self.phase_two_msgs.clear();
        self.phase_three_msgs.clear();
        self.phase_four_msgs.clear();
        self.phase_five_step_one_msgs.clear();
        self.phase_five_step_two_msgs.clear();
        self.phase_five_step_four_msgs.clear();
        self.phase_five_step_five_msgs.clear();
        self.phase_five_step_seven_msgs.clear();
    }
}

impl SignPhase {
    pub fn new(
        party_index: usize,
        params: Parameters,
        subset: &Vec<usize>,
        keygen_result_json: &String,
    ) -> Result<Self, MulEcdsaError> {
        let new_class_group = update_class_group_by_p(&GROUP_128);

        // Load keygen result
        let keygen_result = KenGenResult::from_json_string(keygen_result_json)?;
        let ec_keypair = EcKeyPair::from_sk(keygen_result.ec_sk);
        let cl_keypair = ClKeyPair::from_sk(keygen_result.cl_sk, &new_class_group);
        let vss_scheme_map = keygen_result.vss;
        let share_public_key_map = keygen_result.share_pks;

        let party_num = subset.len();
        if party_num < params.threshold {
            return Err(MulEcdsaError::PartyLessThanThreshold);
        }
        if vss_scheme_map.len() != params.share_count
            || share_public_key_map.len() != params.share_count
        {
            return Err(MulEcdsaError::LeftNotEqualRight);
        }

        // Compute lambda
        let lamda = VerifiableSS::<GE>::map_share_to_new_params(
            &vss_scheme_map
                .get(&party_index)
                .ok_or(MulEcdsaError::GetIndexFailed)?
                .parameters,
            party_index,
            subset,
        );
        let omega = lamda * keygen_result.share_sk;
        let mut big_omega_map = HashMap::new();
        let _big_omega_vec = subset
            .iter()
            .filter_map(|i| {
                if *i != party_index {
                    let share_public_key = share_public_key_map
                        .get(i)
                        .ok_or(MulEcdsaError::GetIndexFailed)
                        .ok()?;
                    let vss_scheme = vss_scheme_map
                        .get(i)
                        .ok_or(MulEcdsaError::GetIndexFailed)
                        .ok()?;
                    let ret = share_public_key
                        * &(VerifiableSS::<GE>::map_share_to_new_params(
                            &vss_scheme.parameters,
                            *i,
                            subset,
                        ));
                    //let ret = share_public_key * &vss_scheme.map_share_to_new_params(*i, subset);
                    big_omega_map.insert(*i, ret.clone());
                    Some(ret)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut ret = SignPhase {
            group: new_class_group,
            party_index,
            party_num,
            params,
            subset: subset.to_vec(),
            ec_keypair,
            cl_keypair,
            public_signing_key: keygen_result.pk,
            message: FE::new_random(),
            omega,
            big_omega_map,
            k: FE::zero(),            // Init k, generate later.
            gamma: FE::zero(),        // Init gamma, generate later.
            delta: FE::zero(),        // Init delta, generate later.
            sigma: FE::zero(),        // Init sigma, generate later.
            delta_sum: FE::zero(),    // Init delta_sum, compute later.
            r_x: FE::zero(),          // Init r_x, compute later.
            r_point: GE::generator(), // Init r_point, compute later.
            rho: FE::zero(),          // Init rho, generate later.
            l: FE::zero(),            // Init l, generate later.
            // beta_vec: Vec::new(),     // Init random beta, generate later.
            // v_vec: Vec::new(),        // Init random v, generate later.
            beta_map: HashMap::new(),
            v_map: HashMap::new(),
            precomputation: HashMap::new(),
            msgs: SignMsgs::new(),
            need_refresh: false,
            a_i_vec: Vec::new(),
        };

        ret.init();

        Ok(ret)
    }

    pub fn refresh(
        &mut self,
        subset: Vec<usize>,
        keygen_result_json: &String,
    ) -> Result<(), MulEcdsaError> {
        self.subset = subset.clone();

        // Load keygen result
        let keygen_result = KenGenResult::from_json_string(keygen_result_json)?;
        self.ec_keypair = EcKeyPair::from_sk(keygen_result.ec_sk);
        self.cl_keypair = ClKeyPair::from_sk(keygen_result.cl_sk, &self.group);
        let vss_scheme_map = keygen_result.vss;
        let share_public_key_map = keygen_result.share_pks;
        self.public_signing_key = keygen_result.pk;

        // Compute lambda
        let lamda = VerifiableSS::<GE>::map_share_to_new_params(
            &vss_scheme_map
                .get(&self.party_index)
                .ok_or(MulEcdsaError::GetIndexFailed)?
                .parameters,
            self.party_index,
            &self.subset,
        );

        self.omega = lamda * keygen_result.share_sk;
        self.big_omega_map.clear();
        let _big_omega_vec = subset
            .iter()
            .filter_map(|i| {
                if *i != self.party_index {
                    let share_public_key = share_public_key_map
                        .get(i)
                        .ok_or(MulEcdsaError::GetIndexFailed)
                        .ok()?;
                    let vss_scheme = vss_scheme_map
                        .get(i)
                        .ok_or(MulEcdsaError::GetIndexFailed)
                        .ok()?;
                    let ret = share_public_key
                        * &(VerifiableSS::<GE>::map_share_to_new_params(
                            &vss_scheme.parameters,
                            *i,
                            &self.subset,
                        ));
                    self.big_omega_map.insert(*i, ret.clone());
                    Some(ret)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        self.beta_map.clear();
        self.v_map.clear();
        self.precomputation.clear();
        self.msgs.clean();

        self.init();
        self.need_refresh = false;
        Ok(())
    }

    fn init(&mut self) {
        self.phase_one_generate_promise_sigma_and_com_msg();
        self.pre_computation();
    }

    fn phase_one_generate_promise_sigma_and_com_msg(&mut self) {
        // Generate promise sigma
        self.k = FE::new_random();

        let cipher = PromiseCipher::encrypt(
            &self.group,
            self.cl_keypair.get_public_key(),
            self.ec_keypair.get_public_key(),
            &self.k,
        );

        let promise_state = PromiseState {
            cipher: cipher.0,
            ec_pub_key: self.ec_keypair.public_share.clone(),
            cl_pub_key: self.cl_keypair.cl_pub_key.clone(),
        };
        let promise_wit = PromiseWit {
            m: self.k,
            r1: cipher.1,
            r2: cipher.2,
        };
        let proof = PromiseProof::prove(&self.group, &promise_state, &promise_wit);

        // Generate commitment
        let gamma_pair = EcKeyPair::new();
        self.gamma = gamma_pair.get_secret_key().clone();
        let dl_com = DlogCommitment::new(&gamma_pair.get_public_key());

        let msg_one = SignPhaseOneMsg {
            commitment: dl_com.commitment,
            promise_state: promise_state,
            proof,
        };
        let msg_four = SignPhaseFourMsg { open: dl_com.open };

        self.msgs
            .phase_one_msgs
            .insert(self.party_index, msg_one.clone());
        self.msgs.phase_four_msgs.insert(self.party_index, msg_four);

        self.delta = self.k * self.gamma;
        self.sigma = self.k * self.omega;
    }

    fn pre_computation(&mut self) {
        let base: GE = ECPoint::generator();
        let zero = FE::zero();
        for index in self.subset.iter() {
            if *index == self.party_index {
                continue;
            }

            let beta = FE::new_random();
            let (r_cipher_1, _r_blind) =
                encrypt_without_r(&self.group, &zero.sub(&beta.get_element()));
            self.beta_map.insert(*index, beta);

            let v = FE::new_random();
            let (r_cipher_2, _r_blind) =
                encrypt_without_r(&self.group, &zero.sub(&v.get_element()));
            let b = base * v;
            self.v_map.insert(*index, v);

            self.precomputation
                .insert(*index, (r_cipher_1, r_cipher_2, b));
        }
    }

    fn get_phase_one_msg(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let msg = self
            .msgs
            .phase_one_msgs
            .get(&self.party_index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        let sending_msg =
            ReceivingMessages::MultiSignMessage(MultiSignMessage::PhaseOneMsg(msg.clone()));
        Ok(bincode::serialize(&sending_msg).map_err(|_| MulEcdsaError::SerializeFailed)?)
    }

    fn handle_phase_one_msg(
        &mut self,
        index: usize,
        msg: &SignPhaseOneMsg,
    ) -> Result<Vec<u8>, MulEcdsaError> {
        // TBD: check ec cl pk
        // Verify promise proof
        msg.proof.verify(&self.group, &msg.promise_state)?;

        // Homo
        let cipher = &msg.promise_state.cipher;
        let homocipher;
        let homocipher_plus;
        let t_p;
        let t_p_plus;

        let (pre_cipher_1, pre_cipher_2, b) = self
            .precomputation
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        {
            // Generate random.
            let t =
                BigInt::sample_below(&(&self.group.stilde * BigInt::from(2).pow(40) * &FE::q()));
            t_p = ECScalar::from(&t.mod_floor(&FE::q()));
            let rho_plus_t = self.gamma.to_big_int() + t;

            // Handle CL cipher.
            let c11 = cipher.cl_cipher.c1.exp(&rho_plus_t);
            let c21 = cipher.cl_cipher.c2.exp(&rho_plus_t);
            let c1 = c11.compose(&pre_cipher_1.c1).reduce();
            let c2 = c21.compose(&pre_cipher_1.c2).reduce();
            homocipher = CLCipher { c1, c2 };
        }

        {
            // Generate random.
            let t =
                BigInt::sample_below(&(&self.group.stilde * BigInt::from(2).pow(40) * &FE::q()));
            t_p_plus = ECScalar::from(&t.mod_floor(&FE::q()));
            let omega_plus_t = self.omega.to_big_int() + t;

            // Handle CL cipher.
            let c11 = cipher.cl_cipher.c1.exp(&omega_plus_t);
            let c21 = cipher.cl_cipher.c2.exp(&omega_plus_t);
            let c1 = c11.compose(&pre_cipher_2.c1).reduce();
            let c2 = c21.compose(&pre_cipher_2.c2).reduce();
            homocipher_plus = CLCipher { c1, c2 };
        }

        let msg_two = SignPhaseTwoMsg {
            homocipher,
            homocipher_plus,
            t_p,
            t_p_plus,
            b: *b,
        };

        let sending_msg =
            ReceivingMessages::MultiSignMessage(MultiSignMessage::PhaseTwoMsg(msg_two));
        Ok(bincode::serialize(&sending_msg).map_err(|_| MulEcdsaError::SerializeFailed)?)
    }

    fn handle_phase_two_msg(
        &mut self,
        index: usize,
        msg: &SignPhaseTwoMsg,
    ) -> Result<(), MulEcdsaError> {
        // Compute delta
        let k_mul_t = self.k * msg.t_p;
        let alpha = decrypt(
            &self.group,
            self.cl_keypair.get_secret_key(),
            &msg.homocipher,
        )
        .sub(&k_mul_t.get_element());
        let beta = self
            .beta_map
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        self.delta = self.delta + alpha + beta;

        // Compute sigma
        let k_mul_t_plus = self.k * msg.t_p_plus;
        let miu = decrypt(
            &self.group,
            self.cl_keypair.get_secret_key(),
            &msg.homocipher_plus,
        )
        .sub(&k_mul_t_plus.get_element());
        let v = self
            .v_map
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        self.sigma = self.sigma + miu + v;

        // Check kW = uP + B
        let big_omega = self
            .big_omega_map
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        let k_omega = big_omega * &self.k;
        let base: GE = ECPoint::generator();
        let up_plus_b = base * miu + msg.b;
        if k_omega != up_plus_b {
            return Err(MulEcdsaError::HandleSignPhaseTwoMsgFailed);
        }
        assert_eq!(k_omega, up_plus_b);

        Ok(())
        // SignPhaseThreeMsg { delta }
    }

    fn phase_two_compute_delta_sum_msg(&mut self) -> Result<(), MulEcdsaError> {
        if self.msgs.phase_three_msgs.len() != self.party_num {
            return Err(MulEcdsaError::ComputeDeltaSumFailed);
        }

        self.delta_sum = self
            .msgs
            .phase_three_msgs
            .iter()
            .fold(FE::zero(), |acc, (_i, v)| acc + v.delta);

        Ok(())
    }

    fn handle_phase_four_msg(
        &mut self,
        index: usize,
        msg: &SignPhaseFourMsg,
    ) -> Result<(), MulEcdsaError> {
        let msg_one = self
            .msgs
            .phase_one_msgs
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        DlogCommitment::verify_dlog(&msg_one.commitment, &msg.open)?;

        Ok(())
    }

    fn compute_r_x(&mut self) -> Result<(), MulEcdsaError> {
        let r = self
            .msgs
            .phase_four_msgs
            .iter()
            .fold(GE::generator(), |acc, (_i, v)| acc + v.open.public_share)
            .sub_point(&GE::generator().get_element());

        self.r_point = r * self.delta_sum.invert();
        self.r_x = ECScalar::from(
            &self
                .r_point
                .x_coor()
                .ok_or(MulEcdsaError::XcoorNone)?
                .mod_floor(&FE::q()),
        );
        Ok(())
    }

    fn phase_five_step_onetwo_generate_com_and_zk_offline_msg(&mut self) -> SignPhaseFiveStepOneTwoOffline{
        let l_i: FE = FE::new_random();
        let rho_i: FE = FE::new_random();
        self.l = l_i;
        self.rho = rho_i;
        let l_i_rho_i = l_i * rho_i;
        let base: GE = ECPoint::generator();
        let a_i = base * rho_i;
        let b_i = base * l_i_rho_i;
        let dl_proof = DLogProof::<GE>::prove(&rho_i);
        let steponetwo_offline_result = SignPhaseFiveStepOneTwoOffline {
            l_i,
            a_i,
            b_i,
            dl_proof
        };
        return steponetwo_offline_result
    }

    fn phase_five_step_onetwo_generate_com_and_zk_online_msg(&mut self) -> SignPhaseFiveStepOneMsg {
        let s_i = self.message * self.k + self.sigma * self.r_x;
        let base: GE = ECPoint::generator();
        let file_name = "./offline_result".to_string() + &self.party_index.to_string() + ".json";
        let data = fs::read_to_string(file_name)
            .expect("Unable to load step one two offline result, did you run multisignoffline first? ");
        let offline_result: (SignPhaseFiveStepOneTwoOffline, GE) =
            serde_json::from_str(&data).unwrap();
        let v_i = self.r_point * &s_i + base * offline_result.0.l_i;
        // Generate com
        let blind = BigInt::sample(SECURITY_BITS);
        let input_hash = HSha256::create_hash_from_ge(&[&v_i, &offline_result.0.a_i, &offline_result.0.b_i]).to_big_int();
        let commitment =
            HashCommitment::create_commitment_with_user_defined_randomness(&input_hash, &blind);

        // Generate zk proof
        let witness = HomoElGamalWitness { r: offline_result.0.l_i, x: s_i };
        let delta = HomoElGamalStatement {
            G: offline_result.0.a_i,
            H: self.r_point,
            Y: base,
            D: v_i,
            E: offline_result.0.b_i,
        };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        let msg_step_one = SignPhaseFiveStepOneMsg { commitment };
        let msg_step_two = SignPhaseFiveStepTwoMsg {
            v_i,
            a_i: offline_result.0.a_i,
            b_i: offline_result.0.b_i,
            blind,
            dl_proof: offline_result.0.dl_proof,
            proof,
        };
        let msg_step_seven = SignPhaseFiveStepSevenMsg { s_i };

        self.msgs
            .phase_five_step_one_msgs
            .insert(self.party_index, msg_step_one.clone());
        self.msgs
            .phase_five_step_two_msgs
            .insert(self.party_index, msg_step_two);
        self.msgs
            .phase_five_step_seven_msgs
            .insert(self.party_index, msg_step_seven);

        msg_step_one
    }

    fn handle_phase_five_step_two_msg(
        &mut self,
        index: usize,
        msg: &SignPhaseFiveStepTwoMsg,
    ) -> Result<(), MulEcdsaError> {
        let msg_one = self
            .msgs
            .phase_five_step_one_msgs
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        // Verify commitment
        let input_hash = HSha256::create_hash_from_ge(&[&msg.v_i, &msg.a_i, &msg.b_i]).to_big_int();

        if HashCommitment::create_commitment_with_user_defined_randomness(&input_hash, &msg.blind)
            != msg_one.commitment
        {
            return Err(MulEcdsaError::OpenGeCommFailed);
        }

        // Verify zk proof
        let delta = HomoElGamalStatement {
            G: msg.a_i,
            H: self.r_point,
            Y: ECPoint::generator(),
            D: msg.v_i,
            E: msg.b_i,
        };

        msg.proof
            .verify(&delta)
            .map_err(|_| MulEcdsaError::VrfyHomoElGamalFailed)?;
        DLogProof::verify(&msg.dl_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;

        Ok(())
    }

    fn generate_phase_five_step_four_msg(
        &mut self
    ) -> Result<SignPhaseFiveStepFourMsg, MulEcdsaError> {
        let my_msg = self
            .msgs
            .phase_five_step_two_msgs
            .get(&self.party_index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        let mut v_sum = my_msg.v_i.clone();
        for (index, msg) in self.msgs.phase_five_step_two_msgs.iter() {
            // Skip my own check
            if *index == self.party_index {
                continue;
            }
            v_sum = v_sum + msg.v_i;
        }

        // Compute V = -mP -rQ + sum (vi)
        let base: GE = ECPoint::generator();
        let mp = base * self.message;
        let rq = self.public_signing_key * &self.r_x;
        let v_big = v_sum
            .sub_point(&mp.get_element())
            .sub_point(&rq.get_element());

        let u_i = v_big * self.rho;
        let file_name = "./offline_result".to_string() + &self.party_index.to_string() + ".json";
        let data = fs::read_to_string(file_name)
            .expect("Unable to load step one two offline result, did you run multisignoffline first? ");
        let offline_result: (SignPhaseFiveStepOneTwoOffline, GE) =
            serde_json::from_str(&data).unwrap();
        let t_i = offline_result.1;

        let input_hash = HSha256::create_hash_from_ge(&[&u_i, &t_i]).to_big_int();
        let blind = BigInt::sample(SECURITY_BITS);
        let commitment =
            HashCommitment::create_commitment_with_user_defined_randomness(&input_hash, &blind);

        let msg_step_four = SignPhaseFiveStepFourMsg { commitment };
        let msg_step_five = SignPhaseFiveStepFiveMsg { blind, u_i, t_i };

        self.msgs
            .phase_five_step_four_msgs
            .insert(self.party_index, msg_step_four.clone());
        self.msgs
            .phase_five_step_five_msgs
            .insert(self.party_index, msg_step_five);

        Ok(msg_step_four)
    }

    fn handle_phase_five_step_five_msg(
        &self,
        index: usize,
        msg_five: &SignPhaseFiveStepFiveMsg,
    ) -> Result<(), MulEcdsaError> {
        let msg_four = self
            .msgs
            .phase_five_step_four_msgs
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        let input_hash = HSha256::create_hash_from_ge(&[&msg_five.u_i, &msg_five.t_i]).to_big_int();
        if HashCommitment::create_commitment_with_user_defined_randomness(
            &input_hash,
            &msg_five.blind,
        ) != msg_four.commitment
        {
            return Err(MulEcdsaError::OpenGeCommFailed);
        }

        Ok(())
    }

    fn phase_five_step_six_check_sum_a_t(&self) -> Result<(), MulEcdsaError> {
        let base: GE = ECPoint::generator();
        let biased_sum_ti = self
            .msgs
            .phase_five_step_five_msgs
            .iter()
            .fold(base, |acc, (_i, x)| acc + x.t_i);
        let biased_sum_ti_minus_ui = self
            .msgs
            .phase_five_step_five_msgs
            .iter()
            .fold(biased_sum_ti, |acc, (_i, x)| {
                acc.sub_point(&x.u_i.get_element())
            });

        if base != biased_sum_ti_minus_ui {
            return Err(MulEcdsaError::VrfySumatFailed);
        }

        Ok(())
    }

    fn phase_five_step_eight_generate_signature_msg(&self) -> Result<Signature, MulEcdsaError> {
        if self.msgs.phase_five_step_seven_msgs.len() != self.party_num {
            return Err(MulEcdsaError::LeftNotEqualRight);
        }

        let mut s = self
            .msgs
            .phase_five_step_seven_msgs
            .iter()
            .fold(FE::zero(), |acc, (_i, x)| acc + x.s_i);
        let s_bn = s.to_big_int();
        let s_tag_bn = FE::q() - &s_bn;
        if s_bn > s_tag_bn {
            s = ECScalar::from(&s_tag_bn);
        }

        Ok(Signature { s, r: self.r_x })
    }

    pub fn process_begin(&mut self, index: usize) -> Result<SendingMessages, MulEcdsaError> {
        if self.subset.contains(&index) {
            let msg = self.get_phase_one_msg()?;
            return Ok(SendingMessages::SubsetMessage(msg));
        }
        Ok(SendingMessages::EmptyMsg)
    }

    pub fn process_online_begin(&mut self, index: usize, message_str: String) -> Result<SendingMessages, MulEcdsaError> {
        if self.subset.contains(&index) {
            let message_bigint =
                BigInt::from_hex(&message_str).map_err(|_| MulEcdsaError::FromHexFailed)?;
                let message: FE = ECScalar::from(&message_bigint);
            self.message = message;
            let msg_five_one = self.phase_five_step_onetwo_generate_com_and_zk_online_msg();
            let sending_msg = ReceivingMessages::MultiSignMessage(
                MultiSignMessage::PhaseFiveStepOneMsg(msg_five_one.clone()),
            );
            let sending_msg_bytes = bincode::serialize(&sending_msg)
                .map_err(|_| MulEcdsaError::SerializeFailed)?;
            return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
       }
       Ok(SendingMessages::EmptyMsg)
    }

    pub fn msg_handler(
        &mut self,
        index: usize,
        msg_received: &MultiSignMessage,
    ) -> Result<SendingMessages, MulEcdsaError> {
        // println!("handle receiving msg: {:?}", msg_received);
        if self.subset.contains(&index) {
            match msg_received {
                MultiSignMessage::PhaseOneMsg(msg) => {
                    // Already received the msg
                    if self.msgs.phase_one_msgs.get(&index).is_some() {
                        return Ok(SendingMessages::EmptyMsg);
                    }
                    // Handle the msg and generate the reply msg
                    self.msgs.phase_one_msgs.insert(index, msg.clone());

                    let msg = self.handle_phase_one_msg(index, &msg)?;
                    return Ok(SendingMessages::NormalMessage(index, msg));
                }
                MultiSignMessage::PhaseTwoMsg(msg) => {
                    // Already received the msg
                    if self.msgs.phase_two_msgs.get(&index).is_some() {
                        return Ok(SendingMessages::EmptyMsg);
                    }

                    // Handle the msg
                    self.handle_phase_two_msg(index, &msg)?;

                    self.msgs.phase_two_msgs.insert(index, msg.clone());
                    // Generate the next msg
                    if self.msgs.phase_two_msgs.len() == (self.party_num - 1) {
                        let msg_three = SignPhaseThreeMsg {
                            delta: self.delta.clone(),
                        };
                        self.msgs
                            .phase_three_msgs
                            .insert(self.party_index, msg_three.clone());
                        let sending_msg = ReceivingMessages::MultiSignMessage(
                            MultiSignMessage::PhaseThreeMsg(msg_three),
                        );
                        let sending_msg_bytes = bincode::serialize(&sending_msg)
                            .map_err(|_| MulEcdsaError::SerializeFailed)?;
                        return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                    }
                }
                MultiSignMessage::PhaseThreeMsg(msg) => {
                    self.msgs.phase_three_msgs.insert(index, msg.clone());
                    if self.msgs.phase_three_msgs.len() == self.party_num {
                        self.phase_two_compute_delta_sum_msg()?;
                        let msg_four = self
                            .msgs
                            .phase_four_msgs
                            .get(&self.party_index)
                            .ok_or(MulEcdsaError::GetIndexFailed)?;
                        let sending_msg = ReceivingMessages::MultiSignMessage(
                            MultiSignMessage::PhaseFourMsg(msg_four.clone()),
                        );
                        let sending_msg_bytes = bincode::serialize(&sending_msg)
                            .map_err(|_| MulEcdsaError::GetIndexFailed)?;
                        return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                    }
                }
                MultiSignMessage::PhaseFourMsg(msg) => {
                    // Already received the msg
                    if self.msgs.phase_four_msgs.get(&index).is_some() {
                        return Ok(SendingMessages::EmptyMsg);
                    }

                    // Handle the msg
                    self.handle_phase_four_msg(index, &msg)?;

                    self.msgs.phase_four_msgs.insert(index, msg.clone());
                    // Generate the next msg
                    if self.msgs.phase_four_msgs.len() == self.party_num {
                        self.compute_r_x()?;
                        let steponetwo_offline_result = self.phase_five_step_onetwo_generate_com_and_zk_offline_msg();
                        let file_name = "./offline_result".to_string() + &self.party_index.to_string() + ".json";
                        let offline_path = Path::new(&file_name);
                        let offline_json = serde_json::to_string(&steponetwo_offline_result)
                        .unwrap();
                        fs::write(offline_path, offline_json).expect("Unable to save !");
                        self.a_i_vec.push(steponetwo_offline_result.a_i);
                        let sending_msg = ReceivingMessages::MultiSignMessage(MultiSignMessage::PhaseFiveStepOneTwoOfflineMsg(steponetwo_offline_result));
                        let sending_msg_bytes = bincode::serialize(&sending_msg)
                            .map_err(|_| MulEcdsaError::GetIndexFailed)?;
                        return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                    }
                }
                MultiSignMessage:: PhaseFiveStepOneTwoOfflineMsg(msg) => {
                    self.a_i_vec.push(msg.a_i);
                    if self.a_i_vec.len() == self.party_num {
                        let (head, tail) = self.a_i_vec.split_at(1);
                        let a_sum = tail.iter().fold(head[0], |acc, x| acc + x);
                        let t_i = a_sum * &self.l;
                        let file_name = "./offline_result".to_string() + &self.party_index.to_string() + ".json";
                        let data = fs::read_to_string(file_name.clone()).expect("Unable to load step one two offline result, did you run multisignoffline first? ");
                        let steponetwo_offline_result: SignPhaseFiveStepOneTwoOffline = serde_json::from_str(&data).unwrap();
                        let offline_json = serde_json::to_string(&(steponetwo_offline_result, t_i))
                        .unwrap();
                        fs::write(file_name, offline_json).expect("Unable to save !");
                    } 
                    println!("offline finish");
                }     
                MultiSignMessage::PhaseFiveStepOneMsg(msg) => {
                    self.msgs
                        .phase_five_step_one_msgs
                        .insert(index, msg.clone());
                    if self.msgs.phase_five_step_one_msgs.len() == self.party_num {
                        let msg_five_two = self
                            .msgs
                            .phase_five_step_two_msgs
                            .get(&self.party_index)
                            .ok_or(MulEcdsaError::GetIndexFailed)?;
                        let sending_msg = ReceivingMessages::MultiSignMessage(
                            MultiSignMessage::PhaseFiveStepTwoMsg(msg_five_two.clone()),
                        );
                        let sending_msg_bytes = bincode::serialize(&sending_msg)
                            .map_err(|_| MulEcdsaError::GetIndexFailed)?;
                        return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                    }
                }
                MultiSignMessage::PhaseFiveStepTwoMsg(msg) => {
                    // Already received the msg
                    if self.msgs.phase_five_step_two_msgs.get(&index).is_some() {
                        return Ok(SendingMessages::EmptyMsg);
                    }

                    // Handle the msg
                    self.handle_phase_five_step_two_msg(index, &msg)?;

                    self.msgs
                        .phase_five_step_two_msgs
                        .insert(index, msg.clone());
                    // Generate the next msg
                    if self.msgs.phase_five_step_two_msgs.len() == self.party_num {
                        let msg_five_four = self.generate_phase_five_step_four_msg()?;
                        let sending_msg = ReceivingMessages::MultiSignMessage(
                            MultiSignMessage::PhaseFiveStepFourMsg(msg_five_four.clone()),
                        );
                        let sending_msg_bytes = bincode::serialize(&sending_msg)
                            .map_err(|_| MulEcdsaError::SerializeFailed)?;
                        return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                    }
                }
                MultiSignMessage::PhaseFiveStepFourMsg(msg) => {
                    self.msgs
                        .phase_five_step_four_msgs
                        .insert(index, msg.clone());
                    if self.msgs.phase_five_step_four_msgs.len() == self.party_num {
                        let msg_five_five = self
                            .msgs
                            .phase_five_step_five_msgs
                            .get(&self.party_index)
                            .ok_or(MulEcdsaError::GetIndexFailed)?;
                        let sending_msg = ReceivingMessages::MultiSignMessage(
                            MultiSignMessage::PhaseFiveStepFiveMsg(msg_five_five.clone()),
                        );
                        let sending_msg_bytes = bincode::serialize(&sending_msg)
                            .map_err(|_| MulEcdsaError::SerializeFailed)?;
                        return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                    }
                }
                MultiSignMessage::PhaseFiveStepFiveMsg(msg) => {
                    // Already received the msg
                    if self.msgs.phase_five_step_five_msgs.get(&index).is_some() {
                        return Ok(SendingMessages::EmptyMsg);
                    }

                    // Handle the msg
                    self.handle_phase_five_step_five_msg(index, &msg)?;

                    self.msgs
                        .phase_five_step_five_msgs
                        .insert(index, msg.clone());
                    // Generate the next msg
                    if self.msgs.phase_five_step_five_msgs.len() == self.party_num {
                        self.phase_five_step_six_check_sum_a_t()
                            .map_err(|_| MulEcdsaError::VrfySumatFailed)?;
                        let msg_seven = self
                            .msgs
                            .phase_five_step_seven_msgs
                            .get(&self.party_index)
                            .ok_or(MulEcdsaError::GetIndexFailed)?;
                        let sending_msg = ReceivingMessages::MultiSignMessage(
                            MultiSignMessage::PhaseFiveStepSevenMsg(msg_seven.clone()),
                        );
                        let sending_msg_bytes = bincode::serialize(&sending_msg)
                            .map_err(|_| MulEcdsaError::SerializeFailed)?;
                        return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                    }
                }
                MultiSignMessage::PhaseFiveStepSevenMsg(msg) => {
                    self.msgs
                        .phase_five_step_seven_msgs
                        .insert(index, msg.clone());
                    if self.msgs.phase_five_step_seven_msgs.len() == self.party_num {
                        let signature = self.phase_five_step_eight_generate_signature_msg()?;

                        signature.verify(&self.public_signing_key, &self.message)?;

                        let signature_json = serde_json::to_string(&signature)
                            .map_err(|_| MulEcdsaError::ToStringFailed)?;
                        self.need_refresh = true;
                        return Ok(SendingMessages::SignSuccessWithResult(signature_json));
                    }
                }
            }
        }

        Ok(SendingMessages::EmptyMsg)
    }
}
