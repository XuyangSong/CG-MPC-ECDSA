use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::ProofError;
use crate::utilities::promise_sigma::*;
use crate::utilities::signature::Signature;
use crate::utilities::SECURITY_BITS;
use class_group::primitives::cl_dl_public_setup::{
    decrypt, encrypt_without_r, CLGroup, Ciphertext as CLCipher, SK as CLSK,
};

use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::ours::keygen::Parameters;
use crate::protocols::multi_party::ours::message::*;
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
use std::collections::HashMap;

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
    // add cl group here
    pub party_index: usize,
    pub party_num: usize,
    pub params: Parameters,
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
    pub beta_vec: Vec<FE>,
    pub v_vec: Vec<FE>,
    pub beta_map: HashMap<usize, FE>,
    pub v_map: HashMap<usize, FE>,
    pub clsk: CLSK,
    pub msgs: SignMsgs,
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
}

impl SignPhase {
    pub fn new() -> Self {
        let params = Parameters {
            threshold: 0,
            share_count: 0,
        };

        Self {
            party_index: 0,
            party_num: 0,
            params,
            public_signing_key: GE::generator(),
            message: FE::zero(),
            clsk: CLSK::from(BigInt::zero()),
            omega: FE::zero(),
            big_omega_map: HashMap::new(),
            k: FE::zero(),            // Init k, generate later.
            gamma: FE::zero(),        // Init gamma, generate later.
            delta: FE::zero(),        // Init delta, generate later.
            sigma: FE::zero(),        // Init sigma, generate later.
            delta_sum: FE::zero(),    // Init delta_sum, compute later.
            r_x: FE::zero(),          // Init r_x, compute later.
            r_point: GE::generator(), // Init r_point, compute later.
            rho: FE::zero(),          // Init rho, generate later.
            l: FE::zero(),            // Init l, generate later.
            beta_vec: Vec::new(),     // Init random beta, generate later.
            v_vec: Vec::new(),        // Init random v, generate later.
            beta_map: HashMap::new(),
            v_map: HashMap::new(),
            msgs: SignMsgs::new(),
        }
    }

    // Merge new and init
    pub fn init_msg(
        &mut self,
        party_index: usize,
        params: Parameters,
        clsk: CLSK,
        vss_scheme_map: &HashMap<usize, VerifiableSS>,
        subset: &[usize],
        share_public_key_map: &HashMap<usize, GE>,
        x: &FE,
        party_num: usize,
        public_signing_key: GE,
        message: FE,
    ) {
        assert!(party_num > params.threshold);
        assert_eq!(vss_scheme_map.len(), params.share_count);
        assert_eq!(share_public_key_map.len(), params.share_count);

        let lamda = vss_scheme_map
            .get(&party_index)
            .unwrap()
            .map_share_to_new_params(party_index, subset);
        let omega = lamda * x;
        let mut big_omega_map = HashMap::new();
        let _big_omega_vec = subset
            .iter()
            .filter_map(|i| {
                if *i != party_index {
                    let share_public_key = share_public_key_map.get(i).unwrap();
                    let vss_scheme = vss_scheme_map.get(i).unwrap();
                    let ret = share_public_key * &vss_scheme.map_share_to_new_params(*i, subset);
                    big_omega_map.insert(*i, ret.clone());
                    Some(ret)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        self.party_index = party_index;
        self.party_num = party_num;
        self.params = params;
        self.public_signing_key = public_signing_key;
        self.message = message;
        self.clsk = clsk;
        self.omega = omega;
        self.big_omega_map = big_omega_map;
        assert_eq!(self.big_omega_map.len(), self.party_num - 1);
    }

    pub fn phase_one_generate_promise_sigma_and_com_msg(
        &mut self,
        group: &CLGroup,
        // TBD: put keypair in signphase
        cl_keypair: &ClKeyPair,
        ec_keypair: &EcKeyPair,
    ) -> SignPhaseOneMsg {
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

        msg_one
    }

    pub fn phase_two_generate_homo_cipher_msg(
        &mut self,
        group: &CLGroup,
    ) -> HashMap<usize, Vec<u8>> {
        assert_eq!(self.msgs.phase_one_msgs.len(), self.party_num);

        let mut sending_msgs: HashMap<usize, Vec<u8>> = HashMap::new();
        let zero = FE::zero();
        for (index, msg) in self.msgs.phase_one_msgs.iter() {
            if *index == self.party_index {
                continue;
            }

            // TBD: check ec cl pk

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
                    encrypt_without_r(&group, &zero.sub(&beta.get_element()));
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
                let (r_cipher, _r_blind) = encrypt_without_r(&group, &zero.sub(&v.get_element()));
                let c11 = cipher.c1.exp(&omega_plus_t);
                let c21 = cipher.c2.exp(&omega_plus_t);
                let c1 = c11.compose(&r_cipher.c1).reduce();
                let c2 = c21.compose(&r_cipher.c2).reduce();
                homocipher_plus = CLCipher { c1, c2 };

                let base: GE = ECPoint::generator();
                b = base * v;
            }

            let msg_two = SignPhaseTwoMsg {
                homocipher,
                homocipher_plus,
                t_p,
                t_p_plus,
                b,
            };

            self.beta_map.insert(*index, beta);
            self.v_map.insert(*index, v);

            let sending_msg =
                ReceivingMessages::MultiSignMessage(MultiSignMessage::PhaseTwoMsg(msg_two));
            let msg_bytes = bincode::serialize(&sending_msg).unwrap();
            sending_msgs.insert(*index, msg_bytes);
        }

        sending_msgs
    }

    pub fn handle_phase_two_msg(
        &mut self,
        group: &CLGroup,
        index: usize,
        msg: &SignPhaseTwoMsg,
    ) -> Result<(), ProofError> {
        // Compute delta
        let k_mul_t = self.k * msg.t_p;
        let alpha = decrypt(&group, &self.clsk, &msg.homocipher).sub(&k_mul_t.get_element());
        let beta = self.beta_map.get(&index).unwrap();
        self.delta = self.delta + alpha + beta;

        // Compute sigma
        let k_mul_t_plus = self.k * msg.t_p_plus;
        let miu =
            decrypt(&group, &self.clsk, &msg.homocipher_plus).sub(&k_mul_t_plus.get_element());
        let v = self.v_map.get(&index).unwrap();
        self.sigma = self.sigma + miu + v;

        // Check kW = uP + B
        let big_omega = self.big_omega_map.get(&index).unwrap();
        let k_omega = big_omega * &self.k;
        let base: GE = ECPoint::generator();
        let up_plus_b = base * miu + msg.b;
        assert_eq!(k_omega, up_plus_b);

        Ok(())
        // SignPhaseThreeMsg { delta }
    }

    pub fn phase_two_compute_delta_sum_msg(&mut self) {
        assert_eq!(self.msgs.phase_three_msgs.len(), self.party_num);

        self.delta_sum = self
            .msgs
            .phase_three_msgs
            .iter()
            .fold(FE::zero(), |acc, (_i, v)| acc + v.delta);
    }

    pub fn handle_phase_four_msg(
        &mut self,
        index: usize,
        msg: &SignPhaseFourMsg,
    ) -> Result<(), ProofError> {
        let msg_one = self.msgs.phase_one_msgs.get(&index).unwrap();
        DlogCommitment::verify_dlog(&msg_one.commitment, &msg.open)?;

        Ok(())
    }

    pub fn compute_r_x(&mut self) {
        let r = self
            .msgs
            .phase_four_msgs
            .iter()
            .fold(GE::generator(), |acc, (_i, v)| acc + v.open.public_share)
            .sub_point(&GE::generator().get_element());

        self.r_point = r * self.delta_sum.invert();
        self.r_x = ECScalar::from(&self.r_point.x_coor().unwrap().mod_floor(&FE::q()));
    }

    pub fn phase_five_step_onetwo_generate_com_and_zk_msg(&mut self) -> SignPhaseFiveStepOneMsg {
        let s_i = (self.message) * self.k + self.sigma * self.r_x;
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

    pub fn handle_phase_five_step_two_msg(
        &mut self,
        index: usize,
        msg: &SignPhaseFiveStepTwoMsg,
    ) -> Result<(), ProofError> {
        let msg_one = self.msgs.phase_five_step_one_msgs.get(&index).unwrap();
        // Verify commitment
        let input_hash = HSha256::create_hash_from_ge(&[&msg.v_i, &msg.a_i, &msg.b_i]).to_big_int();

        if HashCommitment::create_commitment_with_user_defined_randomness(&input_hash, &msg.blind)
            != msg_one.commitment
        {
            return Err(ProofError);
        }

        // Verify zk proof
        let delta = HomoElGamalStatement {
            G: msg.a_i,
            H: self.r_point,
            Y: ECPoint::generator(),
            D: msg.v_i,
            E: msg.b_i,
        };

        msg.proof.verify(&delta).unwrap();
        DLogProof::verify(&msg.dl_proof).unwrap();

        Ok(())
    }

    pub fn generate_phase_five_step_four_msg(&mut self) -> SignPhaseFiveStepFourMsg {
        let my_msg = self
            .msgs
            .phase_five_step_two_msgs
            .get(&self.party_index)
            .unwrap();
        let mut v_sum = my_msg.v_i.clone();
        let mut a_sum = my_msg.a_i.clone();
        for (index, msg) in self.msgs.phase_five_step_two_msgs.iter() {
            // Skip my own check
            if *index == self.party_index {
                continue;
            }

            v_sum = v_sum + msg.v_i;
            a_sum = a_sum + msg.a_i;
        }

        // Compute V = -mP -rQ + sum (vi)
        let base: GE = ECPoint::generator();
        let mp = base * self.message;
        let rq = self.public_signing_key * &self.r_x;
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

        self.msgs
            .phase_five_step_four_msgs
            .insert(self.party_index, msg_step_four.clone());
        self.msgs
            .phase_five_step_five_msgs
            .insert(self.party_index, msg_step_five);

        msg_step_four
    }

    pub fn handle_phase_five_step_five_msg(
        &self,
        index: usize,
        msg_five: &SignPhaseFiveStepFiveMsg,
    ) -> Result<(), ProofError> {
        let msg_four = self.msgs.phase_five_step_four_msgs.get(&index).unwrap();
        let input_hash = HSha256::create_hash_from_ge(&[&msg_five.u_i, &msg_five.t_i]).to_big_int();
        if HashCommitment::create_commitment_with_user_defined_randomness(
            &input_hash,
            &msg_five.blind,
        ) != msg_four.commitment
        {
            return Err(ProofError);
        }

        Ok(())
    }

    pub fn phase_five_step_six_check_sum_a_t(&self) -> Result<(), ProofError> {
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
            return Err(ProofError);
        }

        Ok(())
    }

    pub fn phase_five_step_eight_generate_signature_msg(&self) -> Signature {
        assert_eq!(self.msgs.phase_five_step_seven_msgs.len(), self.party_num);

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

        Signature { s, r: self.r_x }
    }

    pub fn msg_handler(
        &mut self,
        group: &CLGroup,
        index: usize,
        msg_received: &MultiSignMessage,
    ) -> SendingMessages {
        // println!("handle receiving msg: {:?}", msg_received);
        match msg_received {
            MultiSignMessage::SignBegin => {
                if self.msgs.phase_one_msgs.len() == self.party_num {
                    let sending_msg = self.phase_two_generate_homo_cipher_msg(group);
                    return SendingMessages::P2pMessage(sending_msg);
                }
            }
            MultiSignMessage::PhaseOneMsg(msg) => {
                self.msgs.phase_one_msgs.insert(index, msg.clone());
                if self.msgs.phase_one_msgs.len() == self.party_num {
                    // TBD: put it in init phase
                    let sending_msg = self.phase_two_generate_homo_cipher_msg(group);
                    return SendingMessages::P2pMessage(sending_msg);
                }
            }
            MultiSignMessage::PhaseTwoMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_two_msgs.get(&index).is_some() {
                    return SendingMessages::EmptyMsg;
                }

                // Handle the msg
                self.handle_phase_two_msg(group, index, &msg).unwrap();
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
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiSignMessage::PhaseThreeMsg(msg) => {
                self.msgs.phase_three_msgs.insert(index, msg.clone());
                if self.msgs.phase_three_msgs.len() == self.party_num {
                    self.phase_two_compute_delta_sum_msg();
                    let msg_four = self.msgs.phase_four_msgs.get(&self.party_index).unwrap();
                    let sending_msg = ReceivingMessages::MultiSignMessage(
                        MultiSignMessage::PhaseFourMsg(msg_four.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiSignMessage::PhaseFourMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_four_msgs.get(&index).is_some() {
                    return SendingMessages::EmptyMsg;
                }

                // Handle the msg
                self.handle_phase_four_msg(index, &msg).unwrap();
                self.msgs.phase_four_msgs.insert(index, msg.clone());

                // Generate the next msg
                if self.msgs.phase_four_msgs.len() == self.party_num {
                    self.compute_r_x();
                    let msg_five_one = self.phase_five_step_onetwo_generate_com_and_zk_msg();
                    let sending_msg = ReceivingMessages::MultiSignMessage(
                        MultiSignMessage::PhaseFiveStepOneMsg(msg_five_one.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
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
                        .unwrap();
                    let sending_msg = ReceivingMessages::MultiSignMessage(
                        MultiSignMessage::PhaseFiveStepTwoMsg(msg_five_two.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiSignMessage::PhaseFiveStepTwoMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_five_step_two_msgs.get(&index).is_some() {
                    return SendingMessages::EmptyMsg;
                }

                // Handle the msg
                self.handle_phase_five_step_two_msg(index, &msg).unwrap();
                self.msgs
                    .phase_five_step_two_msgs
                    .insert(index, msg.clone());

                // Generate the next msg
                if self.msgs.phase_five_step_two_msgs.len() == self.party_num {
                    let msg_five_four = self.generate_phase_five_step_four_msg();
                    let sending_msg = ReceivingMessages::MultiSignMessage(
                        MultiSignMessage::PhaseFiveStepFourMsg(msg_five_four.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
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
                        .unwrap();
                    let sending_msg = ReceivingMessages::MultiSignMessage(
                        MultiSignMessage::PhaseFiveStepFiveMsg(msg_five_five.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiSignMessage::PhaseFiveStepFiveMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_five_step_five_msgs.get(&index).is_some() {
                    return SendingMessages::EmptyMsg;
                }

                // Handle the msg
                self.handle_phase_five_step_five_msg(index, &msg).unwrap();
                self.msgs
                    .phase_five_step_five_msgs
                    .insert(index, msg.clone());

                // Generate the next msg
                if self.msgs.phase_five_step_five_msgs.len() == self.party_num {
                    self.phase_five_step_six_check_sum_a_t().unwrap();
                    let msg_seven = self
                        .msgs
                        .phase_five_step_seven_msgs
                        .get(&self.party_index)
                        .unwrap();
                    let sending_msg = ReceivingMessages::MultiSignMessage(
                        MultiSignMessage::PhaseFiveStepSevenMsg(msg_seven.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiSignMessage::PhaseFiveStepSevenMsg(msg) => {
                self.msgs
                    .phase_five_step_seven_msgs
                    .insert(index, msg.clone());
                if self.msgs.phase_five_step_seven_msgs.len() == self.party_num {
                    let signature = self.phase_five_step_eight_generate_signature_msg();
                    println!("Signature: {:?}", signature);
                    return SendingMessages::SignSuccess;
                }
            }
        }

        SendingMessages::EmptyMsg
    }
}
