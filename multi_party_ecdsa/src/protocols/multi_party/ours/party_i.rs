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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub share_public_key: Vec<GE>,      // X_i
    pub vss_scheme_vec: Vec<VerifiableSS>,
    pub msgs: KeyGenMsgs,
}

#[derive(Clone, Debug)]
pub struct KeyGenMsgs {
    pub phase_two_msgs: HashMap<usize, KeyGenPhaseTwoMsg>,
    pub phase_three_msgs: HashMap<usize, KeyGenPhaseThreeMsg>,
    pub phase_four_msgs: HashMap<usize, KeyGenPhaseFourMsg>,
    pub phase_five_msgs: HashMap<usize, KeyGenPhaseFiveMsg>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenPhaseTwoMsg {
    // pub ec_pk: GE,
    // pub cl_pk: CLPK,
    pub commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenPhaseThreeMsg {
    pub open: DlogCommitmentOpen,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenPhaseFourMsg {
    pub vss_scheme: VerifiableSS,
    pub secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenPhaseFiveMsg {
    pub dl_proof: DLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MultiKeyGenMessage {
    KeyGenBegin,
    PhaseTwoMsg(KeyGenPhaseTwoMsg),
    PhaseThreeMsg(KeyGenPhaseThreeMsg),
    PhaseFourMsg(KeyGenPhaseFourMsg),
    PhaseFiveMsg(KeyGenPhaseFiveMsg),
}

#[derive(Clone, Debug)]
pub struct SignPhase {
    pub party_index: usize,
    pub party_num: usize,
    pub params: Parameters,
    pub public_signing_key: GE,
    pub message: FE,
    pub omega: FE,
    pub big_omega_map: HashMap<usize, GE>,
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
    pub beta_map: HashMap<usize, FE>,
    pub v_map: HashMap<usize, FE>,
    pub clsk: CLSK,
    pub msgs: SignMsgs,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MultiSignMessage {
    SignBegin,
    PhaseOneMsg(SignPhaseOneMsg),
    PhaseTwoMsg(SignPhaseTwoMsg),
    PhaseThreeMsg(SignPhaseThreeMsg),
    PhaseFourMsg(SignPhaseFourMsg),
    PhaseFiveStepOneMsg(SignPhaseFiveStepOneMsg),
    PhaseFiveStepTwoMsg(SignPhaseFiveStepTwoMsg),
    PhaseFiveStepFourMsg(SignPhaseFiveStepFourMsg),
    PhaseFiveStepFiveMsg(SignPhaseFiveStepFiveMsg),
    PhaseFiveStepSevenMsg(SignPhaseFiveStepSevenMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseOneMsg {
    pub commitment: BigInt,
    pub promise_state: PromiseState,
    pub proof: PromiseProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseTwoMsg {
    pub homocipher: CLCipher,
    pub homocipher_plus: CLCipher,
    pub t_p: FE,
    pub t_p_plus: FE,
    pub b: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseThreeMsg {
    pub delta: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFourMsg {
    pub open: DlogCommitmentOpen,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepOneMsg {
    commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepTwoMsg {
    v_i: GE,
    a_i: GE,
    b_i: GE,
    blind: BigInt,
    dl_proof: DLogProof,
    proof: HomoELGamalProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepFourMsg {
    commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepFiveMsg {
    blind: BigInt,
    u_i: GE,
    t_i: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepSevenMsg {
    pub s_i: FE,
}

impl KeyGen {
    pub fn phase_one_init(group: &CLGroup, party_index: usize, params: Parameters) -> Self {
        let ec_keypair = EcKeyPair::new(); // Generate ec key pair.
        let cl_keypair = ClKeyPair::new(group); // Generate cl key pair.
        let private_signing_key = EcKeyPair::new(); // Generate private key pair.
        let public_signing_key = private_signing_key.get_public_key().clone(); // Init public key, compute later.
        let share_public_key = Vec::with_capacity(params.share_count); // Init share public key, receive later.
        let share_private_key = ECScalar::zero(); // Init share private key, compute later.
        let vss_scheme_vec = Vec::with_capacity(params.share_count); // Init vss_scheme_vec, receive later.
        Self {
            party_index,
            params,
            ec_keypair,
            cl_keypair,
            private_signing_key,
            public_signing_key,
            share_private_key,
            share_public_key,
            vss_scheme_vec,
            msgs: KeyGenMsgs::new(),
        }
    }

    pub fn phase_two_generate_dl_com(&self) -> DlogCommitment {
        DlogCommitment::new(&self.private_signing_key.get_public_key())
    }

    pub fn phase_two_generate_dl_com_msg(&mut self) -> ReceivingMessages {
        let dlog_com = DlogCommitment::new(&self.private_signing_key.get_public_key());
        let msg_2 = KeyGenPhaseTwoMsg {
            commitment: dlog_com.commitment,
        };

        let msg_3 = KeyGenPhaseThreeMsg {
            open: dlog_com.open,
        };

        self.msgs
            .phase_two_msgs
            .insert(self.party_index, msg_2.clone());
        self.msgs.phase_three_msgs.insert(self.party_index, msg_3);

        ReceivingMessages::MultiKeyGenMessage(MultiKeyGenMessage::PhaseTwoMsg(msg_2))
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

    pub fn phase_three_verify_dl_com_and_generate_signing_key_msg(
        &mut self,
    ) -> Result<(), ProofError> {
        assert_eq!(self.msgs.phase_two_msgs.len(), self.params.share_count);
        assert_eq!(self.msgs.phase_three_msgs.len(), self.params.share_count);
        for i in 0..self.params.share_count {
            if i == self.party_index {
                continue;
            }
            let commitment = self.msgs.phase_two_msgs.get(&i).unwrap().commitment.clone();
            let open = self.msgs.phase_three_msgs.get(&i).unwrap().open.clone();

            let dlog_com = DlogCommitment { commitment, open };
            dlog_com.verify()?;

            self.public_signing_key = self.public_signing_key + dlog_com.get_public_share();
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

    pub fn phase_five_verify_vss_and_generate_pok_dlog_msg(
        &mut self,
    ) -> Result<KeyGenPhaseFiveMsg, ProofError> {
        assert_eq!(self.msgs.phase_three_msgs.len(), self.params.share_count);
        assert_eq!(self.msgs.phase_four_msgs.len(), self.params.share_count);

        // Check VSS
        for i in 0..(self.params.share_count) {
            let q = self
                .msgs
                .phase_three_msgs
                .get(&i)
                .unwrap()
                .open
                .public_share;
            let vss = self.msgs.phase_four_msgs.get(&i).unwrap();
            if !(vss
                .vss_scheme
                .validate_share(&vss.secret_share, self.party_index + 1)
                .is_ok()
                && vss.vss_scheme.commitments[0] == q)
            {
                return Err(ProofError);
            }

            self.share_private_key = self.share_private_key + vss.secret_share;
            self.vss_scheme_vec.push(vss.vss_scheme.clone());
        }

        // Compute share private key(x_i)
        let dl_proof = DLogProof::prove(&self.share_private_key);

        Ok(KeyGenPhaseFiveMsg { dl_proof })
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

    pub fn phase_six_verify_dlog_proof_msg(&mut self) -> Result<(), ProofError> {
        assert_eq!(self.msgs.phase_five_msgs.len(), self.params.share_count);
        for i in 0..self.params.share_count {
            let msg = self.msgs.phase_five_msgs.get(&i).unwrap();
            DLogProof::verify(&msg.dl_proof).unwrap();
            self.share_public_key.push(msg.dl_proof.pk);
        }

        Ok(())
    }

    pub fn msg_handler(&mut self, group: &CLGroup, index: usize, msg: &MultiKeyGenMessage) -> SendingMessages {
        // println!("handle receiving msg: {:?}", msg);

        match msg {
            MultiKeyGenMessage::KeyGenBegin => {
                if self.msgs.phase_two_msgs.len() == self.params.share_count {
                    let keygen_phase_three_msg =
                        self.msgs.phase_three_msgs.get(&self.party_index).unwrap();
                    let sending_msg = ReceivingMessages::MultiKeyGenMessage(
                        MultiKeyGenMessage::PhaseThreeMsg(keygen_phase_three_msg.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiKeyGenMessage::PhaseTwoMsg(msg) => {
                if self.msgs.phase_two_msgs.len() == self.params.share_count {
                    let keygen_phase_three_msg =
                        self.msgs.phase_three_msgs.get(&self.party_index).unwrap();
                    let sending_msg = ReceivingMessages::MultiKeyGenMessage(
                        MultiKeyGenMessage::PhaseThreeMsg(keygen_phase_three_msg.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiKeyGenMessage::PhaseThreeMsg(msg) => {
                self.msgs.phase_three_msgs.insert(index, msg.clone());
                if self.msgs.phase_three_msgs.len() == self.params.share_count {
                    self.phase_three_verify_dl_com_and_generate_signing_key_msg()
                        .unwrap();
                    let (vss_scheme, secret_shares, _index) = self.phase_four_generate_vss();
                    let mut sending_msg: HashMap<usize, Vec<u8>> = HashMap::new();
                    for i in 0..self.params.share_count {
                        let msg = KeyGenPhaseFourMsg {
                            vss_scheme: vss_scheme.clone(),
                            secret_share: secret_shares[i],
                        };

                        if i == self.party_index {
                            // send to myself
                            self.msgs.phase_four_msgs.insert(i, msg);
                        } else {
                            let phase_four_msg = ReceivingMessages::MultiKeyGenMessage(
                                MultiKeyGenMessage::PhaseFourMsg(msg),
                            );
                            let msg_bytes = bincode::serialize(&phase_four_msg).unwrap();
                            sending_msg.insert(i, msg_bytes);
                        }
                    }

                    return SendingMessages::P2pMessage(sending_msg);
                }
            }
            MultiKeyGenMessage::PhaseFourMsg(msg) => {
                self.msgs.phase_four_msgs.insert(index, msg.clone());
                if self.msgs.phase_four_msgs.len() == self.params.share_count {
                    let msg_five = self
                        .phase_five_verify_vss_and_generate_pok_dlog_msg()
                        .unwrap();
                    self.msgs
                        .phase_five_msgs
                        .insert(self.party_index, msg_five.clone());
                    let sending_msg = ReceivingMessages::MultiKeyGenMessage(
                        MultiKeyGenMessage::PhaseFiveMsg(msg_five),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiKeyGenMessage::PhaseFiveMsg(msg) => {
                self.msgs.phase_five_msgs.insert(index, msg.clone());
                if self.msgs.phase_five_msgs.len() == self.params.share_count {
                    self.phase_six_verify_dlog_proof_msg().unwrap();
                    return SendingMessages::KeyGenSuccess;
                }
            }
        }

        SendingMessages::EmptyMsg
    }
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

impl KeyGenMsgs {
    pub fn new() -> Self {
        Self {
            phase_two_msgs: HashMap::new(),
            phase_three_msgs: HashMap::new(),
            phase_four_msgs: HashMap::new(),
            phase_five_msgs: HashMap::new(),
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
            big_omega_vec: Vec::new(),
            k: FE::zero(),            // Init k, generate later.
            gamma: FE::zero(),        // Init gamma, generate later.
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

    pub fn init(
        party_index: usize,
        params: Parameters,
        clsk: CLSK,
        vss_scheme_vec: &Vec<VerifiableSS>,
        subset: &[usize],
        share_public_key: &Vec<GE>,
        x: &FE,
        party_num: usize,
        public_signing_key: GE,
        message: FE,
    ) -> Result<Self, ProofError> {
        assert!(party_num > params.threshold);
        assert_eq!(vss_scheme_vec.len(), params.share_count);
        assert_eq!(share_public_key.len(), params.share_count);

        let lamda = vss_scheme_vec[party_index].map_share_to_new_params(party_index, subset);
        let omega = lamda * x;
        let mut big_omega_map = HashMap::new();
        let big_omega_vec = subset
            .iter()
            .filter_map(|&i| {
                if i != party_index {
                    let ret =
                        share_public_key[i] * vss_scheme_vec[i].map_share_to_new_params(i, subset);
                    big_omega_map.insert(i, ret.clone());
                    Some(ret)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(Self {
            party_index,
            party_num,
            params,
            public_signing_key,
            message,
            clsk,
            omega,
            big_omega_map,
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
            beta_map: HashMap::new(),
            v_map: HashMap::new(),
            msgs: SignMsgs::new(),
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
        &mut self,
        group: &CLGroup,
        sign_phase_one_msg_vec: &Vec<SignPhaseOneMsg>,
    ) -> Vec<SignPhaseTwoMsg> {
        assert_eq!(sign_phase_one_msg_vec.len(), self.party_num);
        let mut msgs: Vec<SignPhaseTwoMsg> = Vec::new();
        let zero = FE::zero();
        for (i, msg) in sign_phase_one_msg_vec.iter().enumerate() {
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
            let k_mul_t = self.k * msg_vec[i].t_p;
            let alpha = decrypt(&group, &sk, &msg_vec[i].homocipher).sub(&k_mul_t.get_element());
            delta = delta + alpha + self.beta_vec[i];

            // Compute sigma
            let k_mul_t_plus = self.k * msg_vec[i].t_p_plus;
            let miu =
                decrypt(&group, &sk, &msg_vec[i].homocipher_plus).sub(&k_mul_t_plus.get_element());
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

    pub fn init_msg(
        &mut self,
        party_index: usize,
        params: Parameters,
        clsk: CLSK,
        vss_scheme_vec: &Vec<VerifiableSS>,
        subset: &[usize],
        share_public_key: &Vec<GE>,
        x: &FE,
        party_num: usize,
        public_signing_key: GE,
        message: FE,
    ) {
        assert!(party_num > params.threshold);
        assert_eq!(vss_scheme_vec.len(), params.share_count);
        assert_eq!(share_public_key.len(), params.share_count);

        let lamda = vss_scheme_vec[party_index].map_share_to_new_params(party_index, subset);
        let omega = lamda * x;
        let mut big_omega_map = HashMap::new();
        let _big_omega_vec = subset
            .iter()
            .filter_map(|&i| {
                if i != party_index {
                    let ret =
                        share_public_key[i] * vss_scheme_vec[i].map_share_to_new_params(i, subset);
                    big_omega_map.insert(i, ret.clone());
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

    pub fn phase_two_decrypt_and_verify_msg(&mut self, group: &CLGroup) -> SignPhaseThreeMsg {
        assert_eq!(self.msgs.phase_two_msgs.len(), self.party_num - 1);
        assert_eq!(self.big_omega_map.len(), self.party_num - 1);

        let mut delta = self.k * self.gamma;
        self.sigma = self.k * self.omega;
        for (index, msg) in self.msgs.phase_two_msgs.iter() {
            // Compute delta
            let k_mul_t = self.k * msg.t_p;
            let alpha = decrypt(&group, &self.clsk, &msg.homocipher).sub(&k_mul_t.get_element());
            let beta = self.beta_map.get(index).unwrap();
            delta = delta + alpha + beta;

            // Compute sigma
            let k_mul_t_plus = self.k * msg.t_p_plus;
            let miu =
                decrypt(&group, &self.clsk, &msg.homocipher_plus).sub(&k_mul_t_plus.get_element());
            let v = self.v_map.get(index).unwrap();
            self.sigma = self.sigma + miu + v;

            // Check kW = uP + B
            let big_omega = self.big_omega_map.get(index).unwrap();
            let k_omega = big_omega * &self.k;
            let base: GE = ECPoint::generator();
            let up_plus_b = base * miu + msg.b;
            assert_eq!(k_omega, up_plus_b);
        }

        SignPhaseThreeMsg { delta }
    }

    pub fn phase_two_compute_delta_sum_msg(&mut self) {
        assert_eq!(self.msgs.phase_three_msgs.len(), self.party_num);

        self.delta_sum = self
            .msgs
            .phase_three_msgs
            .iter()
            .fold(FE::zero(), |acc, (_i, v)| acc + v.delta);
    }

    pub fn phase_four_verify_dl_com_msg(&mut self) -> Result<(), ProofError> {
        assert_eq!(self.msgs.phase_one_msgs.len(), self.party_num);
        assert_eq!(self.msgs.phase_four_msgs.len(), self.party_num);

        for (index, msg) in self.msgs.phase_four_msgs.iter() {
            let msg_one = self.msgs.phase_one_msgs.get(index).unwrap();
            DlogCommitment::verify_dlog(&msg_one.commitment, &msg.open)?;
        }

        let r = self
            .msgs
            .phase_four_msgs
            .iter()
            .fold(GE::generator(), |acc, (_i, v)| acc + v.open.public_share)
            .sub_point(&GE::generator().get_element());

        self.r_point = r * self.delta_sum.invert();
        self.r_x = ECScalar::from(&self.r_point.x_coor().unwrap().mod_floor(&FE::q()));
        Ok(())
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

    pub fn phase_five_step_three_verify_com_and_zk_msg(
        &mut self,
    ) -> Result<SignPhaseFiveStepFourMsg, ProofError> {
        assert_eq!(self.msgs.phase_five_step_one_msgs.len(), self.party_num);
        assert_eq!(self.msgs.phase_five_step_two_msgs.len(), self.party_num);

        let base: GE = ECPoint::generator();

        let my_msg_two = self
            .msgs
            .phase_five_step_two_msgs
            .get(&self.party_index)
            .unwrap();
        let mut v_sum = my_msg_two.v_i.clone();
        let mut a_sum = my_msg_two.a_i.clone();

        for (index, msg_one) in self.msgs.phase_five_step_one_msgs.iter() {
            // Skip my own check
            if *index == self.party_index {
                continue;
            }

            let msg_two = self.msgs.phase_five_step_two_msgs.get(index).unwrap();

            // Verify commitment
            let input_hash =
                HSha256::create_hash_from_ge(&[&msg_two.v_i, &msg_two.a_i, &msg_two.b_i])
                    .to_big_int();

            if HashCommitment::create_commitment_with_user_defined_randomness(
                &input_hash,
                &msg_two.blind,
            ) != msg_one.commitment
            {
                return Err(ProofError);
            }

            // Verify zk proof
            let delta = HomoElGamalStatement {
                G: msg_two.a_i,
                H: self.r_point,
                Y: base,
                D: msg_two.v_i,
                E: msg_two.b_i,
            };

            msg_two.proof.verify(&delta).unwrap();
            DLogProof::verify(&msg_two.dl_proof).unwrap();

            v_sum = v_sum + msg_two.v_i;
            a_sum = a_sum + msg_two.a_i;
        }

        // Compute V = -mP -rQ + sum (vi)
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

        Ok(msg_step_four)
    }

    pub fn phase_five_step_six_verify_com_and_check_sum_a_t_msg(&self) -> Result<(), ProofError> {
        assert_eq!(self.msgs.phase_five_step_four_msgs.len(), self.party_num);
        assert_eq!(self.msgs.phase_five_step_five_msgs.len(), self.party_num);
        for (index, msg_four) in self.msgs.phase_five_step_four_msgs.iter() {
            let msg_five = self.msgs.phase_five_step_five_msgs.get(index).unwrap();
            let input_hash =
                HSha256::create_hash_from_ge(&[&msg_five.u_i, &msg_five.t_i]).to_big_int();
            if HashCommitment::create_commitment_with_user_defined_randomness(
                &input_hash,
                &msg_five.blind,
            ) != msg_four.commitment
            {
                return Err(ProofError);
            }
        }

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
                    let sending_msg = self.phase_two_generate_homo_cipher_msg(group);
                    return SendingMessages::P2pMessage(sending_msg);
                }
            }
            MultiSignMessage::PhaseTwoMsg(msg) => {
                self.msgs.phase_two_msgs.insert(index, msg.clone());
                if self.msgs.phase_two_msgs.len() == (self.party_num - 1) {
                    let msg_three = self.phase_two_decrypt_and_verify_msg(group);
                    // FIXME: send to myself
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
                self.msgs.phase_four_msgs.insert(index, msg.clone());
                if self.msgs.phase_four_msgs.len() == self.party_num {
                    self.phase_four_verify_dl_com_msg().unwrap();
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
                self.msgs
                    .phase_five_step_two_msgs
                    .insert(index, msg.clone());
                if self.msgs.phase_five_step_two_msgs.len() == self.party_num {
                    let msg_five_four = self.phase_five_step_three_verify_com_and_zk_msg().unwrap();
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
                self.msgs
                    .phase_five_step_five_msgs
                    .insert(index, msg.clone());
                if self.msgs.phase_five_step_five_msgs.len() == self.party_num {
                    self.phase_five_step_six_verify_com_and_check_sum_a_t_msg()
                        .unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utilities::signature::Signature;
    use class_group::primitives::cl_dl_public_setup::CLGroup;

    fn keygen_t_n_parties(group: &CLGroup, params: &Parameters) -> Vec<KeyGen> {
        let n = params.share_count;
        let t = params.threshold;

        // Key Gen Phase 1
        let mut key_gen_vec = (0..n)
            .map(|i| KeyGen::phase_one_init(group, i, params.clone()))
            .collect::<Vec<KeyGen>>();

        // Key Gen Phase 2
        let dl_com_vec = key_gen_vec
            .iter()
            .map(|key_gen| key_gen.phase_two_generate_dl_com())
            .collect::<Vec<_>>();

        let q_vec = dl_com_vec
            .iter()
            .map(|k| k.get_public_share())
            .collect::<Vec<_>>();

        // Key Gen Phase 3
        let (_, received_dl_com) = dl_com_vec.split_at(1);
        key_gen_vec[0]
            .phase_three_verify_dl_com_and_generate_signing_key(&received_dl_com.to_vec())
            .unwrap();

        // Assign public_signing_key
        for i in 1..n {
            key_gen_vec[i].public_signing_key = key_gen_vec[0].public_signing_key;
        }

        // Key Gen Phase 4
        let vss_result = key_gen_vec
            .iter()
            .map(|k| k.phase_four_generate_vss())
            .collect::<Vec<_>>();

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

        // Key Gen Phase 5
        let mut dlog_proof_vec = Vec::new();
        for i in 0..n {
            let dlog_proof = key_gen_vec[i]
                .phase_five_verify_vss_and_generate_pok_dlog(
                    &q_vec,
                    &party_shares[i],
                    &vss_scheme_vec,
                )
                .expect("invalid vss");
            dlog_proof_vec.push(dlog_proof);
        }

        // Key Gen Phase 6
        for i in 0..n {
            key_gen_vec[i]
                .phase_six_verify_dlog_proof(&dlog_proof_vec)
                .unwrap();
        }

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

        key_gen_vec
    }

    fn test_sign(group: &CLGroup, params: &Parameters, key_gen_vec: &Vec<KeyGen>) {
        // Sign Init
        let party_num = key_gen_vec.len();
        let subset = (0..party_num)
            .map(|i| key_gen_vec[i].party_index)
            .collect::<Vec<_>>();

        let clsk = CLSK::from(BigInt::zero());
        let mut sign_vec = (0..party_num)
            .map(|i| {
                SignPhase::init(
                    key_gen_vec[i].party_index,
                    params.clone(),
                    clsk.clone(),
                    &key_gen_vec[i].vss_scheme_vec,
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

        // Sign phase 1
        let phase_one_result_vec = (0..party_num)
            .map(|i| {
                sign_vec[i].phase_one_generate_promise_sigma_and_com(
                    group,
                    &key_gen_vec[i].cl_keypair,
                    &key_gen_vec[i].ec_keypair,
                )
            })
            .collect::<Vec<_>>();
        let phase_one_msg_vec = (0..party_num)
            .map(|i| phase_one_result_vec[i].0.clone())
            .collect::<Vec<_>>();

        // Sign phase 2
        let phase_two_result_vec = (0..party_num)
            .map(|i| sign_vec[i].phase_two_generate_homo_cipher(group, &phase_one_msg_vec))
            .collect::<Vec<_>>();

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
                group,
                key_gen_vec[index].cl_keypair.get_secret_key(),
                &phase_two_msg_vec,
            );
            phase_three_msg_vec.push(msg);
        }

        // Sign phase 3
        for i in 0..sign_vec.len() {
            sign_vec[i].phase_two_compute_delta_sum(&phase_three_msg_vec);
        }

        // Sign phase 4
        let message: FE = ECScalar::new_random();
        let phase_four_msg_vec = (0..party_num)
            .map(|i| phase_one_result_vec[i].1.clone())
            .collect::<Vec<_>>();

        for i in 0..sign_vec.len() {
            sign_vec[i]
                .phase_four_verify_dl_com(&phase_one_msg_vec, &phase_four_msg_vec)
                .unwrap();
        }

        // Sign phase 5
        let mut phase_five_step_one_msg_vec: Vec<SignPhaseFiveStepOneMsg> =
            Vec::with_capacity(party_num);
        let mut phase_five_step_two_msg_vec: Vec<SignPhaseFiveStepTwoMsg> =
            Vec::with_capacity(party_num);
        let mut phase_five_step_seven_msg_vec: Vec<SignPhaseFiveStepSevenMsg> =
            Vec::with_capacity(party_num);
        for i in 0..party_num {
            let ret = sign_vec[i].phase_five_step_onetwo_generate_com_and_zk(&message);
            phase_five_step_one_msg_vec.push(ret.0);
            phase_five_step_two_msg_vec.push(ret.1);
            phase_five_step_seven_msg_vec.push(ret.2);
        }

        let mut phase_five_step_four_msg_vec: Vec<SignPhaseFiveStepFourMsg> =
            Vec::with_capacity(party_num);
        let mut phase_five_step_five_msg_vec: Vec<SignPhaseFiveStepFiveMsg> =
            Vec::with_capacity(party_num);
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

        SignPhase::phase_five_step_six_verify_com_and_check_sum_a_t(
            &phase_five_step_four_msg_vec,
            &phase_five_step_five_msg_vec,
        )
        .unwrap();

        let sig =
            sign_vec[0].phase_five_step_eight_generate_signature(&phase_five_step_seven_msg_vec);

        // Verify Signature
        Signature::verify(&sig, &key_gen_vec[0].public_signing_key, &message).unwrap();
    }

    #[test]
    fn test_multi_party() {
        let seed: BigInt = str::parse(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();
        let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

        let params = Parameters {
            threshold: 2,
            share_count: 3,
        };

        let key_gen_vec = keygen_t_n_parties(&group, &params);

        test_sign(&group, &params, &key_gen_vec);
    }
}
