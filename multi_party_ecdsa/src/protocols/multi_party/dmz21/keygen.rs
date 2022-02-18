use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::dmz21::message::*;
use crate::utilities::class_group::*;
use crate::utilities::class_group::{GROUP_128, GROUP_UPDATE_128};
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::MulEcdsaError;
use classgroup::gmp_classgroup::*;
use classgroup::ClassGroup;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

#[derive(Clone, Debug)]
pub struct KeyGenMsgs {
    pub phase_one_two_msgs: HashMap<usize, KeyGenPhaseOneTwoMsg>,
    pub phase_three_msgs: HashMap<usize, KeyGenPhaseThreeMsg>,
    pub phase_four_vss_sending_msgs: HashMap<usize, Vec<u8>>,
    pub phase_four_msgs: HashMap<usize, KeyGenPhaseFourMsg>,
    pub phase_five_msgs: HashMap<usize, KeyGenPhaseFiveMsg>,
}

#[derive(Clone, Debug)]
pub struct KeyGenPhase {
    pub party_index: usize,
    pub params: Parameters,
    pub ec_keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub h_caret: PK,
    pub private_signing_key: EcKeyPair,       // (u_i, u_iP)
    pub public_signing_key: GE,               // Q
    pub share_private_key: FE,                // x_i
    pub share_public_key: HashMap<usize, GE>, // X_i // TBD: use vec instead of hashmap
    pub msgs: KeyGenMsgs,
    pub need_refresh: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KenGenResult {
    pub pk: GE,
    pub cl_sk: SK,
    pub ec_sk: FE,
    pub share_sk: FE,
    pub share_pks: HashMap<usize, GE>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub pk: GE,
    pub share_pks: HashMap<usize, GE>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateKey {
    pub cl_sk: SK,
    pub ec_sk: FE,
    pub share_sk: FE,
}

impl KeyGenMsgs {
    pub fn new() -> Self {
        Self {
            phase_one_two_msgs: HashMap::new(),
            phase_three_msgs: HashMap::new(),
            phase_four_vss_sending_msgs: HashMap::new(),
            phase_four_msgs: HashMap::new(),
            phase_five_msgs: HashMap::new(),
        }
    }

    pub fn clean(&mut self) {
        self.phase_one_two_msgs.clear();
        self.phase_three_msgs.clear();
        self.phase_four_vss_sending_msgs.clear();
        self.phase_four_msgs.clear();
        self.phase_five_msgs.clear();
    }
}

impl KenGenResult {
    pub fn from_json_string(json_string: &String) -> Result<Self, MulEcdsaError> {
        let ret = serde_json::from_str(json_string).map_err(|_| MulEcdsaError::FromStringFailed)?;
        Ok(ret)
    }
}

impl KeyGenPhase {
    pub fn new(party_index: usize, params: Parameters) -> Result<Self, MulEcdsaError> {
        // Generate cl keypair
        let mut cl_keypair = ClKeyPair::new(&GROUP_128);
        let h_caret = cl_keypair.get_public_key().clone();
        cl_keypair.update_pk_exp_p();

        // Generate elgamal keypair
        let ec_keypair = EcKeyPair::new();

        // Generate signing key pair
        let private_signing_key = EcKeyPair::new();

        // Init public key, compute later
        let public_signing_key = private_signing_key.get_public_key().clone();

        let mut msgs = KeyGenMsgs::new();

        // Generate dl com
        let dlog_com = DlogCommitment::new(&public_signing_key);

        // Generate phase one and two msg
        let msg_1_2 = KeyGenPhaseOneTwoMsg {
            h_caret: h_caret.clone(),
            h: cl_keypair.get_public_key().clone(),
            ec_pk: ec_keypair.get_public_key().clone(),
            gp: GROUP_UPDATE_128.gq.clone(),
            commitment: dlog_com.commitment,
        };
        msgs.phase_one_two_msgs.insert(party_index, msg_1_2);

        //  Generate phase three msg
        let msg_3 = KeyGenPhaseThreeMsg {
            open: dlog_com.open,
        };
        msgs.phase_three_msgs.insert(party_index, msg_3);

        // Generate phase four msg, vss
        let share_private_key = KeyGenPhase::phase_four_generate_vss(
            &mut msgs,
            party_index,
            params.threshold,
            params.share_count,
            private_signing_key.get_secret_key(),
        )?;

        Ok(Self {
            party_index,
            params,
            ec_keypair,
            cl_keypair,
            h_caret,
            private_signing_key,
            public_signing_key,
            share_private_key, // Init share private key, compute later.
            share_public_key: HashMap::new(),
            msgs,
            need_refresh: false,
        })
    }

    pub fn refresh(&mut self) -> Result<(), MulEcdsaError> {
        // Refresh cl keypair
        let mut cl_keypair = ClKeyPair::new(&GROUP_128);
        self.h_caret = cl_keypair.get_public_key().clone();
        cl_keypair.update_pk_exp_p();
        self.cl_keypair = cl_keypair;

        // Refresh elgamal keypair
        self.ec_keypair = EcKeyPair::new();

        // Refresh signing key pair
        self.private_signing_key = EcKeyPair::new();
        self.public_signing_key = self.private_signing_key.get_public_key().clone();

        self.msgs.clean();

        // Refresh dl com
        let dlog_com = DlogCommitment::new(&self.public_signing_key);

        // Refresh phase one and two msg
        let msg_1_2 = KeyGenPhaseOneTwoMsg {
            h_caret: self.h_caret.clone(),
            h: self.cl_keypair.get_public_key().clone(),
            ec_pk: self.ec_keypair.get_public_key().clone(),
            gp: GROUP_UPDATE_128.gq.clone(),
            commitment: dlog_com.commitment,
        };
        self.msgs
            .phase_one_two_msgs
            .insert(self.party_index, msg_1_2);

        //  Refresh phase three msg
        let msg_3 = KeyGenPhaseThreeMsg {
            open: dlog_com.open,
        };
        self.msgs.phase_three_msgs.insert(self.party_index, msg_3);

        // Refresh phase four msg, vss
        let share_private_key = KeyGenPhase::phase_four_generate_vss(
            &mut self.msgs,
            self.party_index,
            self.params.threshold,
            self.params.share_count,
            self.private_signing_key.get_secret_key(),
        )?;

        self.share_private_key = share_private_key;
        self.need_refresh = false;
        Ok(())
    }

    fn get_phase_one_two_msg(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let msg = self
            .msgs
            .phase_one_two_msgs
            .get(&self.party_index)
            .ok_or(MulEcdsaError::GetIndexFailed)?;
        let msg_send =
            ReceivingMessages::MultiKeyGenMessage(MultiKeyGenMessage::PhaseOneTwoMsg(msg.clone()));
        let result = bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
        Ok(result)
    }

    fn verify_phase_one_msg(
        &self,
        h_caret: &PK,
        h: &PK,
        gp: &GmpClassGroup,
    ) -> Result<(), MulEcdsaError> {
        let mut h_ret = h_caret.0.clone();
        h_ret.pow(q());
        if h_ret != h.0 || *gp != GROUP_UPDATE_128.gq {
            return Err(MulEcdsaError::VrfySignPhaseOneMsgFailed);
        }
        Ok(())
    }

    fn handle_phase_three_msg(
        &mut self,
        index: usize,
        msg: &KeyGenPhaseThreeMsg,
    ) -> Result<(), MulEcdsaError> {
        let commitment = self
            .msgs
            .phase_one_two_msgs
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?
            .commitment
            .clone();
        let open = msg.open.clone();

        let dlog_com = DlogCommitment { commitment, open };
        dlog_com.verify()?;

        self.public_signing_key = self.public_signing_key + dlog_com.get_public_share();

        Ok(())
    }

    fn phase_four_generate_vss(
        msgs: &mut KeyGenMsgs,
        party_index: usize,
        threshold: usize,
        share_count: usize,
        private_signing_key: &FE,
    ) -> Result<FE, MulEcdsaError> {
        let (vss_scheme, secret_shares) =
            VerifiableSS::share(threshold, share_count, private_signing_key);

        let mut share_private_key = FE::zero();
        for i in 0..share_count {
            let msg = KeyGenPhaseFourMsg {
                vss_scheme: vss_scheme.clone(),
                secret_share: secret_shares[i],
            };

            if i == party_index {
                // Handle my onw msg_four
                share_private_key = msg.secret_share;
                msgs.phase_four_msgs.insert(i, msg);
            } else {
                let phase_four_msg =
                    ReceivingMessages::MultiKeyGenMessage(MultiKeyGenMessage::PhaseFourMsg(msg));
                let msg_bytes = bincode::serialize(&phase_four_msg)
                    .map_err(|_| MulEcdsaError::SerializeFailed)?;
                msgs.phase_four_vss_sending_msgs.insert(i, msg_bytes);
            }
        }

        Ok(share_private_key)
    }

    fn get_phase_four_msg(&self) -> HashMap<usize, Vec<u8>> {
        self.msgs.phase_four_vss_sending_msgs.clone()
    }

    fn handle_phase_four_msg(
        &mut self,
        index: usize,
        msg: &KeyGenPhaseFourMsg,
    ) -> Result<(), MulEcdsaError> {
        // Check VSS
        let q = self
            .msgs
            .phase_three_msgs
            .get(&index)
            .ok_or(MulEcdsaError::GetIndexFailed)?
            .open
            .public_share;

        if !(msg
            .vss_scheme
            .validate_share(&msg.secret_share, self.party_index + 1)
            .is_ok()
            && msg.vss_scheme.commitments[0] == q)
        {
            return Err(MulEcdsaError::VrfyVSSFailed);
        }

        // Compute share_private_key(x_i)
        self.share_private_key = self.share_private_key + msg.secret_share;

        Ok(())
    }

    fn generate_phase_five_msg(&mut self) -> KeyGenPhaseFiveMsg {
        //TBD:generalize curv
        let dl_proof = DLogProof::<GE>::prove(&self.share_private_key);
        self.share_public_key
            .insert(self.party_index, dl_proof.pk.clone());
        KeyGenPhaseFiveMsg { dl_proof }
    }

    fn handle_phase_five_msg(
        &mut self,
        index: usize,
        msg: &KeyGenPhaseFiveMsg,
    ) -> Result<(), MulEcdsaError> {
        DLogProof::verify(&msg.dl_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        self.share_public_key.insert(index, msg.dl_proof.pk);

        Ok(())
    }

    fn generate_public_result_json_string(&self) -> Result<String, MulEcdsaError> {
        let ret = PublicKey {
            pk: self.public_signing_key.clone(),
            share_pks: self.share_public_key.clone(),
        };
        let ret_string = serde_json::to_string(&ret).map_err(|_| MulEcdsaError::ToStringFailed)?;

        Ok(ret_string)
    }

    fn generate_private_result_json_string(&self) -> Result<String, MulEcdsaError> {
        let ret = PrivateKey {
            cl_sk: self.cl_keypair.cl_priv_key.clone(),
            ec_sk: self.ec_keypair.secret_share.clone(),
            share_sk: self.share_private_key.clone(),
        };
        let ret_string = serde_json::to_string(&ret).map_err(|_| MulEcdsaError::ToStringFailed)?;

        Ok(ret_string)
    }

    pub fn process_begin(&mut self) -> Result<SendingMessages, MulEcdsaError> {
        // Refresh
        if self.need_refresh {
            self.refresh()?;
        }
        let sending_msg_bytes = self.get_phase_one_two_msg()?;
        return Ok(SendingMessages::BroadcastMessage(sending_msg_bytes));
    }

    pub fn msg_handler(
        &mut self,
        index: usize,
        msg: &MultiKeyGenMessage,
    ) -> Result<SendingMessages, MulEcdsaError> {
        log::debug!("Multi Party msg_handler, from {}, msg: {:?}", index, msg);
        match msg {
            MultiKeyGenMessage::PhaseOneTwoMsg(msg) => {
                // Refresh
                if self.need_refresh {
                    self.refresh()?;
                }

                self.verify_phase_one_msg(&msg.h_caret, &msg.h, &msg.gp)?;
                self.msgs.phase_one_two_msgs.insert(index, msg.clone());
                if self.msgs.phase_one_two_msgs.len() == self.params.share_count {
                    let keygen_phase_three_msg = self
                        .msgs
                        .phase_three_msgs
                        .get(&self.party_index)
                        .ok_or(MulEcdsaError::GetIndexFailed)?;
                    let sending_msg = ReceivingMessages::MultiKeyGenMessage(
                        MultiKeyGenMessage::PhaseThreeMsg(keygen_phase_three_msg.clone()),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg)
                        .map_err(|_| MulEcdsaError::SerializeFailed)?;
                    return Ok(SendingMessages::BroadcastMessage(sending_msg_bytes));
                }
            }
            MultiKeyGenMessage::PhaseThreeMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_three_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                // Handle the msg
                self.handle_phase_three_msg(index, &msg)?;
                self.msgs.phase_three_msgs.insert(index, msg.clone());

                // Generate the next msg
                if self.msgs.phase_three_msgs.len() == self.params.share_count {
                    let sending_msg = self.get_phase_four_msg();

                    return Ok(SendingMessages::P2pMessage(sending_msg));
                }
            }
            MultiKeyGenMessage::PhaseFourMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_four_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                // Handle the msg
                self.handle_phase_four_msg(index, &msg)?;
                self.msgs.phase_four_msgs.insert(index, msg.clone());

                // Generate the next msg
                if self.msgs.phase_four_msgs.len() == self.params.share_count {
                    let msg_five = self.generate_phase_five_msg();
                    self.msgs
                        .phase_five_msgs
                        .insert(self.party_index, msg_five.clone());
                    let sending_msg = ReceivingMessages::MultiKeyGenMessage(
                        MultiKeyGenMessage::PhaseFiveMsg(msg_five),
                    );
                    let sending_msg_bytes = bincode::serialize(&sending_msg)
                        .map_err(|_| MulEcdsaError::SerializeFailed)?;
                    return Ok(SendingMessages::BroadcastMessage(sending_msg_bytes));
                }
            }
            MultiKeyGenMessage::PhaseFiveMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_five_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                // Handle the msg
                self.handle_phase_five_msg(index, &msg)?;
                self.msgs.phase_five_msgs.insert(index, msg.clone());
                if self.msgs.phase_five_msgs.len() == self.params.share_count {
                    let pub_keygen_json = self.generate_public_result_json_string()?;
                    let priv_keygen_json = self.generate_private_result_json_string()?;
                    let keygen_json = vec![pub_keygen_json, priv_keygen_json]; //vec[0] stores public_key_json, vec[1] stores private_key_json by default
                    self.need_refresh = true;
                    return Ok(SendingMessages::KeyGenSuccessWithResult(keygen_json));
                }
            }
        }

        Ok(SendingMessages::EmptyMsg)
    }
}
