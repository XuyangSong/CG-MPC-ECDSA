use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::two_party::xax21::mta::cl_based_mta::PartyTwo;
use crate::protocols::two_party::xax21::party_one::{MtaConsistencyMsg, NonceKEMsg};
use crate::protocols::two_party::message::*;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::MulEcdsaError;
use curv::arithmetic::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGen {
    pub keypair: EcKeyPair,
    pub dl_com_zk_com_rec: DLCommitments,
    pub dl_com_zk_wit_rec: Option<CommWitness>,
    pub dlog_proof: DLogProof<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenResult {
    pub keypair: EcKeyPair,
    pub public_signing_key: GE,
    pub other_public_key: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenSecRoungMsg {
    pub public_share: GE,
    pub dl_proof: DLogProof<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sign {
    pub nonce_pair: EcKeyPair,
    pub dl_com_zk_com: DLComZK,
    pub keygen_result: Option<KeyGenResult>,
    pub message: FE,
    pub reshared_secret_share: FE,
    pub r1_rec: FE,
    pub r_x: FE,
    online_offline: bool,
    pub msg_set: bool,
}

impl KeyGen {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let dlog_proof = DLogProof::<GE>::prove(&keypair.secret_share);
        Self {
            keypair,
            dl_com_zk_com_rec: DLCommitments::default(),
            dl_com_zk_wit_rec: None,
            dlog_proof,
        }
    }

    pub fn get_msg_and_generate_second_round_msg(
        &mut self,
        dl_com_zk_com_rec: &DLCommitments,
    ) -> KeyGenSecRoungMsg {
        self.dl_com_zk_com_rec = (*dl_com_zk_com_rec).clone();
        KeyGenSecRoungMsg {
            public_share: self.keypair.public_share,
            dl_proof: self.dlog_proof.clone(),
        }
    }

    pub fn verify_third_roung_msg(
        &mut self,
        dl_com_zk_wit: &CommWitness,
    ) -> Result<(), MulEcdsaError> {
        DLComZK::verify(&self.dl_com_zk_com_rec, dl_com_zk_wit)?;
        DLogProof::verify(&dl_com_zk_wit.d_log_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        self.dl_com_zk_wit_rec = Some(dl_com_zk_wit.clone());
        Ok(())
    }

    pub fn generate_key_result(&self) -> KeyGenResult {
        KeyGenResult {
            keypair: self.keypair.clone(),
            public_signing_key: self.keypair.public_share
                + self.dl_com_zk_wit_rec.clone().unwrap().public_share,
            other_public_key: self.dl_com_zk_wit_rec.clone().unwrap().public_share,
        }
    }

    pub fn msg_handler_keygen(
        &mut self,
        msg_received: &XAXPartyOneMsg,
    ) -> Result<SendingMessages, MulEcdsaError> {
        match msg_received {
            XAXPartyOneMsg::KeyGenPartyOneRoundOneMsg(msg) => {
                log::info!("KeyGen: Receiving RoundOneMsg from index 0");
                let msg_to_send = self.get_msg_and_generate_second_round_msg(msg);
                let msg_send = ReceivingMessages::XAXTwoKeyGenMessagePartyTwo(
                    XAXPartyTwoMsg::KeyGenPartyTwoRoundOneMsg(msg_to_send),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            }
            XAXPartyOneMsg::KeyGenPartyOneRoundTwoMsg(msg) => {
                self.verify_third_roung_msg(msg)?;
                let keygen_result = self.generate_key_result();
                let keygen_json = serde_json::to_string(&keygen_result)
                    .map_err(|_| MulEcdsaError::ToStringFailed)?;
                return Ok(SendingMessages::KeyGenSuccessWithResult(vec![keygen_json]));
            }
            _ => {
                return Ok(SendingMessages::EmptyMsg);
            }
        }
    }
}

impl Sign {
    pub fn new(message_str: &String, online_offline: bool) -> Result<Self, MulEcdsaError> {
        let nonce_pair = EcKeyPair::new();
        let dl_com_zk_com = DLComZK::new(&nonce_pair);
        // Process the message to sign
        let message_bigint =
            BigInt::from_hex(&message_str).map_err(|_| MulEcdsaError::FromHexFailed)?;
        let message = ECScalar::from(&message_bigint);
        let ret = Self {
            nonce_pair,
            dl_com_zk_com: dl_com_zk_com,
            keygen_result: None,
            message,
            reshared_secret_share: FE::new_random(),
            r1_rec: FE::new_random(),
            r_x: FE::new_random(),
            online_offline,
            msg_set: false,
        };
        Ok(ret)
    }

    pub fn generate_nonce_com(&self) -> DLCommitments {
        self.dl_com_zk_com.commitments.clone()
    }

    pub fn verify_generate_mta_consistency(
        &mut self,
        t_b: FE,
        mta_consis_rec: &MtaConsistencyMsg,
    ) -> Result<(), String> {
        let base: GE = ECPoint::generator();
        if base * (t_b + mta_consis_rec.cc)
            != (mta_consis_rec.reshared_public_share
                * (mta_consis_rec.r1 + self.nonce_pair.secret_share))
                .sub_point(
                    &self
                        .keygen_result
                        .as_ref()
                        .unwrap()
                        .other_public_key
                        .get_element(),
                )
        {
            return Err("Verify Mta Consistency Failed".to_string());
        }
        let reshared_secret_share = self
            .keygen_result
            .as_ref()
            .unwrap()
            .keypair
            .secret_share
            .sub(&t_b.get_element())
            .sub(&mta_consis_rec.cc.get_element());
        self.reshared_secret_share = reshared_secret_share;
        self.r1_rec = mta_consis_rec.r1;
        Ok(())
    }

    pub fn verify_send_nonce_ke_msg(
        &mut self,
        nonce_ke_rec: &NonceKEMsg,
    ) -> Result<CommWitness, String> {
        DLogProof::verify(&nonce_ke_rec.dl_proof).map_err(|_| "Verify DLog failed".to_string())?;
        let r = nonce_ke_rec.nonce_public_key * (self.r1_rec + self.nonce_pair.secret_share);
        self.r_x = ECScalar::from(&r.x_coor().ok_or("get x coor failed")?.mod_floor(&FE::q()));
        Ok(self.dl_com_zk_com.witness.clone())
    }

    pub fn online_sign(&self) -> FE {
        let s_2 = (self.r1_rec + self.nonce_pair.secret_share).invert()
            * (self.message + self.r_x * self.reshared_secret_share);
        return s_2;
    }

    pub fn set_msg(&mut self, message_str: String) -> Result<(), MulEcdsaError> {
        let message_bigint =
            BigInt::from_hex(&message_str).map_err(|_| MulEcdsaError::FromHexFailed)?;
        let message: FE = ECScalar::from(&message_bigint);
        self.message = message;
        self.msg_set = true;
        Ok(())
    }

    pub fn load_keygen_result(&mut self, keygen_json: &String) -> Result<(), MulEcdsaError> {
        // Load keygen result
        let keygen_result = KeyGenResult::from_json_string(keygen_json)?;
        self.keygen_result = Some(keygen_result);
        Ok(())
    }

    pub fn process_begin_sign(&mut self, index: usize) -> Result<SendingMessages, MulEcdsaError> {
        if index == 1 {
            let msg_send = ReceivingMessages::XAXTwoSignMessagePartyTwo(
                XAXPartyTwoMsg::SignPartyTwoRoundOneMsg(self.generate_nonce_com()),
            );
            let msg_bytes =
                bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
            return Ok(SendingMessages::BroadcastMessage(msg_bytes));
        } else {
            log::warn!("Please use index 1 party begin the sign...");
            return Ok(SendingMessages::EmptyMsg);
        }
    }

    pub fn process_begin_sign_online(
        &mut self,
        index: usize,
    ) -> Result<SendingMessages, MulEcdsaError> {
        if index == 1 {
            if self.msg_set == true {
                let s_2 = self.online_sign();
                let msg_send = ReceivingMessages::XAXTwoSignMessagePartyTwo(
                    XAXPartyTwoMsg::SignPartyTwoRoundThreeMsgOnline(s_2),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
                println!("Sign Finish!");
                log::info!("Sign Finish!");
                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            } else {
                log::error!("Please set message to sign first");
                Ok(SendingMessages::EmptyMsg)
            }
        } else {
            log::warn!("Please use index 1 party begin the sign online phase...");
            return Ok(SendingMessages::EmptyMsg);
        }
    }

    pub fn msg_handler_sign(
        &mut self,
        msg_received: &XAXPartyOneMsg,
        mta_party_two: &mut PartyTwo,
    ) -> Result<SendingMessages, MulEcdsaError> {
        match msg_received {
            XAXPartyOneMsg::MtaPartyOneRoundOneMsg(msg) => {
                log::info!("Sign: Receiving RoundOneMsg from index 0");
                let mta_second_round_msg = mta_party_two
                    .receive_and_send_msg(msg.0.clone(), msg.1.clone())
                    .unwrap();
                let msg_send = ReceivingMessages::XAXTwoSignMessagePartyTwo(
                    XAXPartyTwoMsg::MtaPartyTwoRoundOneMsg(mta_second_round_msg),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            }
            XAXPartyOneMsg::SignPartyOneRoundOneMsg(mtaconsistencymsg, noncekemsg) => {
                self.verify_generate_mta_consistency(mta_party_two.t_a, mtaconsistencymsg)
                    .unwrap();
                let party_two_nonce_ke_msg = self.verify_send_nonce_ke_msg(noncekemsg).unwrap();
                if self.online_offline {
                    let msg_send = ReceivingMessages::XAXTwoSignMessagePartyTwo(
                        XAXPartyTwoMsg::SignPartyTwoRoundTwoMsgOnline(party_two_nonce_ke_msg),
                    );
                    let msg_bytes = bincode::serialize(&msg_send)
                        .map_err(|_| MulEcdsaError::SerializeFailed)?;
                    log::info!("offline finish");
                    println!("offline finish");
                    return Ok(SendingMessages::BroadcastMessage(msg_bytes));
                } else {
                    let s_2 = self.online_sign();
                    let msg_send = ReceivingMessages::XAXTwoSignMessagePartyTwo(
                        XAXPartyTwoMsg::SignPartyTwoRoundTwoMsg(party_two_nonce_ke_msg, s_2),
                    );
                    let msg_bytes = bincode::serialize(&msg_send)
                        .map_err(|_| MulEcdsaError::SerializeFailed)?;
                    println!("Sign Finish!");
                    log::info!("Sign Finish!");
                    return Ok(SendingMessages::BroadcastMessage(msg_bytes));
                }
            }
            _ => {
                log::warn!("Unsupported parse Received MessageType");
                return Ok(SendingMessages::EmptyMsg);
            }
        }
    }
}

impl KeyGenResult {
    pub fn from_json_string(json_string: &String) -> Result<Self, MulEcdsaError> {
        let ret = serde_json::from_str(json_string).map_err(|_| MulEcdsaError::FromStringFailed)?;
        Ok(ret)
    }
}
