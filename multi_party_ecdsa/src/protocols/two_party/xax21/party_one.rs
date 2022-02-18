use crate::protocols::two_party::xax21::mta::cl_based_mta::PartyOne;
use crate::protocols::two_party::xax21::party_two::KeyGenSecRoungMsg;
use crate::protocols::two_party::message::*;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
//use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::signature::*;
//use crate::utilities::class_group::*;
use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::utilities::error::MulEcdsaError;
use curv::arithmetic::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use serde::{Deserialize, Serialize};
use std::cmp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGen {
    pub keypair: EcKeyPair,
    pub dl_com_zk_com: DLCommitments,
    pub dl_com_zk_wit: CommWitness,
    pub public_share_rec: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenResult {
    pub keypair: EcKeyPair,
    pub public_signing_key: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sign {
    pub dl_com_zk_com_rec: DLCommitments,
    pub reshared_keypair: EcKeyPair,
    pub keygen_result: Option<KeyGenResult>,
    pub nonce_pair: EcKeyPair,
    pub r1: FE,
    pub r_x: FE,
    pub message: FE,
    pub dl_proof: DLogProof<GE>,
    pub online_offline: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaConsistencyMsg {
    pub reshared_public_share: GE,
    pub r1: FE,
    pub cc: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceKEMsg {
    pub nonce_public_key: GE,
    pub dl_proof: DLogProof<GE>,
}

impl KeyGen {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);
        Self {
            keypair,
            dl_com_zk_com: dl_com_zk.commitments,
            dl_com_zk_wit: dl_com_zk.witness,
            public_share_rec: GE::random_point(),
        }
    }

    pub fn generate_first_round_msg(&self) -> DLCommitments {
        self.dl_com_zk_com.clone()
    }

    pub fn get_msg_and_generate_third_roung_msg(
        &mut self,
        received_msg: &KeyGenSecRoungMsg,
    ) -> Result<CommWitness, MulEcdsaError> {
        DLogProof::verify(&received_msg.dl_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        self.public_share_rec = received_msg.public_share;
        Ok(self.dl_com_zk_wit.clone())
    }

    pub fn generate_key_result(&self) -> KeyGenResult {
        KeyGenResult {
            keypair: self.keypair.clone(),
            public_signing_key: self.public_share_rec + self.keypair.public_share,
        }
    }

    pub fn process_begin_keygen(&mut self, index: usize) -> Result<SendingMessages, MulEcdsaError> {
        if index == 0 {
            let msg_send = ReceivingMessages::XAXTwoKeyGenMessagePartyOne(
                XAXPartyOneMsg::KeyGenPartyOneRoundOneMsg(self.generate_first_round_msg()),
            );
            let msg_bytes =
                bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
            return Ok(SendingMessages::BroadcastMessage(msg_bytes));
        } else {
            log::warn!("Please use index 0 party begin the sign...");
            return Ok(SendingMessages::EmptyMsg);
        }
    }

    pub fn msg_handler_keygen(
        &mut self,
        msg_received: &XAXPartyTwoMsg,
    ) -> Result<SendingMessages, MulEcdsaError> {
        match msg_received {
            XAXPartyTwoMsg::KeyGenPartyTwoRoundOneMsg(msg) => {
                log::info!("KeyGen: Receiving RoundOneMsg from index 1");
                let com_open = self.get_msg_and_generate_third_roung_msg(msg)?;
                let msg_send = ReceivingMessages::XAXTwoKeyGenMessagePartyOne(
                    XAXPartyOneMsg::KeyGenPartyOneRoundTwoMsg(com_open),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;

                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            }
            XAXPartyTwoMsg::KeyGenFinish => {
                log::info!("KeyGen: Receiving KeyGenFinish from index 1");
                let keygen_result = self.generate_key_result();
                let keygen_json = serde_json::to_string(&keygen_result)
                    .map_err(|_| MulEcdsaError::ToStringFailed)?;
                return Ok(SendingMessages::KeyGenSuccessWithResult(vec![keygen_json]));
            }
            _ => return Ok(SendingMessages::EmptyMsg),
        }
    }
}

impl Sign {
    pub fn new(message_str: &String, online_offline: bool) -> Result<Self, MulEcdsaError> {
        let reshared_keypair: EcKeyPair = EcKeyPair::new();
        // Process the message to sign
        let message_bigint =
            BigInt::from_hex(&message_str).map_err(|_| MulEcdsaError::FromHexFailed)?;
        let message = ECScalar::from(&message_bigint);
        let nonce_pair = EcKeyPair::new();
        let dl_proof = DLogProof::<GE>::prove(&nonce_pair.secret_share);
        let ret = Self {
            dl_com_zk_com_rec: DLCommitments::default(),
            reshared_keypair,
            keygen_result: None,
            nonce_pair,
            r1: ECScalar::new_random(),
            r_x: ECScalar::new_random(),
            message,
            dl_proof,
            online_offline,
        };
        Ok(ret)
    }

    pub fn load_keygen_result(&mut self, keygen_json: &String) -> Result<(), MulEcdsaError> {
        // Load keygen result
        let keygen_result = KeyGenResult::from_json_string(keygen_json)?;
        self.keygen_result = Some(keygen_result);
        Ok(())
    }

    pub fn get_nonce_com(&mut self, dl_com_zk_com_rec: &DLCommitments) {
        self.dl_com_zk_com_rec = (*dl_com_zk_com_rec).clone();
    }

    pub fn generate_mta_consistency(&self, t_a: FE) -> MtaConsistencyMsg {
        let cc: FE = (t_a
            + self
                .reshared_keypair
                .secret_share
                .mul(&self.r1.get_element()))
        .sub(
            &self
                .keygen_result
                .clone()
                .unwrap()
                .keypair
                .secret_share
                .get_element(),
        );
        MtaConsistencyMsg {
            reshared_public_share: self.reshared_keypair.public_share,
            r1: self.r1,
            cc,
        }
    }

    pub fn generate_nonce_ke_msg(&mut self) -> NonceKEMsg {
        NonceKEMsg {
            nonce_public_key: self.nonce_pair.public_share,
            dl_proof: self.dl_proof.clone(),
        }
    }

    pub fn verify_nonce_ke_msg(&mut self, nonce_ke_rec: &CommWitness) -> Result<(), MulEcdsaError> {
        DLComZK::verify(&self.dl_com_zk_com_rec, nonce_ke_rec)?;
        DLogProof::verify(&nonce_ke_rec.d_log_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        let base: GE = ECPoint::generator();
        let r = nonce_ke_rec.public_share * self.nonce_pair.secret_share
            + base * self.nonce_pair.secret_share * self.r1;
        self.r_x = ECScalar::from(
            &r.x_coor()
                .ok_or(MulEcdsaError::XcoorNone)?
                .mod_floor(&FE::q()),
        );
        Ok(())
    }

    pub fn online_sign(&self, s2_rec: &FE) -> Result<Signature, MulEcdsaError> {
        let s_tag = self.nonce_pair.secret_share.invert()
            * (*s2_rec + self.r_x * self.reshared_keypair.secret_share);
        let s = cmp::min(s_tag.to_big_int(), FE::q() - s_tag.to_big_int());
        let signature = Signature {
            r: self.r_x,
            s: ECScalar::from(&s),
        };
        signature.verify(
            &self.keygen_result.clone().unwrap().public_signing_key,
            &self.message,
        )?;
        return Ok(signature);
    }

    pub fn msg_handler_sign(
        &mut self,
        msg_received: &XAXPartyTwoMsg,
        mta_party_one: &mut PartyOne,
    ) -> Result<SendingMessages, MulEcdsaError> {
        //let cl_keypair = ClKeyPair::new(&GROUP_128);
        match msg_received {
            XAXPartyTwoMsg::SignPartyTwoRoundOneMsg(msg) => {
                log::info!("Sign: Receiving RoundOneMsg from index 1");
                self.get_nonce_com(msg);
                let mta_first_round_msg =
                    mta_party_one.generate_send_msg(&mta_party_one.cl_keypair.cl_pub_key);
                let msg_send = ReceivingMessages::XAXTwoSignMessagePartyOne(
                    XAXPartyOneMsg::MtaPartyOneRoundOneMsg(mta_first_round_msg),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            }
            XAXPartyTwoMsg::MtaPartyTwoRoundOneMsg(msg) => {
                mta_party_one
                    .handle_receive_msg(&mta_party_one.clone().cl_keypair.cl_priv_key, msg);
                let mta_consistency_msg = self.generate_mta_consistency(mta_party_one.t_b);
                let party_one_nonce_ke_msg = self.generate_nonce_ke_msg();
                let msg_send = ReceivingMessages::XAXTwoSignMessagePartyOne(
                    XAXPartyOneMsg::SignPartyOneRoundOneMsg(
                        mta_consistency_msg,
                        party_one_nonce_ke_msg,
                    ),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            }
            XAXPartyTwoMsg::SignPartyTwoRoundTwoMsg(noncekemsg, s_2) => {
                self.verify_nonce_ke_msg(noncekemsg).unwrap();
                let signature = self.online_sign(s_2).unwrap();
                println!("signature = {:?}", signature);
                let signature_json = serde_json::to_string(&signature)
                    .map_err(|_| MulEcdsaError::GenerateJsonStringFailed)?;
                return Ok(SendingMessages::SignSuccessWithResult(signature_json));
            }
            XAXPartyTwoMsg::SignPartyTwoRoundTwoMsgOnline(msg) => {
                self.verify_nonce_ke_msg(msg).unwrap();
                Ok(SendingMessages::EmptyMsg)
            }
            XAXPartyTwoMsg::SignPartyTwoRoundThreeMsgOnline(msg) => {
                let signature = self.online_sign(msg).unwrap();
                println!("signature = {:?}", signature);
                let signature_json = serde_json::to_string(&signature)
                    .map_err(|_| MulEcdsaError::GenerateJsonStringFailed)?;
                return Ok(SendingMessages::SignSuccessWithResult(signature_json));
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
