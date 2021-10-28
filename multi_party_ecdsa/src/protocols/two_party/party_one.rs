use crate::communication::receiving_messages::ReceivingMessages;
use std::cmp;

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::secp256_k1::GE;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};

use crate::utilities::class::update_class_group_by_p;
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::promise_sigma::*;
use class_group::primitives::cl_dl_public_setup::SK;
use class_group::primitives::cl_dl_public_setup::{
    decrypt, CLGroup, Ciphertext as CLCiphertext, PK,
};
use class_group::BinaryQF;
use crate::protocols::two_party::message::{PartyOneMsg, PartyTwoMsg};
use std::fs;
use std::path::Path;
use crate::communication::sending_messages::SendingMessages;

//****************** Begin: Party One structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenInit {
    pub cl_group: CLGroup,
    pub keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub h_caret: PK,
    pub round_one_msg: DLCommitments,
    pub round_two_msg: CommWitness,
    pub public_signing_key: GE,
    pub promise_state: PromiseState,
    pub promise_proof: PromiseProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhase {
    pub cl_group: CLGroup,
    pub keypair: EcKeyPair,
    pub round_one_msg: DLCommitments,
    pub round_two_msg: CommWitness,
    pub received_msg: DLogProof<GE>,
    pub message: FE,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signature {
    pub s: FE,
    pub r: FE,
}

impl KeyGenInit {
    pub fn new(group: &CLGroup) -> Self {
        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);

        // Generate cl keypair
        let mut cl_keypair = ClKeyPair::new(&group);
        let h_caret = cl_keypair.get_public_key().clone();
        cl_keypair.update_pk_exp_p();

        let new_class_group = update_class_group_by_p(group);

        // Precomputation: promise proof
        let cipher = PromiseCipher::encrypt(
            &new_class_group,
            cl_keypair.get_public_key(),
            keypair.get_secret_key(),
        );

        let promise_state = PromiseState {
            cipher: cipher.0,
            cl_pub_key: cl_keypair.cl_pub_key.clone(),
        };
        let promise_wit = PromiseWit {
            m: keypair.get_secret_key().clone(),
            r: cipher.1,
        };
        let promise_proof = PromiseProof::prove(&new_class_group, &promise_state, &promise_wit);

        Self {
            public_signing_key: ECPoint::generator(), // Compute later
            keypair,
            round_one_msg: dl_com_zk.commitments,
            round_two_msg: dl_com_zk.witness,
            cl_keypair,
            h_caret,
            promise_state,
            promise_proof,
            cl_group: new_class_group,
        }
    }

    pub fn get_class_group_pk(&self) -> (PK, PK, BinaryQF) {
        (
            self.h_caret.clone(),
            self.cl_keypair.get_public_key().clone(),
            self.cl_group.gq.clone(),
        )
    }

    // TBD: remove return value
    pub fn verify_and_get_next_msg(
        &self,
        dl_proof: &DLogProof<GE>,
    ) -> Result<CommWitness, MulEcdsaError> {
        // TBD: handle the error
        DLogProof::verify(dl_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        Ok(self.round_two_msg.clone())
    }

    // TBD: remove return value
    pub fn compute_public_key(&mut self, received_r_2: &GE) -> GE {
        self.public_signing_key = received_r_2 * self.keypair.get_secret_key();
        self.public_signing_key
    }

    pub fn get_promise_proof(&self) -> (PromiseState, PromiseProof) {
        (self.promise_state.clone(), self.promise_proof.clone())
    }

    pub fn msg_handler_keygen(&mut self, index: usize, msg_received: &PartyTwoMsg) -> SendingMessages{
        match msg_received {
            PartyTwoMsg::KegGenBegin => {
                if index == 0 {
                    // Party one time begin
                    let msg_send: ReceivingMessages = ReceivingMessages::TwoKeyGenMessagePartyOne(PartyOneMsg::KeyGenPartyOneRoundOneMsg(
                        self.round_one_msg.clone(),
                    ));
                    let msg_bytes: Vec<u8> = bincode::serialize(&msg_send).unwrap();
                    return SendingMessages::BroadcastMessage(msg_bytes);
                } else {
                    println!("Please use index 0 party begin the keygen...");
                    return SendingMessages::EmptyMsg;
                }
            }
            PartyTwoMsg::KenGenPartyTwoRoundOneMsg(msg) => {
                println!("\n=>    KeyGen: Receiving RoundOneMsg from index 1");
                let com_open = self.verify_and_get_next_msg(&msg).unwrap();
                self.compute_public_key(&msg.pk);

                // Get pk and pk'
                let (h_caret, h, gp) = self.get_class_group_pk();

                let msg_send = ReceivingMessages::TwoKeyGenMessagePartyOne(PartyOneMsg::KeyGenPartyOneRoundTwoMsg(
                    com_open,
                    h_caret,
                    h,
                    gp,
                    self.promise_state.clone(),
                    self.promise_proof.clone(),
                ));
                let msg_bytes = bincode::serialize(&msg_send).unwrap();

                // Party one save keygen to file
                let file_name =
                    "./keygen_result".to_string() + &index.to_string() + ".json";
                let keygen_path = Path::new(&file_name);
                let keygen_json = serde_json::to_string(&(
                    self.cl_keypair.get_secret_key().clone(),
                    self.keypair.get_secret_key().clone(),
                    self.public_signing_key,
                ))
                .unwrap();
                fs::write(keygen_path, keygen_json).expect("Unable to save !");
                println!("##    KeyGen finish!");
                return SendingMessages::BroadcastMessage(msg_bytes);
            }
            _ => {return SendingMessages::EmptyMsg}
        }
    }
}

impl SignPhase {
    pub fn new(cl_group: CLGroup, message_str: &String) -> Self {
        let message_bigint = BigInt::from_hex(message_str).unwrap();
        let message: FE = ECScalar::from(&message_bigint);

        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);
        let received_msg = DLogProof {
            pk: GE::generator(),
            pk_t_rand_commitment: GE::generator(),
            challenge_response: FE::zero(),
        };

        Self {
            cl_group,
            keypair,
            round_one_msg: dl_com_zk.commitments,
            round_two_msg: dl_com_zk.witness,
            received_msg,
            message,
        }
    }

    pub fn set_received_msg(&mut self, msg: DLogProof<GE>) {
        self.received_msg = msg;
    }

    pub fn verify_and_get_next_msg(
        &self,
        dl_proof: &DLogProof<GE>,
    ) -> Result<CommWitness, MulEcdsaError> {
        // TBD: handle the error
        DLogProof::verify(dl_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        Ok(self.round_two_msg.clone())
    }

    pub fn compute_public_share_key(&self, received_r_2: &GE) -> GE {
        received_r_2 * self.keypair.get_secret_key()
    }

    pub fn sign(
        &self,
        cl_sk: &SK,
        partial_sig_c3: &CLCiphertext,
        ephemeral_public_share: &GE,
        secret_key: &FE,
        t_p: &FE,
        public_signing_key: &GE,
        message: FE,
    ) -> Result<Signature, MulEcdsaError> {
        let q = FE::q();
        let r_x: FE = ECScalar::from(
            &ephemeral_public_share
                .x_coor()
                .ok_or(MulEcdsaError::XcoorNone)?
                .mod_floor(&q),
        );
        let k1_inv = self.keypair.get_secret_key().invert();
        let x1_mul_tp = *secret_key * t_p;
        let s_tag = decrypt(&self.cl_group, cl_sk, &partial_sig_c3).sub(&x1_mul_tp.get_element());
        let s_tag_tag = k1_inv * s_tag;
        let s = cmp::min(s_tag_tag.to_big_int(), q - s_tag_tag.to_big_int());
        let signature = Signature {
            s: ECScalar::from(&s),
            r: r_x,
        };
        SignPhase::verify(&signature, public_signing_key, &message).unwrap();
        Ok(signature)
    }

    pub fn verify(signature: &Signature, pubkey: &GE, message: &FE) -> Result<(), MulEcdsaError> {
        let q = FE::q();

        let s_inv_fe = signature.s.invert();
        let u1 = GE::generator() * (*message * s_inv_fe);
        let u2 = *pubkey * (signature.r * s_inv_fe);

        // second condition is against malleability
        let u1_plus_u2 = (u1 + u2)
            .x_coor()
            .ok_or(MulEcdsaError::XcoorNone)?
            .mod_floor(&q);

        if signature.r.to_big_int() == u1_plus_u2
            && signature.s.to_big_int() < FE::q() - signature.s.to_big_int()
        {
            Ok(())
        } else {
            return Err(MulEcdsaError::VrfyTwoECDSAFailed);
        }
    }

    
    pub fn msg_handler_sign(&mut self, index: usize, msg_received: &PartyTwoMsg) -> SendingMessages{
        match msg_received {   
            PartyTwoMsg::SignBegin => {
                if index == 0 {
                    let msg_send = ReceivingMessages::TwoSignMessagePartyOne(PartyOneMsg::SignPartyOneRoundOneMsg(
                        self.round_one_msg.clone(),
                    ));
                    let msg_bytes = bincode::serialize(&msg_send).unwrap();
                    return SendingMessages::BroadcastMessage(msg_bytes);
                } else {
                    println!("Please use index 0 party begin the sign...");
                    return SendingMessages::EmptyMsg;
                }
            }
            PartyTwoMsg::SignPartyTwoRoundOneMsg(msg) => {
                println!("\n=>    Sign: Receiving RoundOneMsg from index 1");

                let witness = self.verify_and_get_next_msg(&msg).unwrap();
                self.set_received_msg((*msg).clone());

                let msg_send = ReceivingMessages::TwoSignMessagePartyOne(PartyOneMsg::SignPartyOneRoundTwoMsg(witness));
                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                return SendingMessages::BroadcastMessage(msg_bytes);
            }
            PartyTwoMsg::SignPartyTwoRoundTwoMsg(cipher, t_p) => {
                println!("\n=>    Sign: Receiving RoundTwoMsg from index 1");

                // read key file
                let file_name =
                    "./keygen_result".to_string() + &index.to_string() + ".json";
                let data = fs::read_to_string(file_name)
                    .expect("Unable to load keys, did you run keygen first? ");
                let (cl_sk, secret_key, public_signing_key): (SK, FE, GE) = serde_json::from_str(&data).unwrap();

                let ephemeral_public_share = self
                    .compute_public_share_key(&self.received_msg.pk);
                let signature = self.sign(
                    &cl_sk,
                    &cipher,
                    &ephemeral_public_share,
                    &secret_key,
                    &t_p,
                    &public_signing_key,
                    self.message,
                );
                // Party one time end
                println!("##    Sign finish! \n signature: {:?}", signature);
                return SendingMessages::EmptyMsg;
            }
            _ => {
                println!("Unsupported parse Received MessageType");
                return SendingMessages::EmptyMsg;
            }
        }
    }
}
