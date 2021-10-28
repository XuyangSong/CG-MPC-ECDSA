use crate::communication::receiving_messages::ReceivingMessages;
use crate::utilities::class::update_class_group_by_p;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::promise_sigma::{PromiseCipher, PromiseProof, PromiseState};
use class_group::primitives::cl_dl_public_setup::{
    encrypt_without_r, eval_scal, eval_sum, CLGroup, Ciphertext as CLCiphertext, PK,
};
use class_group::BinaryQF;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::secp256_k1::GE;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use crate::protocols::two_party::message::{PartyOneMsg, PartyTwoMsg};
use crate::communication::sending_messages::SendingMessages;
use std::fs;
use std::path::Path;

//****************** Begin: Party Two structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenInit {
    pub cl_group: CLGroup,
    pub keypair: EcKeyPair,
    pub msg: DLogProof<GE>,
    pub received_msg: DLCommitments,
    pub public_signing_key: GE,
}

impl KeyGenInit {
    pub fn new(group: &CLGroup) -> Self {
        let keypair = EcKeyPair::new();
        let d_log_proof = DLogProof::prove(keypair.get_secret_key());
        let new_class_group = update_class_group_by_p(group);
        Self {
            cl_group: new_class_group,
            public_signing_key: ECPoint::generator(), // Compute later
            keypair,
            msg: d_log_proof,
            received_msg: DLCommitments::default(),
        }
    }

    pub fn verify_class_group_pk(
        &self,
        h_caret: &PK,
        h: &PK,
        gp: &BinaryQF,
    ) -> Result<(), MulEcdsaError> {
        let h_ret = h_caret.0.exp(&FE::q());
        if h_ret != h.0 || *gp != self.cl_group.gq {
            return Err(MulEcdsaError::VrfyClassGroupFailed);
        }
        Ok(())
    }

    pub fn verify_received_dl_com_zk(
        commitment: &DLCommitments,
        witness: &CommWitness,
    ) -> Result<(), MulEcdsaError> {
        // TBD: handle the error
        DLComZK::verify(commitment, witness).map_err(|_| MulEcdsaError::VrfyRecvDLComZKFailed)?;

        Ok(())
    }

    pub fn verify_promise_proof(
        &self,
        state: &PromiseState,
        proof: &PromiseProof,
    ) -> Result<(), MulEcdsaError> {
        // TBD: check pk

        proof
            .verify(&self.cl_group, state)
            .map_err(|_| MulEcdsaError::VrfyPromiseFailed)?;

        Ok(())
    }

    pub fn set_dl_com(&mut self, msg: DLCommitments) {
        self.received_msg = msg;
    }

    pub fn compute_public_key(&mut self, received_r_1: &GE) {
        self.public_signing_key = received_r_1 * self.keypair.get_secret_key();
    }

    pub fn msg_handler_keygen(&mut self, msg_received: &PartyOneMsg) -> SendingMessages{
        match msg_received {
            PartyOneMsg::KeyGenPartyOneRoundOneMsg(dlcom) => {
                println!("\n=>    KeyGen: Receiving RoundOneMsg from index 0");
                // Party two time begin
                self.set_dl_com((*dlcom).clone());
                let msg_send =
                ReceivingMessages::TwoKeyGenMessagePartyTwo(PartyTwoMsg::KenGenPartyTwoRoundOneMsg(self.msg.clone()));
                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                return SendingMessages::BroadcastMessage(msg_bytes);
            }
            PartyOneMsg::KeyGenPartyOneRoundTwoMsg(
                com_open,
                h_caret,
                h,
                gp,
                promise_state,
                promise_proof,
            ) => {
                println!("\n=>    KeyGen: Receiving RoundTwoMsg from index 0");
                // Verify commitment
                KeyGenInit::verify_received_dl_com_zk(
                    &self.received_msg,
                    &com_open,
                )
                .unwrap();

                // Verify pk and pk's
                self.verify_class_group_pk(&h_caret, &h, &gp)
                    .unwrap();

                // Verify promise proof
                self.verify_promise_proof(&promise_state, &promise_proof)
                    .unwrap();
                self.compute_public_key(com_open.get_public_key());

                // Party two save keygen to file
                let file_name = "./keygen_result".to_string() + ".json";
                let keygen_path = Path::new(&file_name);
                let keygen_json = serde_json::to_string(&(
                    promise_state,
                    self.keypair.get_secret_key().clone(),
                ))
                .unwrap();
                fs::write(keygen_path, keygen_json).expect("Unable to save !");

                println!("##    KeyGen succuss!");
                return SendingMessages::EmptyMsg;
            }
            _ => {return SendingMessages::EmptyMsg;}
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhase {
    pub cl_group: CLGroup,
    pub keypair: EcKeyPair,
    pub msg: DLogProof<GE>,
    pub received_round_one_msg: DLCommitments,
    pub precompute_c1: CLCiphertext,
}

impl SignPhase {
    pub fn new(cl_group: CLGroup, message_str: &String) -> Self {
        let message_bigint = BigInt::from_hex(message_str).unwrap();
        let message: FE = ECScalar::from(&message_bigint);

        let keypair = EcKeyPair::new();
        let d_log_proof = DLogProof::prove(keypair.get_secret_key());

        // Precompute c1
        let k2_inv = keypair.get_secret_key().invert();
        let k2_inv_m = k2_inv * message;
        let c1 = encrypt_without_r(&cl_group, &k2_inv_m);

        Self {
            cl_group,
            keypair,
            msg: d_log_proof,
            received_round_one_msg: DLCommitments::default(),
            precompute_c1: c1.0,
        }
    }

    pub fn set_dl_com(&mut self, msg: DLCommitments) {
        self.received_round_one_msg = msg;
    }

    pub fn verify_received_dl_com_zk(
        commitment: &DLCommitments,
        witness: &CommWitness,
    ) -> Result<(), MulEcdsaError> {
        // TBD: handle the error
        DLComZK::verify(commitment, witness).map_err(|_| MulEcdsaError::VrfyRecvDLComZKFailed)?;
        Ok(())
    }

    pub fn compute_public_share_key(&self, received_r_1: &GE) -> GE {
        received_r_1 * self.keypair.get_secret_key()
    }

    pub fn sign(
        &self,
        ephemeral_public_share: &GE,
        secret_key: &FE,
        cipher: &PromiseCipher,
        // message: &FE,
    ) -> Result<(CLCiphertext, FE), MulEcdsaError> {
        let q = FE::q();
        let r_x: FE = ECScalar::from(
            &ephemeral_public_share
                .x_coor()
                .ok_or(MulEcdsaError::XcoorNone)?
                .mod_floor(&q),
        );
        let k2_inv = self.keypair.get_secret_key().invert();
        // let k2_inv_m = k2_inv * message;

        // let c1 = encrypt_without_r(cl_group, &k2_inv_m);
        let v = k2_inv * r_x * secret_key;
        let t = BigInt::sample_below(&(&self.cl_group.stilde * BigInt::from(2).pow(40) * &q));
        let t_p = ECScalar::from(&t.mod_floor(&q));
        let t_plus = t + v.to_big_int();
        let c2 = eval_scal(&cipher.cl_cipher, &t_plus);

        Ok((eval_sum(&self.precompute_c1, &c2), t_p))
    }

    pub fn msg_handler_sign(&mut self, msg_received: &PartyOneMsg) -> SendingMessages{
        match msg_received {
            PartyOneMsg::SignPartyOneRoundOneMsg(dlcom) => {
                println!("\n=>    Sign: Receiving RoundOneMsg from index 0");
                self.set_dl_com((*dlcom).clone());
                let msg_send =
                ReceivingMessages::TwoSignMessagePartyTwo(PartyTwoMsg::SignPartyTwoRoundOneMsg(self.msg.clone()));
                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                return SendingMessages::BroadcastMessage(msg_bytes);
            }
            PartyOneMsg::SignPartyOneRoundTwoMsg(witness) => {
                println!("\n=>    Sign: Receiving RoundTwoMsg from index 0");

                SignPhase::verify_received_dl_com_zk(
                    &self.received_round_one_msg,
                    &witness,
                )
                .unwrap();

                // read key file
                let file_name = "./keygen_result".to_string() + ".json";
                let data = fs::read_to_string(file_name)
                    .expect("Unable to load keys, did you run keygen first? ");
                let (promise_state, secret_key): (PromiseState, FE) =
                    serde_json::from_str(&data).unwrap();

                let ephemeral_public_share = self.compute_public_share_key(witness.get_public_key());
                let (cipher, t_p) = self.sign(&ephemeral_public_share, &secret_key, &promise_state.cipher)
                    .unwrap();

                let msg_send = ReceivingMessages::TwoSignMessagePartyTwo(PartyTwoMsg::SignPartyTwoRoundTwoMsg(cipher, t_p));
                let msg_bytes = bincode::serialize(&msg_send).unwrap();

                // Party two time end
                println!("##    Sign Finish!");
                return SendingMessages::BroadcastMessage(msg_bytes);
            }
            _ => {
                println!("Unsupported parse Received MessageType");
                return SendingMessages::EmptyMsg;
            }
        }
    }
}
