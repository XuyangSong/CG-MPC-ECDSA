use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::ours::keygen::KenGenResult;
use crate::protocols::multi_party::ours::message::*;
use crate::utilities::class::{GROUP_128, GROUP_UPDATE_128};
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::eckeypair::EcKeyPair;
use class_group::primitives::cl_dl_public_setup::PK;
use class_group::BinaryQF;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS, ShamirSecretSharing};
use curv::elliptic::curves::traits::ECScalar;
use std::collections::HashMap;
use crate::utilities::error::MulEcdsaError;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;

#[derive(Clone, Debug)]
pub struct KeyRefreshPhase {
    pub party_index: usize,
    pub params: ShamirSecretSharing,
    pub ec_keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub h_caret: PK,
    pub private_key_old: Option<KenGenResult>,
    pub share_private_key_new: FE,                // x_i
    pub share_public_key_new: HashMap<usize, GE>, // X_i 
    pub public_signing_key: GE,
    pub vss_scheme_map: HashMap<usize, VerifiableSS<GE>>, 
    pub threshold_set: Vec<usize>,
    pub msgs: KeyRefreshMsgs,
}

#[derive(Clone, Debug)]
pub struct KeyRefreshMsgs {
    pub phase_one_msgs: HashMap<usize, KeyRefreshPhaseOneMsg>,
    pub phase_two_msgs: HashMap<usize, KeyRefreshPhaseTwoMsg>,
    pub phase_two_sending_msgs: HashMap<usize, Vec<u8>>,
    pub phase_three_msgs: HashMap<usize, KeyRefreshPhaseThreeMsg>,
}

impl KeyRefreshMsgs {
     pub fn new() -> Self {
         Self {
             phase_one_msgs: HashMap::new(),
             phase_two_msgs: HashMap::new(),
             phase_two_sending_msgs: HashMap::new(),
             phase_three_msgs: HashMap::new(),
         }
     }
}

impl KeyRefreshPhase {
     pub fn new(party_index: usize, private_key_old_string: Option<String>, params: ShamirSecretSharing, threshold_set: Vec<usize>, public_signing_key_string: String) -> Result<Self, MulEcdsaError> {
          let mut private_key_old: Option<KenGenResult> = None;
          if let Some(private_key_old_string) = private_key_old_string {
               private_key_old = Some(KenGenResult::from_json_string(&private_key_old_string).unwrap());
          }
          let public_signing_key: GE = serde_json::from_str(&public_signing_key_string).map_err(|_| MulEcdsaError::FromStringFailed)?;
          // Generate cl keypair
          let mut cl_keypair = ClKeyPair::new(&GROUP_128);
          let h_caret = cl_keypair.get_public_key().clone();
          cl_keypair.update_pk_exp_p();

          // Generate elgamal keypair
          let ec_keypair = EcKeyPair::new();

          let mut msgs = KeyRefreshMsgs::new();
          let phase_one_msg = KeyRefreshPhaseOneMsg {
               h_caret: h_caret.clone(),
               h: cl_keypair.get_public_key().clone(),
               ec_pk: *ec_keypair.get_public_key(),
               gp: GROUP_UPDATE_128.gq.clone()
          };
          msgs.phase_one_msgs.insert(party_index, phase_one_msg.clone());
          
          //share the old key share
          let mut share_private_key_new = FE::zero();
          let mut vss_scheme_map = HashMap::new();
          if threshold_set.contains(&party_index){
               let (vss_scheme, secret_shares) = VerifiableSS::<GE>::share(params.threshold, params.share_count, &private_key_old.clone().unwrap().share_sk);
               for i in 0..params.share_count {
                    let phase_two_msg = KeyRefreshPhaseTwoMsg {
                        vss_scheme: vss_scheme.clone(),
                        secret_share: secret_shares[i],
                    };
                    if i == party_index {
                        // Handle my onw msg_four
                        vss_scheme_map.insert(i, vss_scheme.clone());
                        let lambda = VerifiableSS::<GE>::map_share_to_new_params(&params, party_index, &threshold_set);
                        share_private_key_new = lambda*phase_two_msg.secret_share;
                        msgs.phase_two_msgs.insert(i, phase_two_msg);
                      
                    } else {
                        let phase_two_message =
                            ReceivingMessages::KeyRefreshMessage(KeyRefreshMessage::PhaseTwoMsg(phase_two_msg));
                        let msg_two_bytes = bincode::serialize(&phase_two_message)
                            .map_err(|_| MulEcdsaError::SerializeFailed)?;
                        msgs.phase_two_sending_msgs.insert(i, msg_two_bytes);
                    }
                }
          }
           Ok(Self{
                party_index,
                params,
                ec_keypair,
                cl_keypair,
                h_caret,
                private_key_old,
                share_private_key_new,
                share_public_key_new: HashMap::new(),
                public_signing_key,
                vss_scheme_map,
                threshold_set,
                msgs,
           })
     }

     fn handle_phase_one_msg(
          &self,
          h_caret: &PK,
          h: &PK,
          gp: &BinaryQF,
      ) -> Result<(), MulEcdsaError> {
          let h_ret = h_caret.0.exp(&FE::q());
          if h_ret != h.0 || *gp != GROUP_UPDATE_128.gq {
              return Err(MulEcdsaError::VrfySignPhaseOneMsgFailed);
          }
          Ok(())
      } 

      fn handle_phase_two_msg(&mut self, index: usize, msg: &KeyRefreshPhaseTwoMsg) -> Result<(), MulEcdsaError>{
           //Check VSS
           //Check polynomial constant item equals to old key share
           let mut public_share_old = GE::random_point();
           if let Some(private_key_old) = &self.private_key_old {
               public_share_old = *private_key_old.share_pks.get(&index).ok_or(MulEcdsaError::GetIndexFailed)?;
           }
           if self.threshold_set.contains(&self.party_index) {//TBD: handle party with no input
               if !(msg
                    .vss_scheme
                    .validate_share(&msg.secret_share, self.party_index + 1)
                    .is_ok()
                    && msg.vss_scheme.commitments[0] == public_share_old)
                {
                    return Err(MulEcdsaError::VrfyVSSFailed);
                }
           }
           

           //Compute new share_private_key
           let lambda = VerifiableSS::<GE>::map_share_to_new_params(&self.params, index, &self.threshold_set);
           self.share_private_key_new = self.share_private_key_new + lambda*msg.secret_share;

           // Store vss_scheme
           self.vss_scheme_map.insert(index, msg.vss_scheme.clone());

           Ok(())
      }

      fn generate_phase_three_msg(&mut self) -> KeyRefreshPhaseThreeMsg {
          //TBD:generalize curv
          let dl_proof = DLogProof::<GE>::prove(&self.share_private_key_new);
          self.share_public_key_new
              .insert(self.party_index, dl_proof.pk.clone());
              KeyRefreshPhaseThreeMsg { dl_proof }
      }
  
      fn handle_phase_three_msg(
          &mut self,
          index: usize,
          msg: &KeyRefreshPhaseThreeMsg,
      ) -> Result<(), MulEcdsaError> {
          DLogProof::verify(&msg.dl_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
          self.share_public_key_new.insert(index, msg.dl_proof.pk);
  
          Ok(())
      }

      pub fn process_begin(&mut self) -> Result<SendingMessages, MulEcdsaError> {
          let msg = self
          .msgs
          .phase_one_msgs
          .get(&self.party_index)
          .ok_or(MulEcdsaError::GetIndexFailed)?;
          let msg_send =
               ReceivingMessages::KeyRefreshMessage(KeyRefreshMessage::PhaseOneMsg(msg.clone()));
          let sending_msg_bytes = bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
          return Ok(SendingMessages::BroadcastMessage(sending_msg_bytes));
      }

      pub fn msg_handler(&mut self, index: usize, msg: &KeyRefreshMessage) -> Result<SendingMessages, MulEcdsaError> {
           match msg {
                KeyRefreshMessage::PhaseOneMsg(msg) => {
                    self.handle_phase_one_msg(&msg.h_caret, &msg.h, &msg.gp)?; 
                    self.msgs.phase_one_msgs.insert(index, msg.clone());
                    if self.msgs.phase_one_msgs.len() == self.params.share_count {
                         let sending_msg = self.msgs.phase_two_sending_msgs.clone();
                         return Ok(SendingMessages::P2pMessage(sending_msg));
                    }
                }
                KeyRefreshMessage::PhaseTwoMsg(msg) => {
                     // Already received the msg
                     if self.msgs.phase_two_msgs.get(&index).is_some() {
                          return Ok(SendingMessages::EmptyMsg);
                     }

                     //Handle the msg
                     self.handle_phase_two_msg(index, &msg)?;
                     self.msgs.phase_two_msgs.insert(index, msg.clone());

                     //Generate the next msg
                     if self.msgs.phase_two_msgs.len() == self.params.threshold+1 {
                          let msg_three = self.generate_phase_three_msg();
                          self.msgs.phase_three_msgs.insert(self.party_index, msg_three.clone());
                          let sending_msg = ReceivingMessages::KeyRefreshMessage(KeyRefreshMessage::PhaseThreeMsg(msg_three));
                          let sending_msg_bytes = bincode::serialize(&sending_msg)
                        .map_err(|_| MulEcdsaError::SerializeFailed)?;
                         return Ok(SendingMessages::BroadcastMessage(sending_msg_bytes));
                     }
                }
                KeyRefreshMessage::PhaseThreeMsg(msg) => {
                     //Already received the msg
                     if self.msgs.phase_three_msgs.get(&index).is_some() {
                         return Ok(SendingMessages::EmptyMsg);
                     }

                     //Handle the msg
                     self.handle_phase_three_msg(index, &msg)?;
                     self.msgs.phase_three_msgs.insert(index, msg.clone());
                     
                     if self.msgs.phase_three_msgs.len() == self.params.share_count {
                         let ret = KenGenResult {
                              pk: self.public_signing_key,
                              cl_sk: self.cl_keypair.cl_priv_key.clone(),
                              ec_sk: self.ec_keypair.secret_share.clone(),
                              share_sk: self.share_private_key_new.clone(),
                              share_pks: self.share_public_key_new.clone(),
                              vss: self.vss_scheme_map.clone(),
                          };
                          let keygen_json = serde_json::to_string(&ret).map_err(|_| MulEcdsaError::ToStringFailed)?;
                         return Ok(SendingMessages::KeyRefreshSuccessWithResult(keygen_json));
                     }
                }
           }

           Ok(SendingMessages::EmptyMsg)
      }
}

#[test]
fn test_key_refresh(){
     use curv::BigInt;
     use curv::elliptic::curves::traits::ECPoint;
     let private_key_old_json_0 = r#"{
          "pk": {
               "x": "97d8767855c1d34e95cd8ccd00c4f0ddfa6d55b03ac059c739611a2dcbc34ab9",
               "y": "7caad4cc3cdeba44bd5f0874b820a6b921c0b744a2ebadabfc0db8d9bf3c8eda"
          },
          "cl_sk": "45b0d1d48dd307fbdaee70dfd4c24d8317bde11f341384b1c89727c800bf907165be1479cd6be72a85f9f8d3f669877f0acc8088e359b773819e32d7364fbe9f83020bfecd31105d7d369696f02858c824fa6dafa789f6cb462648a95e2e13ca44df6c96a03df2d337e9423b9e218089a1adff385b489fbd13b2b587050c9d1d0d69082aa5301713e77a7d1b6",
          "ec_sk": "f98677d73d6a7b0b0e17499022a481baa0a261d42fc414f67d0b7184d1752eba",
          "share_sk": "585a119dce89d7fdc68f37948994250668cd6fe73242a8bfce488789a5150b45",
          "share_pks": {
               "1": {
                    "x": "55619e8302b3186a21292f56fde4d7bab8a0d601d3c76eede045e5daf66837b9",
                    "y": "4f64f92d9aada806147bd667b30c1710482ee52168867cf13177cec4099fe6f8"
               },
               "0": {
                    "x": "3dbb042edd7f6dabae8be77f84226baa992e95516c874aa72d077216c61b476",
                    "y": "c17bf5c8da4c6699d453fb460ddb773d80b1ad30617f9edfc99b6f55d1ef5759"
               },
               "2": {
                    "x": "881c985f3f040230e70e9ff3f41c5a554850716bfb05c05739c2da5627ac124f",
                    "y": "9d30943d8c02826a7fd7b6e1fcd1c58b8fc92ab1a759e4165e4a2150ad65b356"
               }
          },
          "vss": {
               "1": {
                    "parameters": {
                         "threshold": 1,
                         "share_count": 3
                    },
                    "commitments": [{
                         "x": "34c304983d115cafe4b0aa4a185cb1843532eb98e18e591c986b7b4fe278b6f0",
                         "y": "81ba8da81850a10e18e58ba3410e5793009ecb16283864a8b4b5fc16b0e8af73"
                    }, {
                         "x": "392359898051b9d76159f1844433fd833557a343b865ac0dff3b22932dcd721",
                         "y": "e02796d3b02bea6718fc148a985c9ddaf1e16bef7672c7b4b0e89f90a71913d9"
                    }]
               },
               "2": {
                    "parameters": {
                         "threshold": 1,
                         "share_count": 3
                    },
                    "commitments": [{
                         "x": "e5722c116419780bc48e333b46822276cec727ca6e66c6047deff3bbdbff3438",
                         "y": "f50b10ab324a1093d736720cf5e39369c7d1bc1f147b53cc8379d44af6a12848"
                    }, {
                         "x": "e602d084f75066aa8f46e536aae9a7909c2abfcb91a41bda4db282fdae7172d9",
                         "y": "289b973bb9a7cb09eb6a9f411ff240a63de4899490a0fca1134e16c9c17b3557"
                    }]
               },
               "0": {
                    "parameters": {
                         "threshold": 1,
                         "share_count": 3
                    },
                    "commitments": [{
                         "x": "b6166251c41e3328321ac972c5514d388e4bdfe77087b0169849024e8843fd69",
                         "y": "8dbda227c175d0c68908c5b7a2c2de9c9d499161d243a5fef0a4d2d57efefec8"
                    }, {
                         "x": "717af4754480356c948f02d820794c062de94504a57ad470a21f0507b73b707d",
                         "y": "18ba06c6be38be4777a10f5d080c88c180190852d6e205230875ba5a6835ab94"
                    }]
               }
          }
     }"#;
     let private_key_old_json_1 = r#"{
          "pk": {
               "x": "97d8767855c1d34e95cd8ccd00c4f0ddfa6d55b03ac059c739611a2dcbc34ab9",
               "y": "7caad4cc3cdeba44bd5f0874b820a6b921c0b744a2ebadabfc0db8d9bf3c8eda"
          },
          "cl_sk": "416384f8a0eceef99dcda6d9c55fd5e03453e6e8f2b187a0774e975d943163bdf861de2df1b080f07978ef1d33603bf579ca5e09b0bb7f30fe357167b14934ebf95750770e1c4de073a91462594d42407afff284019d5d3b8398757542913f491300cee1acf2f0081142afeca15815966cde36ba3423d5d48bc45f1851efc80fdc583540215427be4925f089b",
          "ec_sk": "e1eb4b54601b50338b9565f42c582392b407c7c739ce43a71f90aa913582643b",
          "share_sk": "b5f5e19a706b0245c723109cf99067b4648a057201c208001f6bda63f934b03a",
          "share_pks": {
               "0": {
                    "x": "3dbb042edd7f6dabae8be77f84226baa992e95516c874aa72d077216c61b476",
                    "y": "c17bf5c8da4c6699d453fb460ddb773d80b1ad30617f9edfc99b6f55d1ef5759"
               },
               "1": {
                    "x": "55619e8302b3186a21292f56fde4d7bab8a0d601d3c76eede045e5daf66837b9",
                    "y": "4f64f92d9aada806147bd667b30c1710482ee52168867cf13177cec4099fe6f8"
               },
               "2": {
                    "x": "881c985f3f040230e70e9ff3f41c5a554850716bfb05c05739c2da5627ac124f",
                    "y": "9d30943d8c02826a7fd7b6e1fcd1c58b8fc92ab1a759e4165e4a2150ad65b356"
               }
          },
          "vss": {
               "2": {
                    "parameters": {
                         "threshold": 1,
                         "share_count": 3
                    },
                    "commitments": [{
                         "x": "e5722c116419780bc48e333b46822276cec727ca6e66c6047deff3bbdbff3438",
                         "y": "f50b10ab324a1093d736720cf5e39369c7d1bc1f147b53cc8379d44af6a12848"
                    }, {
                         "x": "e602d084f75066aa8f46e536aae9a7909c2abfcb91a41bda4db282fdae7172d9",
                         "y": "289b973bb9a7cb09eb6a9f411ff240a63de4899490a0fca1134e16c9c17b3557"
                    }]
               },
               "0": {
                    "parameters": {
                         "threshold": 1,
                         "share_count": 3
                    },
                    "commitments": [{
                         "x": "b6166251c41e3328321ac972c5514d388e4bdfe77087b0169849024e8843fd69",
                         "y": "8dbda227c175d0c68908c5b7a2c2de9c9d499161d243a5fef0a4d2d57efefec8"
                    }, {
                         "x": "717af4754480356c948f02d820794c062de94504a57ad470a21f0507b73b707d",
                         "y": "18ba06c6be38be4777a10f5d080c88c180190852d6e205230875ba5a6835ab94"
                    }]
               },
               "1": {
                    "parameters": {
                         "threshold": 1,
                         "share_count": 3
                    },
                    "commitments": [{
                         "x": "34c304983d115cafe4b0aa4a185cb1843532eb98e18e591c986b7b4fe278b6f0",
                         "y": "81ba8da81850a10e18e58ba3410e5793009ecb16283864a8b4b5fc16b0e8af73"
                    }, {
                         "x": "392359898051b9d76159f1844433fd833557a343b865ac0dff3b22932dcd721",
                         "y": "e02796d3b02bea6718fc148a985c9ddaf1e16bef7672c7b4b0e89f90a71913d9"
                    }]
               }
          }
     }"#;
     let params = ShamirSecretSharing{
          share_count: 3,
          threshold: 1,
     };

     let threshold_set = vec![0, 1];

     let public_signing_key = r#"{
          "x": "97d8767855c1d34e95cd8ccd00c4f0ddfa6d55b03ac059c739611a2dcbc34ab9",
          "y": "7caad4cc3cdeba44bd5f0874b820a6b921c0b744a2ebadabfc0db8d9bf3c8eda"
     }"#;
     //init key refresh
     let mut keyrefresh_0 = KeyRefreshPhase::new(0, Some(private_key_old_json_0.to_string()), params.clone(), threshold_set.clone(), public_signing_key.to_string()).unwrap();
     let mut keyrefresh_1 = KeyRefreshPhase::new(1, Some(private_key_old_json_1.to_string()), params.clone(), threshold_set.clone(), public_signing_key.to_string()).unwrap();
     let mut keyrefresh_2 = KeyRefreshPhase::new(2, None, params, threshold_set.clone(), public_signing_key.to_string()).unwrap();

     //generate phase one msgs
     let phase_one_msg_0 = keyrefresh_0.msgs
          .phase_one_msgs
          .get(&keyrefresh_0.party_index)
          .ok_or(MulEcdsaError::GetIndexFailed).unwrap();
     let phase_one_msg_1 = keyrefresh_1.msgs
          .phase_one_msgs
          .get(&keyrefresh_1.party_index)
          .ok_or(MulEcdsaError::GetIndexFailed).unwrap();
     let phase_one_msg_2 = keyrefresh_2.msgs
          .phase_one_msgs
          .get(&keyrefresh_2.party_index)
          .ok_or(MulEcdsaError::GetIndexFailed).unwrap();

     //handle phase one msgs and generate phase two msgs
     //party 0
     keyrefresh_0.handle_phase_one_msg(&phase_one_msg_1.h_caret, &phase_one_msg_1.h, &phase_one_msg_1.gp).unwrap();
     keyrefresh_0.handle_phase_one_msg(&phase_one_msg_2.h_caret, &phase_one_msg_2.h, &phase_one_msg_2.gp).unwrap();
     let phase_two_msg_0 = keyrefresh_0.msgs.phase_two_sending_msgs.clone();
     //party 1
     keyrefresh_1.handle_phase_one_msg(&phase_one_msg_0.h_caret, &phase_one_msg_0.h, &phase_one_msg_0.gp).unwrap();
     keyrefresh_1.handle_phase_one_msg(&phase_one_msg_2.h_caret, &phase_one_msg_2.h, &phase_one_msg_2.gp).unwrap();
     let phase_two_msg_1 = keyrefresh_1.msgs.phase_two_sending_msgs.clone();
     //party 2
     keyrefresh_2.handle_phase_one_msg(&phase_one_msg_0.h_caret, &phase_one_msg_0.h, &phase_one_msg_0.gp).unwrap();
     keyrefresh_2.handle_phase_one_msg(&phase_one_msg_1.h_caret, &phase_one_msg_1.h, &phase_one_msg_1.gp).unwrap();
     //let phase_two_msg_2 = keyrefresh_2.msgs.phase_two_sending_msgs.clone();

     //handle phase two msgs and generate phase three msgs
     let mut phase_two_msg_0_received: HashMap<usize, KeyRefreshPhaseTwoMsg> = HashMap::new();
     for (key, value) in phase_two_msg_0 {
          let received_msg: ReceivingMessages = bincode::deserialize(&value).unwrap();
          match received_msg {
               ReceivingMessages::KeyRefreshMessage(msg_1) => {
                    match msg_1 {
                         KeyRefreshMessage::PhaseTwoMsg(msg) => {
                              phase_two_msg_0_received.insert(key, msg);
                         }
                         _ => {}
                    }
               }
               _ => {}
          }
     }
     let mut phase_two_msg_1_received: HashMap<usize, KeyRefreshPhaseTwoMsg> = HashMap::new();
     for (key, value) in phase_two_msg_1 {
          let received_msg: ReceivingMessages = bincode::deserialize(&value).unwrap();
          match received_msg {
               ReceivingMessages::KeyRefreshMessage(msg_1) => {
                    match msg_1 {
                         KeyRefreshMessage::PhaseTwoMsg(msg) => {
                              phase_two_msg_1_received.insert(key, msg);
                         }
                         _ => {}
                    }
               }
               _ => {}
          }
     }

     //party 0
     keyrefresh_0.handle_phase_two_msg(1, phase_two_msg_1_received.get(&(0 as usize)).unwrap()).unwrap();
     keyrefresh_0.msgs.phase_two_msgs.insert(1, phase_two_msg_1_received.get(&(0 as usize)).unwrap().clone());
     let phase_three_msg_0 = keyrefresh_0.generate_phase_three_msg();
     keyrefresh_0.msgs.phase_three_msgs.insert(keyrefresh_0.party_index, phase_three_msg_0.clone());
     //party 1
     keyrefresh_1.handle_phase_two_msg(0, phase_two_msg_0_received.get(&(1 as usize)).unwrap()).unwrap();
     keyrefresh_1.msgs.phase_two_msgs.insert(0, phase_two_msg_0_received.get(&(1 as usize)).unwrap().clone());
     let phase_three_msg_1 = keyrefresh_1.generate_phase_three_msg();
     keyrefresh_1.msgs.phase_three_msgs.insert(keyrefresh_0.party_index, phase_three_msg_1.clone());
     //party 2
     keyrefresh_2.handle_phase_two_msg(0, phase_two_msg_0_received.get(&(2 as usize)).unwrap()).unwrap();
     keyrefresh_2.msgs.phase_two_msgs.insert(0, phase_two_msg_0_received.get(&(2 as usize)).unwrap().clone());
     keyrefresh_2.handle_phase_two_msg(1, phase_two_msg_1_received.get(&(2 as usize)).unwrap()).unwrap();
     keyrefresh_2.msgs.phase_two_msgs.insert(1, phase_two_msg_1_received.get(&(2 as usize)).unwrap().clone());
     let phase_three_msg_2 = keyrefresh_2.generate_phase_three_msg();
     keyrefresh_2.msgs.phase_three_msgs.insert(keyrefresh_2.party_index, phase_three_msg_2.clone());

     //handle phase three msgs and generate new key
     //party 0
     keyrefresh_0.handle_phase_three_msg(1, &phase_three_msg_1).unwrap();
     keyrefresh_0.msgs.phase_three_msgs.insert(1, phase_three_msg_1.clone());
     keyrefresh_0.handle_phase_three_msg(2, &phase_three_msg_2).unwrap();
     keyrefresh_0.msgs.phase_three_msgs.insert(2, phase_three_msg_2.clone());
     let key_new_0 = KenGenResult {
          pk: keyrefresh_0.private_key_old.unwrap().pk,
          cl_sk: keyrefresh_0.cl_keypair.cl_priv_key.clone(),
          ec_sk: keyrefresh_0.ec_keypair.secret_share.clone(),
          share_sk: keyrefresh_0.share_private_key_new.clone(),
          share_pks: keyrefresh_0.share_public_key_new.clone(),
          vss: keyrefresh_0.vss_scheme_map.clone(),
     };
     //party 1
     keyrefresh_1.handle_phase_three_msg(1, &phase_three_msg_1).unwrap();
     keyrefresh_1.msgs.phase_three_msgs.insert(1, phase_three_msg_1.clone());
     keyrefresh_1.handle_phase_three_msg(2, &phase_three_msg_2).unwrap();
     keyrefresh_1.msgs.phase_three_msgs.insert(2, phase_three_msg_2.clone());
     let key_new_1 = KenGenResult {
          pk: keyrefresh_1.private_key_old.clone().unwrap().pk,
          cl_sk: keyrefresh_1.cl_keypair.cl_priv_key.clone(),
          ec_sk: keyrefresh_1.ec_keypair.secret_share.clone(),
          share_sk: keyrefresh_1.share_private_key_new.clone(),
          share_pks: keyrefresh_1.share_public_key_new.clone(),
          vss: keyrefresh_1.vss_scheme_map.clone(),
     };
     //party 2
     keyrefresh_2.handle_phase_three_msg(1, &phase_three_msg_1).unwrap();
     keyrefresh_2.msgs.phase_three_msgs.insert(1, phase_three_msg_1.clone());
     keyrefresh_2.handle_phase_three_msg(2, &phase_three_msg_2).unwrap();
     keyrefresh_2.msgs.phase_three_msgs.insert(2, phase_three_msg_2.clone());
     let key_new_2 = KenGenResult {
          pk: keyrefresh_1.private_key_old.unwrap().pk,
          cl_sk: keyrefresh_2.cl_keypair.cl_priv_key.clone(),
          ec_sk: keyrefresh_2.ec_keypair.secret_share.clone(),
          share_sk: keyrefresh_2.share_private_key_new.clone(),
          share_pks: keyrefresh_2.share_public_key_new.clone(),
          vss: keyrefresh_2.vss_scheme_map.clone(),
     };

     let points0 = vec![0, 1, 2].clone()
     .iter()
     .map(|i| {
         let index_bn = BigInt::from(*i as u32 + 1);
         ECScalar::from(&index_bn)
     })
     .collect::<Vec<FE>>();
     let master_key_1 = VerifiableSS::<GE>::lagrange_interpolation_at_zero(&[points0[0], points0[1]], &vec![key_new_0.share_sk, key_new_1.share_sk]);
     let master_key_2 = VerifiableSS::<GE>::lagrange_interpolation_at_zero(&[points0[1], points0[2]], &vec![key_new_1.share_sk, key_new_2.share_sk]);
     let master_key_3 = VerifiableSS::<GE>::lagrange_interpolation_at_zero(&[points0[0], points0[2]], &vec![key_new_0.share_sk, key_new_2.share_sk]);
     assert_eq!(key_new_0.pk, GE::generator().scalar_mul(&master_key_1.get_element()));
     assert_eq!(key_new_0.pk, GE::generator().scalar_mul(&master_key_2.get_element()));
     assert_eq!(key_new_0.pk, GE::generator().scalar_mul(&master_key_3.get_element()));
}


