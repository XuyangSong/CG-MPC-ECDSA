use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::ProofError;
use class_group::primitives::cl_dl_public_setup::CLGroup;

use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::ours::message::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

#[derive(Clone, Debug)]
pub struct KeyGenMsgs {
    pub phase_two_msgs: HashMap<usize, KeyGenPhaseTwoMsg>,
    pub phase_three_msgs: HashMap<usize, KeyGenPhaseThreeMsg>,
    pub phase_four_msgs: HashMap<usize, KeyGenPhaseFourMsg>,
    pub phase_five_msgs: HashMap<usize, KeyGenPhaseFiveMsg>,
}

#[derive(Clone, Debug)]
pub struct KeyGen {
    // add cl group here
    pub party_index: usize,
    pub params: Parameters,
    pub ec_keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub private_signing_key: EcKeyPair,       // (u_i, u_iP)
    pub public_signing_key: GE,               // Q
    pub share_private_key: FE,                // x_i
    pub share_public_key: HashMap<usize, GE>, // X_i
    pub vss_scheme_map: HashMap<usize, VerifiableSS>,
    pub msgs: KeyGenMsgs,
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

impl KeyGen {
    pub fn phase_one_init(group: &CLGroup, party_index: usize, params: Parameters) -> Self {
        // Simulate CL computation
        let q = FE::q();
        group.gq.exp(&q);
        group.gq.exp(&q);

        let private_signing_key = EcKeyPair::new(); // Generate private key pair.
        let public_signing_key = private_signing_key.get_public_key().clone(); // Init public key, compute later.
        Self {
            party_index,
            params,
            ec_keypair: EcKeyPair::new(),
            cl_keypair: ClKeyPair::new(group),
            private_signing_key,
            public_signing_key,
            share_private_key: ECScalar::zero(), // Init share private key, compute later.
            share_public_key: HashMap::new(),
            vss_scheme_map: HashMap::new(),
            msgs: KeyGenMsgs::new(),
        }
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

    // TBD: move it to init
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

    pub fn handle_phase_three_msg(
        &mut self,
        index: usize,
        msg: &KeyGenPhaseThreeMsg,
    ) -> Result<(), ProofError> {
        let commitment = self
            .msgs
            .phase_two_msgs
            .get(&index)
            .unwrap()
            .commitment
            .clone();
        let open = msg.open.clone();

        let dlog_com = DlogCommitment { commitment, open };
        dlog_com.verify()?;

        self.public_signing_key = self.public_signing_key + dlog_com.get_public_share();

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

    pub fn handle_phase_four_msg(
        &mut self,
        index: usize,
        msg: &KeyGenPhaseFourMsg,
    ) -> Result<(), ProofError> {
        // Check VSS
        let q = self
            .msgs
            .phase_three_msgs
            .get(&index)
            .unwrap()
            .open
            .public_share;

        if !(msg
            .vss_scheme
            .validate_share(&msg.secret_share, self.party_index + 1)
            .is_ok()
            && msg.vss_scheme.commitments[0] == q)
        {
            return Err(ProofError);
        }

        // Compute share_private_key(x_i)
        self.share_private_key = self.share_private_key + msg.secret_share;

        // Store vss_scheme
        self.vss_scheme_map.insert(index, msg.vss_scheme.clone());

        Ok(())
    }

    pub fn generate_phase_five_msg(&mut self) -> KeyGenPhaseFiveMsg {
        let dl_proof = DLogProof::prove(&self.share_private_key);
        self.share_public_key
            .insert(self.party_index, dl_proof.pk.clone());
        KeyGenPhaseFiveMsg { dl_proof }
    }

    pub fn handle_phase_five_msg(
        &mut self,
        index: usize,
        msg: &KeyGenPhaseFiveMsg,
    ) -> Result<(), ProofError> {
        DLogProof::verify(&msg.dl_proof).unwrap();
        self.share_public_key.insert(index, msg.dl_proof.pk);

        Ok(())
    }

    pub fn msg_handler(
        &mut self,
        group: &CLGroup,
        index: usize,
        msg: &MultiKeyGenMessage,
    ) -> SendingMessages {
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
                self.msgs.phase_two_msgs.insert(index, msg.clone());
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
                // Simulate CL check
                let q = FE::q();
                group.gq.exp(&q);

                // Already received the msg
                if self.msgs.phase_three_msgs.get(&index).is_some() {
                    return SendingMessages::EmptyMsg;
                }

                // Handle the msg
                self.handle_phase_three_msg(index, &msg).unwrap();
                self.msgs.phase_three_msgs.insert(index, msg.clone());

                // Generate the next msg
                if self.msgs.phase_three_msgs.len() == self.params.share_count {
                    let (vss_scheme, secret_shares, _index) = self.phase_four_generate_vss();
                    let mut sending_msg: HashMap<usize, Vec<u8>> = HashMap::new();
                    for i in 0..self.params.share_count {
                        let msg = KeyGenPhaseFourMsg {
                            vss_scheme: vss_scheme.clone(),
                            secret_share: secret_shares[i],
                        };

                        if i == self.party_index {
                            // Handle my onw msg_four
                            self.vss_scheme_map.insert(i, vss_scheme.clone());
                            self.share_private_key = self.share_private_key + msg.secret_share;
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
                // Already received the msg
                if self.msgs.phase_four_msgs.get(&index).is_some() {
                    return SendingMessages::EmptyMsg;
                }

                // Handle the msg
                self.handle_phase_four_msg(index, &msg).unwrap();
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
                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                    return SendingMessages::BroadcastMessage(sending_msg_bytes);
                }
            }
            MultiKeyGenMessage::PhaseFiveMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_five_msgs.get(&index).is_some() {
                    return SendingMessages::EmptyMsg;
                }

                // Handle the msg
                self.handle_phase_five_msg(index, &msg).unwrap();
                self.msgs.phase_five_msgs.insert(index, msg.clone());
                if self.msgs.phase_five_msgs.len() == self.params.share_count {
                    return SendingMessages::KeyGenSuccess;
                }
            }
        }

        SendingMessages::EmptyMsg
    }
}
