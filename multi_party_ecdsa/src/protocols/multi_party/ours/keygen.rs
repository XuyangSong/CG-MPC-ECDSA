use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::ProofError;
use class_group::primitives::cl_dl_public_setup::{CLGroup, PK};

use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::ours::message::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use crate::utilities::class::update_class_group_by_p;
use class_group::BinaryQF;

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
pub struct KeyGen {
    group: CLGroup,
    pub party_index: usize,
    pub params: Parameters,
    pub cl_keypair: ClKeyPair,
    pub h_caret: PK,
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
            phase_one_two_msgs: HashMap::new(),
            phase_three_msgs: HashMap::new(),
            phase_four_vss_sending_msgs: HashMap::new(),
            phase_four_msgs: HashMap::new(),
            phase_five_msgs: HashMap::new(),
        }
    }
}

impl KeyGen {
    pub fn init(seed: &BigInt, qtilde: &BigInt, party_index: usize, params: Parameters) -> Self {
        // Init CL group
        let group = CLGroup::new_from_qtilde(seed, qtilde);

        // Generate cl keypair
        let mut cl_keypair = ClKeyPair::new(&group);
        let h_caret = cl_keypair.get_public_key().clone();
        cl_keypair.update_pk_exp_p();

        // Update gp
        let new_class_group = update_class_group_by_p(&group);

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
            gp: group.gq.clone(),
            commitment: dlog_com.commitment,
        };
        msgs.phase_one_two_msgs.insert(party_index, msg_1_2);

        //  Generate phase three msg
        let msg_3 = KeyGenPhaseThreeMsg {
            open: dlog_com.open,
        };
        msgs.phase_three_msgs.insert(party_index, msg_3);

        // Generate phase four msg, vss
        let (vss_scheme_map, share_private_key) = KeyGen::phase_four_generate_vss(
            &mut msgs,
            party_index,
            params.threshold,
            params.share_count,
            private_signing_key.get_secret_key(),
        );

        Self {
            group: new_class_group,
            party_index,
            params,
            cl_keypair,
            h_caret,
            private_signing_key,
            public_signing_key,
            share_private_key, // Init share private key, compute later.
            share_public_key: HashMap::new(),
            vss_scheme_map,
            msgs,
        }
    }

    fn get_phase_one_two_msg(&self) -> Vec<u8> {
        let msg = self.msgs.phase_one_two_msgs.get(&self.party_index).unwrap();
        let msg_send =
            ReceivingMessages::MultiKeyGenMessage(MultiKeyGenMessage::PhaseOneTwoMsg(msg.clone()));
        bincode::serialize(&msg_send).unwrap()
    }

    fn verify_phase_one_msg(&self, h_caret: &PK, h: &PK, gp: &BinaryQF) -> Result<(), ProofError> {
        let h_ret = h_caret.0.exp(&FE::q());
        if h_ret != h.0 && *gp != self.group.gq {
            return Err(ProofError);
        }
        Ok(())
    }

    fn handle_phase_three_msg(
        &mut self,
        index: usize,
        msg: &KeyGenPhaseThreeMsg,
    ) -> Result<(), ProofError> {
        println!("index: {}", index);
        let commitment = self
            .msgs
            .phase_one_two_msgs
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

    fn phase_four_generate_vss(
        msgs: &mut KeyGenMsgs,
        party_index: usize,
        threshold: usize,
        share_count: usize,
        private_signing_key: &FE,
    ) -> (HashMap<usize, VerifiableSS>, FE) {
        let (vss_scheme, secret_shares) =
            VerifiableSS::share(threshold, share_count, private_signing_key);

        let mut vss_scheme_map = HashMap::new();
        let mut share_private_key = FE::zero();
        for i in 0..share_count {
            let msg = KeyGenPhaseFourMsg {
                vss_scheme: vss_scheme.clone(),
                secret_share: secret_shares[i],
            };

            if i == party_index {
                // Handle my onw msg_four
                vss_scheme_map.insert(i, vss_scheme.clone());
                share_private_key = msg.secret_share;
                msgs.phase_four_msgs.insert(i, msg);
            } else {
                let phase_four_msg =
                    ReceivingMessages::MultiKeyGenMessage(MultiKeyGenMessage::PhaseFourMsg(msg));
                let msg_bytes = bincode::serialize(&phase_four_msg).unwrap();
                msgs.phase_four_vss_sending_msgs.insert(i, msg_bytes);
            }
        }

        (vss_scheme_map, share_private_key)
    }

    fn get_phase_four_msg(&self) -> HashMap<usize, Vec<u8>> {
        self.msgs.phase_four_vss_sending_msgs.clone()
    }

    fn handle_phase_four_msg(
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

    fn generate_phase_five_msg(&mut self) -> KeyGenPhaseFiveMsg {
        let dl_proof = DLogProof::prove(&self.share_private_key);
        self.share_public_key
            .insert(self.party_index, dl_proof.pk.clone());
        KeyGenPhaseFiveMsg { dl_proof }
    }

    fn handle_phase_five_msg(
        &mut self,
        index: usize,
        msg: &KeyGenPhaseFiveMsg,
    ) -> Result<(), ProofError> {
        DLogProof::verify(&msg.dl_proof).unwrap();
        self.share_public_key.insert(index, msg.dl_proof.pk);

        Ok(())
    }

    pub fn msg_handler(&mut self, index: usize, msg: &MultiKeyGenMessage) -> SendingMessages {
        // println!("handle receiving msg: {:?}", msg);
        match msg {
            MultiKeyGenMessage::KeyGenBegin => {
                let sending_msg_bytes = self.get_phase_one_two_msg();
                return SendingMessages::BroadcastMessage(sending_msg_bytes);
            }
            MultiKeyGenMessage::PhaseOneTwoMsg(msg) => {
                self.verify_phase_one_msg(&msg.h_caret, &msg.h, &msg.gp).unwrap();
                self.msgs.phase_one_two_msgs.insert(index, msg.clone());
                if self.msgs.phase_one_two_msgs.len() == self.params.share_count {
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
                // Already received the msg
                if self.msgs.phase_three_msgs.get(&index).is_some() {
                    return SendingMessages::EmptyMsg;
                }

                // Handle the msg
                self.handle_phase_three_msg(index, &msg).unwrap();
                self.msgs.phase_three_msgs.insert(index, msg.clone());

                // Generate the next msg
                if self.msgs.phase_three_msgs.len() == self.params.share_count {
                    let sending_msg = self.get_phase_four_msg();

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
                    // Save keygen to file
                    let keygen_path = Path::new("./keygen_result.json");
                    let keygen_json = serde_json::to_string(&(
                        self.cl_keypair.clone(),
                        self.public_signing_key.clone(),
                        self.share_private_key.clone(),
                        self.share_public_key.clone(),
                        self.vss_scheme_map.clone(),
                    ))
                    .unwrap();
                    fs::write(keygen_path, keygen_json.clone()).expect("Unable to save !");
                    return SendingMessages::KeyGenSuccessWithResult(keygen_json);
                    //return SendingMessages::KeyGenSuccess;
                }
            }
        }

        SendingMessages::EmptyMsg
    }
}

#[test]
fn test_exp() {
    use curv::arithmetic::traits::*;
    let seed: BigInt = str::parse(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
    ).unwrap();

    // 683
    // let qtilde: BigInt = str::parse("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();

    // 923
    let qtilde: BigInt = str::parse("23134629277267369792843354241183585965289672542849276532207430015120455980466994354663282525744929223097771940566085692607836906398587331469747248600524817812682304621106507179764371100444437141969242248158429617082063052414988242667563996070192147160738941577591048902446543474661282744240565430969463246910793975505673398580796242020117195767211576704240148858827298420892993584245717232048052900060035847264121684747571088249105643535567823029086931610261875021794804631").unwrap();
    let group = CLGroup::new_from_qtilde(&seed, &qtilde);
    println!("{}", group.stilde.bit_length());
    let r_1 = BigInt::sample_below(&(&group.stilde * BigInt::from(2).pow(40)));
    let r_2 = BigInt::sample_below(
        &(&group.stilde
            * BigInt::from(2).pow(40)
            * BigInt::from(2).pow(128 as u32)
            * BigInt::from(2).pow(40)),
    );

    let t1 = time::now();
    group.gq.exp(&r_1);
    println!("time: {:?}", time::now() - t1);
    let t2 = time::now();
    group.gq.exp(&r_2);
    println!("time: {:?}", time::now() - t2);
}
