use crate::utilities::dl_com_zk::*;
use crate::utilities::promise_sigma::{PromiseProof, PromiseState};
use class_group::primitives::cl_dl_public_setup::{Ciphertext as CLCipher, PK};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{BigInt, FE, GE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use class_group::BinaryQF;

#[derive(Clone, Debug)]
pub struct KeyGenMsgs {
    pub phase_one_two_msgs: HashMap<usize, KeyGenPhaseOneTwoMsg>,
    pub phase_three_msgs: HashMap<usize, KeyGenPhaseThreeMsg>,
    pub phase_four_msgs: HashMap<usize, KeyGenPhaseFourMsg>,
    pub phase_five_msgs: HashMap<usize, KeyGenPhaseFiveMsg>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenPhaseOneTwoMsg {
    pub h_caret: PK,
    pub h: PK,
    pub gp: BinaryQF,
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
    PhaseOneTwoMsg(KeyGenPhaseOneTwoMsg),
    PhaseThreeMsg(KeyGenPhaseThreeMsg),
    PhaseFourMsg(KeyGenPhaseFourMsg),
    PhaseFiveMsg(KeyGenPhaseFiveMsg),
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
    pub commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepTwoMsg {
    pub v_i: GE,
    pub a_i: GE,
    pub b_i: GE,
    pub blind: BigInt,
    pub dl_proof: DLogProof,
    pub proof: HomoELGamalProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepFourMsg {
    pub commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepFiveMsg {
    pub blind: BigInt,
    pub u_i: GE,
    pub t_i: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepSevenMsg {
    pub s_i: FE,
}
