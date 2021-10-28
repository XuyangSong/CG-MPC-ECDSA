use crate::utilities::dl_com_zk::*;
use crate::utilities::promise_sigma::{PromiseProof, PromiseState};
use class_group::primitives::cl_dl_public_setup::{Ciphertext as CLCiphertext, PK};
use class_group::BinaryQF;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use serde::{Deserialize, Serialize};

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub enum TwoPartyMsg {
//     KeyGenInitSync(usize),
//     KegGenBegin,
//     KeyGenPartyOneRoundOneMsg(DLCommitments),
//     KenGenPartyTwoRoundOneMsg(DLogProof<GE>),
//     KeyGenPartyOneRoundTwoMsg(CommWitness, PK, PK, BinaryQF, PromiseState, PromiseProof),
//     SignInitSync(usize),
//     SignBegin,
//     SignPartyOneRoundOneMsg(DLCommitments),
//     SignPartyTwoRoundOneMsg(DLogProof<GE>),
//     SignPartyOneRoundTwoMsg(CommWitness),
//     SignPartyTwoRoundTwoMsg(CLCiphertext, FE),
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PartyOneMsg {
    KeyGenInitSync(usize),
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KeyGenPartyOneRoundTwoMsg(CommWitness, PK, PK, BinaryQF, PromiseState, PromiseProof),
    SignInitSync(usize),
    SignPartyOneRoundOneMsg(DLCommitments),
    SignPartyOneRoundTwoMsg(CommWitness),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PartyTwoMsg {
    KeyGenInitSync(usize),
    KegGenBegin,
    KenGenPartyTwoRoundOneMsg(DLogProof<GE>),
    SignInitSync(usize),
    SignBegin,
    SignPartyTwoRoundOneMsg(DLogProof<GE>),
    SignPartyTwoRoundTwoMsg(CLCiphertext, FE),
}
