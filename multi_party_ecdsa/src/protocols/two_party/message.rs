use crate::utilities::dl_com_zk::*;
use crate::utilities::promise_sigma::{PromiseProof, PromiseState};
use class_group::primitives::cl_dl_public_setup::{Ciphertext as CLCiphertext, PK};
use class_group::BinaryQF;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::FE;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TwoPartyMsg {
    KeyGenInitSync(usize),
    KegGenBegin,
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KenGenPartyTwoRoundOneMsg(DLogProof),
    KeyGenPartyOneRoundTwoMsg(CommWitness, PK, PK, BinaryQF, PromiseState, PromiseProof),
    SignInitSync(usize),
    SignBegin,
    SignPartyOneRoundOneMsg(DLCommitments),
    SignPartyTwoRoundOneMsg(DLogProof),
    SignPartyOneRoundTwoMsg(CommWitness),
    SignPartyTwoRoundTwoMsg(CLCiphertext, FE),
}
