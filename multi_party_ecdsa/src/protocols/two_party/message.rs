use crate::utilities::dl_com_zk::*;
use class_group::primitives::cl_dl_public_setup::{Ciphertext as CLCiphertext, PK};
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::FE;
use serde::{Deserialize, Serialize};
use crate::utilities::promise_sigma::{PromiseState, PromiseProof};
use class_group::BinaryQF;


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
