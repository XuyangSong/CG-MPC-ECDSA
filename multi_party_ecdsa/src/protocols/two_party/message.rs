use crate::utilities::dl_com_zk::*;
use class_group::primitives::cl_dl_public_setup::Ciphertext as CLCiphertext;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::FE;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TwoPartyMsg {
    KeyGenInitSync(usize),
    KegGenBegin,
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KenGenPartyTwoRoundOneMsg(DLogProof),
    KeyGenPartyOneRoundTwoMsg(CommWitness, HSMCLPublic),
    SignInitSync(usize),
    SignBegin,
    SignPartyOneRoundOneMsg(DLCommitments),
    SignPartyTwoRoundOneMsg(DLogProof),
    SignPartyOneRoundTwoMsg(CommWitness),
    SignPartyTwoRoundTwoMsg(CLCiphertext, FE),
}
