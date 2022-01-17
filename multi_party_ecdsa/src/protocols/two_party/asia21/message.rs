use crate::utilities::dl_com_zk::*;
use crate::utilities::promise_sigma::{PromiseProof, PromiseState};
use crate::utilities::class_group::*;
use classgroup::gmp_classgroup::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PartyOneMsg {
    KeyGenInitSync(usize),
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KeyGenPartyOneRoundTwoMsg(CommWitness, PK, PK, GmpClassGroup, PromiseState, PromiseProof),
    SignInitSync(usize),
    SignPartyOneRoundOneMsg(DLCommitments),
    SignPartyOneRoundTwoMsg(CommWitness),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PartyTwoMsg {
    KeyGenInitSync(usize),
    KenGenPartyTwoRoundOneMsg(DLogProof<GE>),
    KeyGenFinish,
    SignInitSync(usize),
    SignPartyTwoRoundOneMsg(DLogProof<GE>),
    SignPartyTwoRoundTwoMsg(Ciphertext, FE),
}
