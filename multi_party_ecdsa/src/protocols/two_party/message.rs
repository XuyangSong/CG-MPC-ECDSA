use crate::utilities::dl_com_zk::*;
use crate::utilities::cl_dl_proof::*;
use crate::utilities::promise_sigma::{PromiseProof, PromiseState};
use crate::utilities::class_group::*;
use crate::protocols::two_party::ccs21::party_two::KeyGenSecRoungMsg;
use crate::protocols::two_party::ccs21::party_one::{MtaConsistencyMsg, NonceKEMsg};
use classgroup::gmp_classgroup::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AsiaPartyOneMsg {
    KeyGenInitSync(usize),
    SignInitSync(usize),
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KeyGenPartyOneRoundTwoMsg(CommWitness, PK, PK, GmpClassGroup, PromiseState, PromiseProof),
    SignPartyOneRoundOneMsg(DLCommitments),
    SignPartyOneRoundTwoMsg(CommWitness),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CCSPartyOneMsg {
    KeyGenInitSync(usize),
    SignInitSync(usize),
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KeyGenPartyOneRoundTwoMsg(CommWitness),
    MtaPartyOneRoundOneMsg((CLDLProof, CLDLState)),
    SignPartyOneRoundOneMsg(MtaConsistencyMsg, NonceKEMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AsiaPartyTwoMsg {
    KeyGenInitSync(usize),
    KenGenPartyTwoRoundOneMsg(DLogProof<GE>),
    KeyGenFinish,
    SignInitSync(usize),
    SignPartyTwoRoundOneMsg(DLogProof<GE>),
    SignPartyTwoRoundTwoMsg(Ciphertext, FE),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CCSPartyTwoMsg {
    KeyGenInitSync(usize),
    KeyGenFinish,
    SignInitSync(usize),
    KeyGenPartyTwoRoundOneMsg(KeyGenSecRoungMsg),
    SignPartyTwoRoundOneMsg(DLCommitments),
    MtaPartyTwoRoundOneMsg(Ciphertext),
    SignPartyTwoRoundTwoMsg(CommWitness, FE),
    SignPartyTwoRoundTwoMsgOnline(CommWitness),
    SignPartyTwoRoundThreeMsgOnline(FE),
}
