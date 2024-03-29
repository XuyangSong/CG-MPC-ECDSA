use crate::protocols::two_party::xax21::party_one::{MtaConsistencyMsg, NonceKEMsg};
use crate::protocols::two_party::xax21::party_two::KeyGenSecRoungMsg;
use crate::utilities::cl_proof::*;
use crate::utilities::class_group::*;
use crate::utilities::dl_com_zk::*;
use crate::utilities::promise_sigma::{PromiseProof, PromiseState};
use classgroup::gmp_classgroup::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DMZPartyOneMsg {
    KeyGenInitSync(usize),
    SignInitSync(usize),
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KeyGenPartyOneRoundTwoMsg(
        CommWitness,
        PK,
        PK,
        GmpClassGroup,
        PromiseState,
        PromiseProof,
    ),
    SignPartyOneRoundOneMsg(DLCommitments),
    SignPartyOneRoundTwoMsg(CommWitness),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum XAXPartyOneMsg {
    KeyGenInitSync(usize),
    SignInitSync(usize),
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KeyGenPartyOneRoundTwoMsg(CommWitness),
    MtaPartyOneRoundOneMsg((CLProof, CLState)),
    SignPartyOneRoundOneMsg(MtaConsistencyMsg, NonceKEMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DMZPartyTwoMsg {
    KeyGenInitSync(usize),
    KenGenPartyTwoRoundOneMsg(DLogProof<GE>),
    KeyGenFinish,
    SignInitSync(usize),
    SignPartyTwoRoundOneMsg(DLogProof<GE>),
    SignPartyTwoRoundTwoMsg(Ciphertext, FE),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum XAXPartyTwoMsg {
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
