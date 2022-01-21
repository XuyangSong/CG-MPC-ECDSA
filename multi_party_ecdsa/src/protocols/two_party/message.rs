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
pub enum PartyOneMsg {
    KeyGenInitSync(usize),
    SignInitSync(usize),
    AsiaKeyGenPartyOneRoundOneMsg(DLCommitments),
    AsiaKeyGenPartyOneRoundTwoMsg(CommWitness, PK, PK, GmpClassGroup, PromiseState, PromiseProof),
    AsiaSignPartyOneRoundOneMsg(DLCommitments),
    AsiaSignPartyOneRoundTwoMsg(CommWitness),
    CCSKeyGenPartyOneRoundOneMsg(DLCommitments),
    CCSKeyGenPartyOneRoundTwoMsg(CommWitness),
    MtaPartyOneRoundOneMsg((CLDLProof, CLDLState)),
    CCSSignPartyOneRoundOneMsg(MtaConsistencyMsg, NonceKEMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PartyTwoMsg {
    KeyGenInitSync(usize),
    AsiaKenGenPartyTwoRoundOneMsg(DLogProof<GE>),
    KeyGenFinish,
    SignInitSync(usize),
    AsiaSignPartyTwoRoundOneMsg(DLogProof<GE>),
    AsiaSignPartyTwoRoundTwoMsg(Ciphertext, FE),
    CCSKeyGenPartyTwoRoundOneMsg(KeyGenSecRoungMsg),
    CCSSignPartyTwoRoundOneMsg(DLCommitments),
    MtaPartyTwoRoundOneMsg(Ciphertext),
    CCSSignPartyTwoRoundTwoMsg(CommWitness, FE),
    CCSSignPartyTwoRoundTwoMsgOnline(CommWitness),
    CCSSignPartyTwoRoundThreeMsgOnline(FE),
}
