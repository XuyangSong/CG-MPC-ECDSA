use crate::protocols::multi_party::message::{MultiKeyGenMessage, MultiSignMessage};
use crate::protocols::two_party::message::{PartyOneMsg, PartyTwoMsg};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivingMessages {
    MultiKeyGenInitSync(usize),
    MultiKeyGenMessage(MultiKeyGenMessage),
    MultiSignInitSync(usize),
    MultiSignMessage(MultiSignMessage),
    TwoKeyGenMessagePartyOne(PartyOneMsg),
    TwoSignMessagePartyOne(PartyOneMsg),
    TwoKeyGenMessagePartyTwo(PartyTwoMsg),
    TwoSignMessagePartyTwo(PartyTwoMsg),
    KeyGenBegin,
    SignOfflineBegin,
    SignOnlineBegin(String),
    TwoPartySignRefresh(String, String), // SignRefresh(message, keygen_result_json)
    MultiPartySignRefresh(String, String, Vec<usize>), // SignRefresh(message, keygen_result_json, subset)
    // TBD: Extend it to errors
    NeedRefresh,
}
