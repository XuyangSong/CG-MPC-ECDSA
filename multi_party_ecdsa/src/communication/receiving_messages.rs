use crate::protocols::multi_party::ours::message::{MultiKeyGenMessage, MultiSignMessage, KeyRefreshMessage};
use crate::protocols::two_party::asia21::message::{PartyOneMsg, PartyTwoMsg};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivingMessages {
    MultiKeyGenInitSync(usize),
    MultiKeyGenMessage(MultiKeyGenMessage),
    KeyRefreshMessage(KeyRefreshMessage),
    MultiSignInitSync(usize),
    MultiSignMessage(MultiSignMessage),
    TwoKeyGenMessagePartyOne(PartyOneMsg),
    TwoSignMessagePartyOne(PartyOneMsg),
    TwoKeyGenMessagePartyTwo(PartyTwoMsg),
    TwoSignMessagePartyTwo(PartyTwoMsg),
    KeyGenBegin,
    SignBegin,
    KeyRefreshBegin,
    SetMessage(String),
    SignOnlineBegin,
    TwoPartySignRefresh(String, String), // SignRefresh(message, keygen_result_json)
    MultiPartySignRefresh(String, String, String, Vec<usize>), // SignRefresh(message, keygen_result_json, subset)
    // TBD: Extend it to errors
    NeedRefresh,
}
