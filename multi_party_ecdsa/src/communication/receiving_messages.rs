use crate::protocols::multi_party::ours::message::{
    KeyRefreshMessage, MultiKeyGenMessage, MultiSignMessage,
};
use crate::protocols::two_party::message::{
    AsiaPartyOneMsg, AsiaPartyTwoMsg, CCSPartyOneMsg, CCSPartyTwoMsg,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivingMessages {
    MultiKeyGenInitSync(usize),
    MultiKeyGenMessage(MultiKeyGenMessage),
    KeyRefreshMessage(KeyRefreshMessage),
    MultiSignInitSync(usize),
    MultiSignMessage(MultiSignMessage),
    AsiaTwoKeyGenMessagePartyOne(AsiaPartyOneMsg),
    AsiaTwoSignMessagePartyOne(AsiaPartyOneMsg),
    AsiaTwoKeyGenMessagePartyTwo(AsiaPartyTwoMsg),
    AsiaTwoSignMessagePartyTwo(AsiaPartyTwoMsg),
    CCSTwoKeyGenMessagePartyOne(CCSPartyOneMsg),
    CCSTwoSignMessagePartyOne(CCSPartyOneMsg),
    CCSTwoKeyGenMessagePartyTwo(CCSPartyTwoMsg),
    CCSTwoSignMessagePartyTwo(CCSPartyTwoMsg),
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
