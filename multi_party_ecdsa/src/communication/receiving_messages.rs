use crate::protocols::multi_party::dmz21::message::{
    KeyRefreshMessage, MultiKeyGenMessage, MultiSignMessage,
};
use crate::protocols::two_party::message::{
    DMZPartyOneMsg, DMZPartyTwoMsg, XAXPartyOneMsg, XAXPartyTwoMsg,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivingMessages {
    MultiKeyGenInitSync(usize),
    MultiKeyGenMessage(MultiKeyGenMessage),
    KeyRefreshMessage(KeyRefreshMessage),
    MultiSignInitSync(usize),
    MultiSignMessage(MultiSignMessage),
    DMZTwoKeyGenMessagePartyOne(DMZPartyOneMsg),
    DMZTwoSignMessagePartyOne(DMZPartyOneMsg),
    DMZTwoKeyGenMessagePartyTwo(DMZPartyTwoMsg),
    DMZTwoSignMessagePartyTwo(DMZPartyTwoMsg),
    XAXTwoKeyGenMessagePartyOne(XAXPartyOneMsg),
    XAXTwoSignMessagePartyOne(XAXPartyOneMsg),
    XAXTwoKeyGenMessagePartyTwo(XAXPartyTwoMsg),
    XAXTwoSignMessagePartyTwo(XAXPartyTwoMsg),
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
