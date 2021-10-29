use crate::protocols::multi_party::ours::message::{MultiKeyGenMessage, MultiSignMessage};
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
}
