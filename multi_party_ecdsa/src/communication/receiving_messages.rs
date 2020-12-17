use crate::protocols::multi_party::ours::party_i::MultiKeyGenMessage;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivingMessages {
    MultiKeyGenMessage(MultiKeyGenMessage),
}
