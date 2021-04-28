use crate::protocols::multi_party::ours::message::{MultiKeyGenMessage, MultiSignMessage};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivingMessages {
    MultiKeyGenInitSync(usize),
    MultiKeyGenMessage(MultiKeyGenMessage),
    MultiSignInitSync(usize),
    MultiSignMessage(MultiSignMessage),
}
