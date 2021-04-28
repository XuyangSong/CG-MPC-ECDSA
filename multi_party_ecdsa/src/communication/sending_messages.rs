use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SendingMessages {
    NormalMessage(usize, Vec<u8>),
    P2pMessage(HashMap<usize, Vec<u8>>),
    BroadcastMessage(Vec<u8>),
    EmptyMsg,
    KeyGenSuccess,
    SignSuccess,
    KeyGenSuccessWithResult(String),
    SignSuccessWithResult(String),
}
