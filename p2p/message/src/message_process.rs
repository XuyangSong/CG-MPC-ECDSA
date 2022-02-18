use readerwriter::Codable;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum ProcessMessage<Custom: Codable> {
    BroadcastMessage(Custom),
    SendMessage(usize, Custom),
    SendMultiMessage(HashMap<usize, Custom>),
    Quit(),
    Default(),
}

pub trait MsgProcess<Custom: Codable> {
    fn process(
        &mut self,
        index: usize,
        msg: Custom,
    ) -> Result<ProcessMessage<Custom>, anyhow::Error>;
}
