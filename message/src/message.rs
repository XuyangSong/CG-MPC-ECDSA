use readerwriter::{Decodable, Encodable, ReadError, Reader, WriteError, Writer};
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq)]
pub struct Message(pub Vec<u8>);

impl Deref for Message {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Encodable for Message {
    fn encode(&self, dst: &mut impl Writer) -> Result<(), WriteError> {
        Ok(dst.write(b"data", self.as_slice()).unwrap())
    }
}

impl Decodable for Message {
    fn decode(buf: &mut impl Reader) -> Result<Self, ReadError> {
        Ok(Self(buf.read_bytes(buf.remaining_bytes()).unwrap()))
    }
}
