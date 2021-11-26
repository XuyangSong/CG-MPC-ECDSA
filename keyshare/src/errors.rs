//! Errors type.
use thiserror::Error;

/// Represents an error in vss.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum KeyShareError {
    /// This error occurs when a json is not a valid
    #[error("Json decoding failed.")]
    InvalidJson,

    /// This error occurs when data is malformed
    #[error("Format in invalid")]
    InvalidFormat,

    // This error occurs when pointer is null
    #[error("Null pointer")]
    InvalidPointer,
    
}
