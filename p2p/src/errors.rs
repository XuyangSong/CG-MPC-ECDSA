use thiserror::Error;

/// Represents errors.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum MpcIOError {
    #[error("Obtain HashMap value Failed")]
    ObtainValueFailed,
}
