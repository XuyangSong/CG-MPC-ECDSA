use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy)]
pub struct ProofError;

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProofError")
    }
}

impl Error for ProofError {
    fn description(&self) -> &str {
        "Error while verifying"
    }
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorReason {
    OpenCommError,
    EvalError,
    VDFVerifyError,
    SetupError,
    PoEError,
}
