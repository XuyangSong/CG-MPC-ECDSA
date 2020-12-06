#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
extern crate libc;
#[macro_use]
extern crate serde_derive;
extern crate curv;
extern crate serde;
extern crate serde_json;

mod binaryqf;
mod clkeypair;
pub mod dl_com_zk;
pub mod eccl_setup;
pub mod eckeypair;
pub mod elgamal;
mod error;
pub mod hsmcl;
mod primitive;
mod promise_sigma;
mod signature;
mod cl_enc_proof;

pub use self::binaryqf::{bn_to_gen, BinaryQF};
pub use self::clkeypair::ClKeyPair;
pub use self::dl_com_zk::{
    CommWitness, DLComZK, DLCommitments, DlogCommitment, DlogCommitmentOpen,
};
pub use self::eccl_setup::{CLGroup, Ciphertext, PK, SK, next_probable_prime};
pub use self::eckeypair::EcKeyPair;
pub use self::error::{ErrorReason, ProofError};
pub use self::primitive::{is_prime, numerical_log, prng, SECURITY_BITS};
pub use self::promise_sigma::{PromiseCipher, PromiseProof, PromiseState, PromiseWit};
pub use self::cl_enc_proof::{CLEncState, CLEncProof, CLEncWit};
pub use self::signature::Signature;
