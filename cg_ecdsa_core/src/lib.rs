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
pub mod dl_com_zk;
pub mod eccl_setup;
pub mod eckeypair;
mod error;
pub mod hsmcl;
mod primitive;

pub use self::binaryqf::{bn_to_gen, BinaryQF};
pub use self::eccl_setup::CLGroup;
pub use self::eckeypair::EcKeyPair;
pub use self::error::{ErrorReason, ProofError};
pub use self::primitive::{is_prime, numerical_log, prng, SECURITY_BITS};
