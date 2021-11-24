use crate::errors::KeyShareError;
use curv::elliptic::curves::secp256_k1::FE;
use crate::slices::Slice;
use serde::{Deserialize, Serialize};
use curv::BigInt;
use curv::elliptic::curves::traits::*;
use curv::arithmetic::traits::*;
use class_group::primitives::cl_dl_public_setup::SK;
use libc::c_char;
use crate::common::{c_pointer_to_string, string_to_c_pointer};
use crate::keyshare::*;
use std::{panic, ptr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TwoPartyOneKey {
    pub ec_sk: FE,
    pub cl_sk: SK,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TwoPartyTwoKey {
    pub ec_sk: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiPartyKey {
    pub ec_sk: FE,
    pub cl_sk: SK,
    pub share_sk: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TwoPartyOneShare {
    pub ec_shares: VssShareOutput,
    pub cl_shares: Vec<VssShareOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TwoPartyTwoShare {
    pub ec_shares: VssShareOutput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiPartyShare {
    pub ec_shares: VssShareOutput,
    pub cl_shares: Vec<VssShareOutput>,
    pub share_shares: VssShareOutput,
}

impl Slice for TwoPartyOneKey {
    fn key_to_slice(&self) -> Vec<FE> {
        let key_str = serde_json::to_string(&self).unwrap();
        let key_bytes = key_str.as_bytes();
        let mut slices: Vec<FE> = Vec::new();
        let mut i = 0;
        while i+30 < key_bytes.len() {
             let element = ECScalar::from(&BigInt::from_bytes(&key_bytes[i..(i+30)]));
             slices.push(element);
             i += 30;
        }
        let last_element: FE = ECScalar::from(&BigInt::from_bytes(&key_bytes[i..key_bytes.len()]));
        slices.push(last_element);
        return slices;
    }
    
    fn slice_to_key(slices: Vec<FE>) -> TwoPartyOneKey {
        let mut key_bytes = Vec::new();
        for i in 0..slices.len() {
             key_bytes.extend(slices[i].to_big_int().to_bytes());
        }
        let key_str = std::str::from_utf8(&key_bytes).unwrap();
        let key = serde_json::from_str(key_str).unwrap();
        return key;
    }
}

impl TwoPartyOneKey {
    #[no_mangle]
    pub extern "C" fn share(key: *const c_char, threshold: usize, share_count: usize) -> *mut c_char{
        let result = panic::catch_unwind(|| {
            let key_string = c_pointer_to_string(key).unwrap();
            let key: Self = serde_json::from_str(&key_string).unwrap();
            let key_fe = key.key_to_slice();
            let key_shares = key_share(threshold, share_count, key_fe).unwrap();
            let result_json = serde_json::to_string(&key_shares).unwrap();
            string_to_c_pointer(result_json)
        });
        match result {
            Ok(r) => r,
            Err(_) => ptr::null_mut(),
        } 
    }

    #[no_mangle]
    pub extern "C" fn reconstruct(key_shares: *const c_char) -> *mut c_char {
        let result = panic::catch_unwind(|| {
            let key_shares_string = c_pointer_to_string(key_shares).unwrap();
            let key_shares: Vec<VssReconstructInput> = serde_json::from_str(&key_shares_string).unwrap();
            let key_reconstructed_fe = key_reconstruct(key_shares);
            let key_reconstructed: Self = Slice::slice_to_key(key_reconstructed_fe);
            let result_json = serde_json::to_string(&key_reconstructed).unwrap();
            string_to_c_pointer(result_json)
        });
        match result {
            Ok(r) => r,
            Err(_) => ptr::null_mut(),
        }
    }

    #[no_mangle]
    pub extern "C" fn restore(key_shares: *const c_char, restore_index: usize) -> *mut c_char {
        let result = panic::catch_unwind(|| {
            let key_shares_string = c_pointer_to_string(key_shares).unwrap();
            let key_shares: Vec<VssRestoreInput> = serde_json::from_str(&key_shares_string).unwrap();
            let key_restored = key_restore(key_shares, restore_index);
            let result_json = serde_json::to_string(&key_restored).unwrap();
            string_to_c_pointer(result_json)
        });
        match result {
            Ok(r) => r,
            Err(_) => ptr::null_mut(),
        }
    }
}
