use crate::slices::*;
use libc::c_char;
use crate::common::{c_pointer_to_string, string_to_c_pointer};
use crate::keyshare::*;
use std::{panic, ptr};
use std::ffi::CString;

#[no_mangle]
pub extern "C" fn share(key: *const c_char, threshold: usize, share_count: usize) -> *mut c_char{
    let result = panic::catch_unwind(|| {
        let key_string = c_pointer_to_string(key).unwrap();
        let key_fe = key_to_slice(key_string);
        let key_shares = key_share(threshold, share_count, key_fe);
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
        let key_reconstructed: String = slice_to_key(key_reconstructed_fe).unwrap();
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

#[no_mangle]
/// String pointer free
///
/// You must free the pointers return by 'vss_create, vss_verify, secret_reconstruct' manually.
pub unsafe extern fn str_free(ptr: *mut libc::c_char) {
    if ptr.is_null() {
        return;
    }

    CString::from_raw(ptr);
}

