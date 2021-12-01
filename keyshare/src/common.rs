//! Common functions.
use crate::errors::KeyShareError;
use libc::c_char;
use std::ffi::CStr;
use std::{ffi::CString, ptr};

/// Converts C char pointer to Rust string.
pub fn c_pointer_to_string(c_pointer: *const c_char) -> Result<String, KeyShareError> {
    if c_pointer == ptr::null_mut() {
        return Err(KeyShareError::InvalidPointer);
    }

    let cstr = unsafe { CStr::from_ptr(c_pointer) };
    match cstr.to_str() {
        Ok(v) => Ok(v.to_owned()),
        Err(_) => Err(KeyShareError::InvalidFormat),
    }
}

/// Converts Rust string to C char pointer.
pub fn string_to_c_pointer(string: String) -> *mut c_char {
    match CString::new(string) {
        Ok(s) => s.into_raw(),
        Err(_) => return ptr::null_mut(),
    }
}


