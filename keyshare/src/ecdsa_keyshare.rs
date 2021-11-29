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

#[test]
fn test_share(){
    use std::ffi::CString;

    let secret_str = "1c67f89bfd156ef37e33dd4cf0cdfccf899aaf12d";
    let c_pointer = CString::new(secret_str).expect("CString::new failed");

    // Successful instance
    let ret = share(c_pointer.as_ptr(), 1, 3);
    assert_ne!(ret, ptr::null_mut());

    // Failed instance, null pointer
    let ret = share(ptr::null_mut(), 1, 3);
    assert_eq!(ret, ptr::null_mut());

    // Failed instance, wrong vss parameter
    let ret = share(c_pointer.as_ptr(), 4, 3);
    assert_eq!(ret, ptr::null_mut());
}

#[test]
fn test_reconstruct() {
    use std::ffi::CString;

    let input_string = r#"[{
        "vss_scheme": {
            "parameters": {
                "threshold": 1,
                "share_count": 3
            },
            "commitments": [{
                "x": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "y": "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            }, {
                "x": "d8912ad335dcf36fc205b47baa269b7dfc6bcdcd59450e64bfcfd13c909fbbf8",
                "y": "e2eb761872986f295143e54e7d44f95729566799486d74996c97eb704a300255"
            }]
        },
        "secret_shares": ["fbca3e9364d5ffd645e053fb661b333835b07695337c28acde0a42e370b874ef", "f7947d26c9abffac8bc0a7f6cc366671b0b21043b7afb11dfc42273a113aa89c"],
        "secret_shares_indice": [0, 1]
    }, {
        "vss_scheme": {
            "parameters": {
                "threshold": 1,
                "share_count": 3
            },
            "commitments": [{
                "x": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "y": "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
            }, {
                "x": "1ccd2a5096f48c05caafe650a02124978e3880c72f70d302fbdc1687d5063ec6",
                "y": "4f550ebc72326c00968fdd3099255688211879b4ca9e26720e7227fc553eedd8"
            }]
        },
        "secret_shares": ["50f4b9a00b649f8b13ffeb9bb7d118ac6d6ee919431acf519c1e1a17bab1feee", "a1e9734016c93f1627ffd7376fa23158daddd23286359ea3383c342f7563fdda"],
        "secret_shares_indice": [0, 1]
    }]"#;

    let c_pointer = CString::new(input_string).expect("CString::new failed");
    let ret = reconstruct(c_pointer.as_ptr());
    assert_ne!(ret, ptr::null_mut());


    // Failed instance, null pointer
    let ret = reconstruct(ptr::null_mut());
    assert_eq!(ret, ptr::null_mut());

    // Failed instance, invalid json format string
    let invalid_json = r#"{"76f3f440a601bb04dd3730cbec67baf987c96b1eed4b3258ecefc}"#;
    let invalid_json_c_pointer = CString::new(invalid_json).expect("CString::new failed");
    let ret = reconstruct(invalid_json_c_pointer.as_ptr());
    assert_eq!(ret, ptr::null_mut());
}

#[test]
fn test_restore(){
    use std::ffi::CString;

    let input_string = r#"[{
        "secret_shares": ["21eff1a2ed10ce112c10660cb9a787d85d22b4c5321dc04b6281ad3a6ecda2ab", "43dfe345da219c225820cc19734f0fb0ba45698a643b8096c5035a74dd9b4555"],
        "secret_shares_indice": [0, 1]
    }, {
        "secret_shares": ["c02f5be8b267afc9226eb3a56f41748e8063b0333af3f1c270804b3a5dd98da0", "805eb7d164cf5f9244dd674ade82e91e4618837fc69f4349212e37e7eb7cd9fd"],
        "secret_shares_indice": [0, 1]
    }]"#;
    let c_pointer = CString::new(input_string).expect("CString::new failed");
    let ret = restore(c_pointer.as_ptr(), 2);
    assert_ne!(ret, ptr::null_mut());

    // Failed instance, null pointer
    let ret = restore(ptr::null_mut(), 2);
    assert_eq!(ret, ptr::null_mut());

    //Failed instance, invalid index to restore
    let ret = restore(c_pointer.as_ptr(), 1);
    assert_eq!(ret, ptr::null_mut());

    // Failed instance, invalid json format string
    let invalid_json = r#"{"76f3f440a601bb04dd3730cbec67baf987c96b1eed4b3258ecefc}"#;
    let invalid_json_c_pointer = CString::new(invalid_json).expect("CString::new failed");
    let ret = reconstruct(invalid_json_c_pointer.as_ptr());
    assert_eq!(ret, ptr::null_mut());
}

