use crate::common::{c_pointer_to_string, string_to_c_pointer};
use crate::keyshare::*;
use crate::slices::*;
use libc::c_char;
use std::ffi::CString;
use std::{panic, ptr};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MultiRestoreInput {
    pub key_shares: Vec<VssRestoreInput>, 
    pub restore_indices: Vec<usize>,
}

#[no_mangle]
/// Key sharing with any inputs.
///
/// 'threshold': at least 'threshold + 1' members can reconstruct sk.
/// ‘sharecount’: the num of shares.
/// 'key': key to share, any string.
///
/// output json string format example:
///[{
/// 	"vss_scheme": {
/// 		"parameters": {
/// 			"threshold": 1,
/// 			"share_count": 3
/// 		},
/// 		"commitments": [{
/// 			"x": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
/// 			"y": "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
///		}, {
/// 			"x": "1d1a759d68d2ce48b02cb3a21f39451a2f88d7b6ab0602ce6e4158f3262d3272",
/// 			"y": "347b7ccba7b680f879da4d7e58440c9a4315ad5db8ad750d016c42a782abbc36"
/// 		}]
/// 	},
/// 	"secret_shares": ["dc27c25b22d2c89a2d852a5209b7e132457ee9472280ff3052c84c688a7e0986", "b84f84b645a591345b0a54a4136fc265d04ef5a795b95e24e5be3a4444c5d1ca", "94774711687859ce888f7ef61d27a3995b1f020808f1bd1978b4281fff0d9a0e"]
/// }, {
/// 	"vss_scheme": {
/// 		"parameters": {
///			"threshold": 1,
/// 			"share_count": 3
/// 		},
/// 		"commitments": [{
/// 			"x": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
/// 			"y": "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
/// 		}, {
/// 			"x": "8326a4e72fe8e1eb4d638fd0f7a22f2f8710a44d26c02aee0c0d1494099a6223",
/// 			"y": "2b3057ddcebeafacad5aca50dca322a0b4da896c830f361e7286b1c763c3f28"
/// 		}]
/// 	},
/// 	"secret_shares": ["92f7d81455f2161b5be7a9653f00e0ade04d240ce659d03668d61e7285405442", "25efb028abe42c36b7cf52ca7e01c15d05eb6b331d6b003111d9de583a4a6741", "b8e7883d01d6425213b6fc2fbd02a20ae6388f4003c4d0677aaffccabf8abb81"]
/// }]
pub extern "C" fn share(key: *const c_char, threshold: usize, share_count: usize) -> *mut c_char {
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
///Verify a share is valid.
/// input 'key_shares' json string format example:
/// [{
///"vss_scheme": {
///    "parameters": {
///        "threshold": 1,
///        "share_count": 3
///    },
///    "commitments": [{
///        "x": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
///        "y": "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
///   }, {
///        "x": "1d1a759d68d2ce48b02cb3a21f39451a2f88d7b6ab0602ce6e4158f3262d3272",
///        "y": "347b7ccba7b680f879da4d7e58440c9a4315ad5db8ad750d016c42a782abbc36"
///    }]
///},
///"secret_share": "dc27c25b22d2c89a2d852a5209b7e132457ee9472280ff3052c84c688a7e0986",
///"secret_share_indice": 0
///}, {
///"vss_scheme": {
///    "parameters": {
///       "threshold": 1,
///        "share_count": 3
///    },
///    "commitments": [{
///        "x": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
///        "y": "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
///    }, {
///        "x": "8326a4e72fe8e1eb4d638fd0f7a22f2f8710a44d26c02aee0c0d1494099a6223",
///        "y": "2b3057ddcebeafacad5aca50dca322a0b4da896c830f361e7286b1c763c3f28"
///    }]
///},
///"secret_share": "92f7d81455f2161b5be7a9653f00e0ade04d240ce659d03668d61e7285405442",
///"secret_share_indice": 0
///}]
pub extern "C" fn verify(key_shares: *const c_char) -> bool {
    let result = panic::catch_unwind(|| {
        let key_shares_string = c_pointer_to_string(key_shares).unwrap();
        let input: Vec<VssVerifyInput> = serde_json::from_str(&key_shares_string).unwrap();
        key_verify(input)
    });
    match result {
        Ok(ret) => ret,
        _ => false,
    }
}

#[no_mangle]
/// Key reconstruct.
/// input 'key_shares' json string format example:
/// "[{
///     "vss_scheme": {
///         "parameters": {
///             "threshold": 1,
///             "share_count": 3
///         },
///         "commitments": [{
///             "x": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
///             "y": "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
///         }, {
///             "x": "d8912ad335dcf36fc205b47baa269b7dfc6bcdcd59450e64bfcfd13c909fbbf8",
///             "y": "e2eb761872986f295143e54e7d44f95729566799486d74996c97eb704a300255"
///         }]
///     },
///     "secret_shares": ["fbca3e9364d5ffd645e053fb661b333835b07695337c28acde0a42e370b874ef", "f7947d26c9abffac8bc0a7f6cc366671b0b21043b7afb11dfc42273a113aa89c"],
///     "secret_shares_indice": [0, 1]
/// }, {
///     "vss_scheme": {
///         "parameters": {
///             "threshold": 1,
///             "share_count": 3
///         },
///         "commitments": [{
///             "x": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
///             "y": "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
///         }, {
///             "x": "1ccd2a5096f48c05caafe650a02124978e3880c72f70d302fbdc1687d5063ec6",
///             "y": "4f550ebc72326c00968fdd3099255688211879b4ca9e26720e7227fc553eedd8"
///         }]
///     },
///     "secret_shares": ["50f4b9a00b649f8b13ffeb9bb7d118ac6d6ee919431acf519c1e1a17bab1feee", "a1e9734016c93f1627ffd7376fa23158daddd23286359ea3383c342f7563fdda"],
///     "secret_shares_indice": [0, 1]
/// }]"
///
/// If success, return c pointer of result, else return nullptr.
pub extern "C" fn reconstruct(key_shares: *const c_char) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let key_shares_string = c_pointer_to_string(key_shares).unwrap();
        let key_shares: Vec<VssReconstructInput> =
            serde_json::from_str(&key_shares_string).unwrap();
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
/// Key restore.
///
/// 'restore_index': index of share to restore.
/// Input 'key_shares' json string format example:
/// "{
///"key_shares": [{
///    "secret_shares": ["21eff1a2ed10ce112c10660cb9a787d85d22b4c5321dc04b6281ad3a6ecda2ab", "43dfe345da219c225820cc19734f0fb0ba45698a643b8096c5035a74dd9b4555"],
///    "secret_shares_indice": [0, 1]
///}, {
///   "secret_shares": ["c02f5be8b267afc9226eb3a56f41748e8063b0333af3f1c270804b3a5dd98da0", "805eb7d164cf5f9244dd674ade82e91e4618837fc69f4349212e37e7eb7cd9fd"],
///    "secret_shares_indice": [0, 1]
///}],
///"restore_indices": [2]
///}"
///
/// output json string format example:
/// "["7213ee56e32e4cd0965f1e0a79c4ca62444883c3e5a73fb869a532e00a117dfe","22eb8f361cb493777c1e171312bdbc402cf7806d8b1a064802536c2d53b37a09"]"
pub extern "C" fn restore(restore_inputs: *const c_char) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let restore_inputs_string = c_pointer_to_string(restore_inputs).unwrap();
        let restore_inputs: MultiRestoreInput = serde_json::from_str(&restore_inputs_string).unwrap();
        let key_restored = key_restore(restore_inputs.key_shares, restore_inputs.restore_indices); 
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
pub unsafe extern "C" fn str_free(ptr: *mut libc::c_char) {
    if ptr.is_null() {
        return;
    }

    CString::from_raw(ptr);
}

#[test]
fn test_share() {
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
fn test_verify() {
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
         			"x": "1d1a759d68d2ce48b02cb3a21f39451a2f88d7b6ab0602ce6e4158f3262d3272",
         			"y": "347b7ccba7b680f879da4d7e58440c9a4315ad5db8ad750d016c42a782abbc36"
         		}]
         	},
         	"secret_share": "dc27c25b22d2c89a2d852a5209b7e132457ee9472280ff3052c84c688a7e0986", 
            "secret_share_indice": 0
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
         			"x": "8326a4e72fe8e1eb4d638fd0f7a22f2f8710a44d26c02aee0c0d1494099a6223",
         			"y": "2b3057ddcebeafacad5aca50dca322a0b4da896c830f361e7286b1c763c3f28"
         		}]
         	},
         	"secret_share": "92f7d81455f2161b5be7a9653f00e0ade04d240ce659d03668d61e7285405442",
             "secret_share_indice": 0
         }]"#;
    let c_pointer = CString::new(input_string).expect("CString::new failed");
    let ret = verify(c_pointer.as_ptr());
    assert_eq!(ret, true);

    //Failed instance, null pointer
    let ret = verify(ptr::null_mut());
    assert_eq!(ret, false);

    // Failed instance, invalid json format string
    let invalid_json = r#"{"76f3f440a601bb04dd3730cbec67baf987c96b1eed4b3258ecefc"}"#;
    let invalid_json_c_pointer = CString::new(invalid_json).expect("CString::new failed");
    let ret = verify(invalid_json_c_pointer.as_ptr());
    assert_eq!(ret, false);
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
fn test_restore() {
    use std::ffi::CString;
    let input_string = r#"{
        "key_shares": [{
            "secret_shares": ["21eff1a2ed10ce112c10660cb9a787d85d22b4c5321dc04b6281ad3a6ecda2ab", "43dfe345da219c225820cc19734f0fb0ba45698a643b8096c5035a74dd9b4555"],
            "secret_shares_indice": [0, 1]
        }, {
            "secret_shares": ["c02f5be8b267afc9226eb3a56f41748e8063b0333af3f1c270804b3a5dd98da0", "805eb7d164cf5f9244dd674ade82e91e4618837fc69f4349212e37e7eb7cd9fd"],
            "secret_shares_indice": [0, 1]
        }],
        "restore_indices": [2]
    }"#;
    let c_pointer = CString::new(input_string).expect("CString::new failed");
    let ret = restore(c_pointer.as_ptr());
    assert_ne!(ret, ptr::null_mut());
    unsafe{str_free(ret)};

    //Failed instance, null pointer
    let ret1 = restore(ptr::null_mut());
    assert_eq!(ret1, ptr::null_mut());

    //Failed instance, invalid index to restore
    let input_string_1 = r#"{
        "key_shares": [{
            "secret_shares": ["21eff1a2ed10ce112c10660cb9a787d85d22b4c5321dc04b6281ad3a6ecda2ab", "43dfe345da219c225820cc19734f0fb0ba45698a643b8096c5035a74dd9b4555"],
            "secret_shares_indice": [0, 1]
        }, {
            "secret_shares": ["c02f5be8b267afc9226eb3a56f41748e8063b0333af3f1c270804b3a5dd98da0", "805eb7d164cf5f9244dd674ade82e91e4618837fc69f4349212e37e7eb7cd9fd"],
            "secret_shares_indice": [0, 1]
        }],
        "restore_indices": [1]
    }"#;
    let c_pointer_1 = CString::new(input_string_1).expect("CString::new failed");
    let ret2 = restore(c_pointer_1.as_ptr());
    assert_eq!(ret2, ptr::null_mut());

    // Failed instance, invalid json format string
    let invalid_json = r#"{"76f3f440a601bb04dd3730cbec67baf987c96b1eed4b3258ecefc}"#;
    let invalid_json_c_pointer = CString::new(invalid_json).expect("CString::new failed");
    let ret = restore(invalid_json_c_pointer.as_ptr());
    assert_eq!(ret, ptr::null_mut());
}
