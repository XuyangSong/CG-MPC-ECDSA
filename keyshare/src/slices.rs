use curv::elliptic::curves::secp256_k1::FE;
use curv::BigInt;
use curv::elliptic::curves::traits::*;
use curv::arithmetic::traits::*;

pub fn key_to_slice(key_string: String) -> Vec<FE> {
     let key = key_string.as_bytes();
     let mut slices: Vec<FE> = Vec::new();
     let mut i = 0;
     while i+30 < key.len() {
          let element = ECScalar::from(&BigInt::from_bytes(&key[i..(i+30)]));
          slices.push(element);
          i += 30;
     }
     let last_element: FE = ECScalar::from(&BigInt::from_bytes(&key[i..key.len()]));
     slices.push(last_element);
     return slices;
 }
 
pub fn slice_to_key(slices: Vec<FE>) -> Result<String, String> {
     let mut key_bytes = Vec::new();
     for i in 0..slices.len() {
          key_bytes.extend(slices[i].to_big_int().to_bytes());
     }
     let key = String::from_utf8(key_bytes).map_err(|_| "Failed to transfer bytes to string")?;
     return Ok(key);
 }
