use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use serde::{Deserialize, Serialize};
use curv::BigInt;
use curv::elliptic::curves::traits::*;
use curv::arithmetic::traits::*;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VssShareOutput {
    pub vss_scheme: VerifiableSS<GE>,
    pub secret_shares: Vec<FE>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VssReconstructInput {
    pub vss_scheme: VerifiableSS<GE>,
    pub secret_shares: Vec<FE>,
    pub secret_shares_indice: Vec<usize>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VssRestoreInput {
    pub secret_shares: Vec<FE>,
    pub secret_shares_indice: Vec<usize>,
}

pub fn vss_share(
     threshold: usize,
     share_count: usize,
     secret: FE,
 ) -> VssShareOutput {
     let (vss_scheme, secret_shares) =
          VerifiableSS::<GE>::share(threshold, share_count, &secret);
     let output = VssShareOutput {
          vss_scheme,
          secret_shares,
     }; 
     output
 }

 pub fn key_share(
      threshold: usize,
      share_count: usize,
      key: Vec<FE>,
 ) -> Vec<VssShareOutput> {
     let mut key_shares: Vec<VssShareOutput> = Vec::new();
     for i in 0..key.len() {
          let (vss_scheme, secret_shares) =
          VerifiableSS::<GE>::share(threshold, share_count, &key[i]);
          let output = VssShareOutput {
               vss_scheme,
               secret_shares,
               };
               key_shares.push(output);
     }
     key_shares
 }

 pub fn key_reconstruct(key_shares: Vec<VssReconstructInput>) -> Vec<FE>{
      let mut key_vec: Vec<FE> = Vec::new();
      for i in 0..key_shares.len() {
           let key_mid = key_shares[i].vss_scheme.reconstruct(&key_shares[i].secret_shares_indice, &key_shares[i].secret_shares);
           key_vec.push(key_mid);
      }
      key_vec
 }

 pub fn key_restore(key_shares: Vec<VssRestoreInput>, restore_index: usize) -> Vec<FE> {
      let  mut restore_shares: Vec<FE> = Vec::new();
      for i in 0..key_shares.len() {
           let restore_share = restore(&key_shares[i], restore_index);
           restore_shares.push(restore_share);
      }
      restore_shares
 }

 pub fn restore(key_shares: &VssRestoreInput, restore_index: usize) -> FE {
     //restore a share from other shares
      let restore_index_big = BigInt::from(restore_index as u32 + 1);
      let point = ECScalar::from(&restore_index_big);
      let points = key_shares.secret_shares_indice
            .iter()
            .map(|i| {
                let index_big = BigInt::from(*i as u32 + 1);
                ECScalar::from(&index_big)
            })
            .collect::<Vec<FE>>();
      let restore_share = lagrange_interpolation_at_point(&points, &key_shares.secret_shares, point);
      restore_share
 }

 pub fn lagrange_interpolation_at_point(points: &[FE], values: &[FE], point: FE) -> FE {
     let vec_len = values.len();
     assert_eq!(points.len(), vec_len);
     // Lagrange interpolation for a point 
     let lag_coef = (0..vec_len)
         .map(|i| {
             let xi = &points[i];
             let yi = &values[i];
             let num: FE = ECScalar::from(&BigInt::one());
             let denum: FE = ECScalar::from(&BigInt::one());
             let num = points.iter().zip(0..vec_len).fold(num, |acc, x| {
                 if i != x.1 {
                     let xi_sub_x = x.0.sub(&point.get_element());
                     acc * xi_sub_x
                 } else {
                     acc
                 }
             });
             let denum = points.iter().zip(0..vec_len).fold(denum, |acc, x| {
                 if i != x.1 {
                     let xj_sub_xi = x.0.sub(&xi.get_element());
                     acc * xj_sub_xi
                 } else {
                     acc
                 }
             });
             let denum = denum.invert();
             num * denum * yi.clone()
         })
         .collect::<Vec<FE>>();
     let mut lag_coef_iter = lag_coef.iter();
     let head = lag_coef_iter.next().unwrap();
     let tail = lag_coef_iter;
     tail.fold(head.clone(), |acc, x| acc.add(&x.get_element()))
 }
    
 #[test]
 fn test_key_share() {
     use crate::slices::*;
   
      //construct key to share
      let key_fe = key_to_slice(String::from_utf8(b"test123123123123123123123123123123123".to_vec()).unwrap());
      
      //key share
      let key_shares = key_share(1, 3, key_fe);
      println!("key_shares = {:?}", key_shares);
      
      //construct inputs to reconstruct key
      let mut reconstruct_input_vec: Vec<VssReconstructInput> = Vec::new();
      for i in 0..key_shares.len() {
          let secret_shares: Vec<FE> = vec![key_shares[i].secret_shares[0], key_shares[i].secret_shares[1]];
          let secret_shares_indice: Vec<usize> = vec![0, 1];
          let reconstruct_input =  VssReconstructInput {
               vss_scheme: key_shares[i].vss_scheme.clone(),
               secret_shares,
               secret_shares_indice,
          };
          reconstruct_input_vec.push(reconstruct_input);
      }

      //key reconstruct
      let key_reconstructed_fe = key_reconstruct(reconstruct_input_vec);
      let key_reconstructed: String = slice_to_key(key_reconstructed_fe).unwrap();

      //construct inputs to restore a share
      let mut restore_input_vec: Vec<VssRestoreInput> = Vec::new();
      for i in 0..key_shares.len() {
          let secret_shares: Vec<FE> = vec![key_shares[i].secret_shares[0], key_shares[i].secret_shares[1]];
          let secret_shares_indice: Vec<usize> = vec![0, 1];
          let reconstruct_input =  VssRestoreInput {
               secret_shares,
               secret_shares_indice,
          };
          restore_input_vec.push(reconstruct_input);
      }

      //key restore
      let key_restored = key_restore(restore_input_vec, 2);
      println!("key_restored = {:?}", key_restored);
      println!("key_reconstructed = {:?}", key_reconstructed);
 }
 
 
