#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use super::error::MulEcdsaError;
use super::SECURITY_PARAMETER;
use class_group::primitives::cl_dl_public_setup::{CLGroup, Ciphertext as CLCipher, PK, SK};
use class_group::BinaryQF;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PromiseCipher {
    pub cl_cipher: CLCipher,
    pub q: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseProof {
    pub A: GE,
    pub a1: BinaryQF,
    pub a2: BinaryQF,
    pub zm: FE,
    pub zr: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseState {
    pub cipher: PromiseCipher,
    pub cl_pub_key: PK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseWit {
    pub m: FE,
    pub r: SK,
}

impl PromiseCipher {
    pub fn encrypt(group: &CLGroup, cl_pub_key: &PK, m: &FE) -> (Self, SK) {
        use class_group::primitives::cl_dl_public_setup::encrypt;
        let (cl_cipher, r) = encrypt(group, cl_pub_key, m);

        let base: GE = ECPoint::generator();
        let q = base * m;

        (Self { cl_cipher, q }, r)
    }

    pub fn decrypt(&self, group: &CLGroup, sk: &SK) -> FE {
        class_group::primitives::cl_dl_public_setup::decrypt(group, sk, &self.cl_cipher)
    }
}

impl PromiseProof {
    pub fn prove(group: &CLGroup, stat: &PromiseState, wit: &PromiseWit) -> Self {
        // First round
        let base: GE = ECPoint::generator();
        let sm = FE::new_random();
        let sr: BigInt = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)),
        );

        let A = base * sm;
        let a1 = group.gq.exp(&sr);
        let hsr = stat.cl_pub_key.0.exp(&sr);
        let fsm = BinaryQF::expo_f(&FE::q(), &group.delta_q, &sm.to_big_int());
        let a2 = fsm.compose(&hsr).reduce();

        // Second round: get challenge
        let e: BigInt = Self::challenge(&stat, &A, &a1, &a2);
        let e_fe: FE = ECScalar::from(&e);

        // Third round
        let zm = sm + e_fe * wit.m;
        let zr = sr + &e * &wit.r.0;

        Self { A, a1, a2, zm, zr }
    }

    pub fn challenge(state: &PromiseState, A: &GE, a1: &BinaryQF, a2: &BinaryQF) -> BigInt {
        let hash256 = HSha256::create_hash(&[
            // hash the statement i.e. the discrete log of Q is encrypted in (c1,c2) under encryption key h.
            &BigInt::from_bytes(state.cipher.cl_cipher.c1.to_bytes().as_ref()),
            &BigInt::from_bytes(state.cipher.cl_cipher.c2.to_bytes().as_ref()),
            &BigInt::from_bytes(state.cl_pub_key.0.to_bytes().as_ref()),
            // hash Sigma protocol commitments
            &A.bytes_compressed_to_big_int(),
            &BigInt::from_bytes(a1.to_bytes().as_ref()),
            &BigInt::from_bytes(a2.to_bytes().as_ref()),
        ]);

        let hash128 = &BigInt::to_bytes(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from_bytes(hash128)
    }

    pub fn verify(&self, group: &CLGroup, stat: &PromiseState) -> Result<(), MulEcdsaError> {
        let sample_size = &group.stilde
            * BigInt::from(2).pow(40)
            * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
            * BigInt::from(2).pow(40)
            + (FE::q() - BigInt::one()) * &group.stilde * BigInt::from(2).pow(40);

        if self.zr > sample_size {
            return Err(MulEcdsaError::ZrExcceedSize);
        }

        let base: GE = GE::generator();

        // Get challenge
        let e: BigInt = Self::challenge(&stat, &self.A, &self.a1, &self.a2);
        let e_fe: FE = ECScalar::from(&e);

        let left_1 = base * self.zm;
        let right_1 = self.A + stat.cipher.q * e_fe;

        let left_2 = group.gq.exp(&self.zr);
        let c1k = stat.cipher.cl_cipher.c1.exp(&e);
        let right_2 = self.a1.compose(&c1k).reduce();

        let hzr = stat.cl_pub_key.0.exp(&self.zr);
        let fzm = BinaryQF::expo_f(&FE::q(), &group.delta_q, &self.zm.to_big_int());
        let left_3 = hzr.compose(&fzm).reduce();
        let c2k = stat.cipher.cl_cipher.c2.exp(&e);
        let right_3 = self.a2.compose(&c2k).reduce();

        if left_1 == right_1 && left_2 == right_2 && left_3 == right_3 {
            Ok(())
        } else {
            Err(MulEcdsaError::VrfyPromiseFailed)
        }
    }
}
