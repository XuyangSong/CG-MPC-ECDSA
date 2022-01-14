#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::utilities::error::MulEcdsaError;
use crate::utilities::SECURITY_PARAMETER;
use crate::utilities::class_group::Ciphertext as CLCipher;
use crate::utilities::class_group::*;
use classgroup::gmp_classgroup::*;
use classgroup::gmp::mpz::Mpz;
use classgroup::ClassGroup;
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
    pub a1: GmpClassGroup,
    pub a2: GmpClassGroup,
    pub zm: FE,
    pub zr: Mpz,
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
        let (cl_cipher, r) = CLGroup::encrypt(group, cl_pub_key, m);

        let base: GE = ECPoint::generator();
        let q = base * m;

        (Self { cl_cipher, q }, r)
    }

    pub fn decrypt(&self, group: &CLGroup, sk: &SK) -> FE {
        CLGroup::decrypt(group, sk, &self.cl_cipher)
    }
}

impl PromiseProof {
    pub fn prove(group: &CLGroup, stat: &PromiseState, wit: &PromiseWit) -> Self {
        // First round
        let base: GE = ECPoint::generator();
        let sm = FE::new_random();
        let sr: BigInt = BigInt::sample_below(
            &(&mpz_to_bigint(group.stilde.clone())
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)));
        let A = base * sm;
        let mut a1 = group.gq.clone();
        a1.pow(bigint_to_mpz(sr.clone()));
        let mut hsr = stat.cl_pub_key.0.clone();
        hsr.pow(bigint_to_mpz(sr.clone()));
        let fsm = expo_f(&q(), &group.gq.discriminant(), &into_mpz(&sm));
        let a2 = fsm * hsr;

        // Second round: get challenge
        let e: BigInt = Self::challenge(&stat, &A, &a1, &a2);
        let e_fe: FE = ECScalar::from(&e);
        // Third round
        let zm = sm + e_fe * wit.m;
        let zr = bigint_to_mpz(sr) + &(&Mpz::from_str_radix(&e.to_str_radix(16), 16).unwrap() * &wit.r.0);
        Self { A, a1, a2, zm, zr }
    }

    pub fn challenge(state: &PromiseState, A: &GE, a1: &GmpClassGroup, a2: &GmpClassGroup) -> BigInt {
        let hash256 = HSha256::create_hash(&[
            // hash the statement i.e. the discrete log of Q is encrypted in (c1,c2) under encryption key h.
            &BigInt::from_bytes(&state.cipher.cl_cipher.c1.to_bytes()),
            &BigInt::from_bytes(&state.cipher.cl_cipher.c2.to_bytes()),
            &BigInt::from_bytes(&state.cl_pub_key.0.to_bytes()),
            // hash Sigma protocol commitments
            &A.bytes_compressed_to_big_int(),
            &BigInt::from_bytes(&a1.to_bytes()),
            &BigInt::from_bytes(&a2.to_bytes()),
        ]);

        let hash128 = &BigInt::to_bytes(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from_bytes(hash128)
    }

    pub fn verify(&self, group: &CLGroup, stat: &PromiseState) -> Result<(), MulEcdsaError> {
        let sample_size = &group.stilde
            * Mpz::from(2).pow(40)
            * Mpz::from(2).pow(SECURITY_PARAMETER as u32)
            * Mpz::from(2).pow(40)
            + (q() - Mpz::one()) * &group.stilde * Mpz::from(2).pow(40);

        if self.zr.clone() > sample_size {
            return Err(MulEcdsaError::ZrExcceedSize);
        }

        let base: GE = GE::generator();

        // Get challenge
        let e: BigInt = Self::challenge(&stat, &self.A, &self.a1, &self.a2);
        let e_fe: FE = ECScalar::from(&e);

        let left_1 = base * self.zm;
        let right_1 = self.A + stat.cipher.q * e_fe;

        let mut left_2 = group.gq.clone();
        left_2.pow(self.zr.clone());
        let mut c1k = stat.cipher.cl_cipher.c1.clone();
        c1k.pow(Mpz::from_str_radix(&e.to_str_radix(16), 16).unwrap());
        let right_2 = self.a1.clone() * c1k;

        let mut hzr = stat.cl_pub_key.0.clone();
        hzr.pow(self.zr.clone());
        let fzm = expo_f(&q(), &group.gq.discriminant(), &into_mpz(&self.zm));
        let left_3 = hzr * fzm;
        let mut c2k = stat.cipher.cl_cipher.c2.clone();
        c2k.pow(Mpz::from_str_radix(&e.to_str_radix(16), 16).unwrap());
        let right_3 = self.a2.clone() * c2k;

        if left_1 == right_1 && left_2 == right_2 && left_3 == right_3 {
            Ok(())
        } else {
            Err(MulEcdsaError::VrfyPromiseFailed)
        }
    }
}
