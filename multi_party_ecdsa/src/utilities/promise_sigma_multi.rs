#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::utilities::elgamal::ElgamalCipher;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::SECURITY_PARAMETER;
use class_group::primitives::cl_dl_public_setup::{CLGroup, Ciphertext as CLCipher, PK, SK};
use class_group::BinaryQF;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseCipher {
    pub ec_cipher: ElgamalCipher,
    pub cl_cipher: CLCipher,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseProof {
    pub A1: GE,
    pub A2: GE,
    pub a1: BinaryQF,
    pub a2: BinaryQF,
    pub z1: FE,
    pub z2: BigInt,
    pub zm: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseState {
    pub cipher: PromiseCipher,
    pub ec_pub_key: GE,
    pub cl_pub_key: PK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseWit {
    pub m: FE,
    pub r1: FE,
    pub r2: SK,
}

impl PromiseCipher {
    pub fn encrypt(group: &CLGroup, cl_pub_key: &PK, ec_pub_key: &GE, m: &FE) -> (Self, FE, SK) {
        use class_group::primitives::cl_dl_public_setup::encrypt;
        let (ec_cipher, r1) = ElgamalCipher::encrypt(ec_pub_key, m);
        let (cl_cipher, r2) = encrypt(group, cl_pub_key, m);

        (
            Self {
                ec_cipher,
                cl_cipher,
            },
            r1,
            r2,
        )
    }

    pub fn decrypt(&self, group: &CLGroup, sk: &SK) -> FE {
        class_group::primitives::cl_dl_public_setup::decrypt(group, sk, &self.cl_cipher)
    }
}

impl PromiseProof {
    pub fn prove(group: &CLGroup, stat: &PromiseState, wit: &PromiseWit) -> Self {
        // First round
        let G: GE = GE::generator();
        let P = stat.ec_pub_key;

        let s1: FE = FE::new_random();
        let s2: BigInt = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)),
        );
        let sm = FE::new_random();

        let A1 = G * s1;
        let A2 = G * sm + P * s1;
        let a1 = group.gq.exp(&s2);
        let fr = BinaryQF::expo_f(&FE::q(), &group.delta_q, &sm.to_big_int());
        let pkr1 = &stat.cl_pub_key.0.exp(&s2);
        let a2 = fr.compose(&pkr1).reduce();

        // Second round: get challenge
        let e: BigInt = Self::challenge(&stat, &A1, &A2, &a1, &a2);

        // Third round
        let z11 = BigInt::mod_add(&s1.to_big_int(), &(&e * &wit.r1.to_big_int()), &FE::q());
        let z1 = ECScalar::from(&z11);
        let z2 = s2 + &e * &wit.r2.0;
        let zm1 = BigInt::mod_add(&sm.to_big_int(), &(&e * &wit.m.to_big_int()), &FE::q());
        let zm = ECScalar::from(&zm1);

        Self {
            A1,
            A2,
            a1,
            a2,
            z1,
            z2,
            zm,
        }
    }

    pub fn challenge(
        state: &PromiseState,
        A1: &GE,
        A2: &GE,
        a1: &BinaryQF,
        a2: &BinaryQF,
    ) -> BigInt {
        let hash256 = HSha256::create_hash(&[
            &A1.bytes_compressed_to_big_int(),
            &A2.bytes_compressed_to_big_int(),
            &BigInt::from_bytes(a1.to_bytes().as_ref()),
            &BigInt::from_bytes(a2.to_bytes().as_ref()),
            &BigInt::from_bytes(state.cipher.cl_cipher.c1.to_bytes().as_ref()),
            &BigInt::from_bytes(state.cipher.cl_cipher.c2.to_bytes().as_ref()),
            &state.cipher.ec_cipher.c1.bytes_compressed_to_big_int(),
            &state.cipher.ec_cipher.c2.bytes_compressed_to_big_int(),
        ]);

        let hash128 = &BigInt::to_bytes(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from_bytes(hash128)
    }

    pub fn verify(&self, group: &CLGroup, stat: &PromiseState) -> Result<(), MulEcdsaError> {
        let (C1, C2, c1, c2) = (
            &stat.cipher.ec_cipher.c1,
            &stat.cipher.ec_cipher.c2,
            &stat.cipher.cl_cipher.c1,
            &stat.cipher.cl_cipher.c2,
        );
        let G: GE = GE::generator();
        let P = &stat.ec_pub_key;
        let cl_pub_key = &stat.cl_pub_key;
        let e: BigInt = Self::challenge(&stat, &self.A1, &self.A2, &self.a1, &self.a2);
        let e_fe: FE = ECScalar::from(&e);
        let r1_left = G * &self.z1;
        let r1_right = &self.A1 + &(C1 * &e_fe);
        let r2_left = group.gq.exp(&self.z2);
        let c1k = c1.exp(&e);
        let r2_right = self.a1.compose(&c1k).reduce();
        let m_ec_left = G * &self.zm + P * &self.z1;
        let m_ec_right = &self.A2 + &(C2 * &e_fe);
        let pkz2 = cl_pub_key.0.exp(&self.z2);
        let fz3 = BinaryQF::expo_f(&FE::q(), &group.delta_q, &&self.zm.to_big_int());
        let m_cl_left = pkz2.compose(&fz3).reduce();
        let c2k = c2.exp(&e);
        let m_cl_right = self.a2.compose(&c2k).reduce();
        if r1_left == r1_right
            && r2_left == r2_right
            && m_cl_left == m_cl_right
            && m_ec_left == m_ec_right
        {
            Ok(())
        } else {
            Err(MulEcdsaError::VrfyPromiseFailed)
        }
    }
}
