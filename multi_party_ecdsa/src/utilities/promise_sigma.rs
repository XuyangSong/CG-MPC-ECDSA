#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use super::elgamal::ElgamalCipher;
use super::error::ProofError;
use super::SECURITY_PARAMETER;
use class_group::primitives::cl_dl_public_setup::{CLGroup, Ciphertext as CLCipher, PK, SK};
use class_group::BinaryQF;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PromiseCipher {
    pub c1: BinaryQF,
    pub c2: BinaryQF,
    pub c3: GE,
    pub c4: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseProof {
    pub a1: GE,
    pub a2: GE,
    pub b1: BinaryQF,
    pub b2: BinaryQF,
    pub z1: FE,
    pub z2: BigInt,
    pub z3: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseState {
    pub cipher: PromiseCipher,
    pub ec_pub_key: GE,
    pub cl_pub_key: PK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseWit {
    pub x: FE,
    pub r1: FE,
    pub r2: SK,
}

impl PromiseCipher {
    pub fn encrypt(group: &CLGroup, cl_pub_key: &PK, ec_pub_key: &GE, m: &FE) -> (Self, FE, SK) {
        use class_group::primitives::cl_dl_public_setup::encrypt;
        let (cl_cipher, r2) = encrypt(group, cl_pub_key, m);
        let (ec_cipher, r1) = ElgamalCipher::encrypt(ec_pub_key, m);
        (
            Self {
                c1: cl_cipher.c1,
                c2: cl_cipher.c2,
                c3: ec_cipher.c1,
                c4: ec_cipher.c2,
            },
            r1,
            r2,
        )
    }

    pub fn decrypt(&self, group: &CLGroup, sk: &SK) -> FE {
        let (c1, c2) = (&self.c1, &self.c2);
        let cl_cipher = CLCipher {
            c1: c1.clone(),
            c2: c2.clone(),
        };
        let m = class_group::primitives::cl_dl_public_setup::decrypt(group, sk, &cl_cipher);
        m
    }
}

impl PromiseProof {
    pub fn prove(group: &CLGroup, stat: &PromiseState, wit: &PromiseWit) -> Self {
        let G: GE = GE::generator();
        let H = stat.ec_pub_key;
        let cl_pub_key = &stat.cl_pub_key;
        let (x, r1, r2) = (&wit.x, &wit.r1, &wit.r2);
        let s_fe: FE = FE::new_random();
        let s = s_fe.to_big_int();
        let s1: FE = FE::new_random();
        let s2: BigInt = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)),
        );
        let a1 = G * s1;
        let a2 = G * s_fe + H * s1;
        let b1 = group.gq.exp(&s2);
        let fr = BinaryQF::expo_f(&FE::q(), &group.delta_q, &s);
        let pkr1 = cl_pub_key.0.exp(&s2);
        let b2 = fr.compose(&pkr1).reduce();
        let k: BigInt = Self::challenge(&cl_pub_key, &a1, &a2, &b1, &b2, &stat.cipher);
        let z11 = BigInt::mod_add(&s1.to_big_int(), &(&k * r1.to_big_int()), &FE::q());
        let z1 = ECScalar::from(&z11);
        let z2 = s2 + &k * &r2.0;
        let z31 = BigInt::mod_add(&s, &(&k * x.to_big_int()), &FE::q());
        let z3 = ECScalar::from(&z31);

        Self {
            a1,
            a2,
            b1,
            b2,
            z1,
            z2,
            z3,
        }
    }

    pub fn challenge(
        public_key: &PK,
        a1: &GE,
        a2: &GE,
        b1: &BinaryQF,
        b2: &BinaryQF,
        ciphertext: &PromiseCipher,
    ) -> BigInt {
        let hash256 = HSha256::create_hash(&[
            // hash the statement i.e. the discrete log of Q is encrypted in (c1,c2) under encryption key h.
            &a1.bytes_compressed_to_big_int(),
            &a2.bytes_compressed_to_big_int(),
            &BigInt::from(ciphertext.c1.to_bytes().as_ref()),
            &BigInt::from(ciphertext.c2.to_bytes().as_ref()),
            &BigInt::from(public_key.0.to_bytes().as_ref()),
            // hash Sigma protocol commitments
            &BigInt::from(b1.to_bytes().as_ref()),
            &BigInt::from(b2.to_bytes().as_ref()),
        ]);

        let hash128 = &BigInt::to_vec(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from(hash128)
    }

    pub fn verify(&self, group: &CLGroup, stat: &PromiseState) -> Result<(), ProofError> {
        let (a1, a2, b1, b2, z1, z2, z3) = (
            &self.a1, &self.a2, &self.b1, &self.b2, &self.z1, &self.z2, &self.z3,
        );
        let (c1, c2, c3, c4) = (
            &stat.cipher.c1,
            &stat.cipher.c2,
            &stat.cipher.c3,
            &stat.cipher.c4,
        );
        let G: GE = GE::generator();
        let H = &stat.ec_pub_key;
        let cl_pub_key = &stat.cl_pub_key;
        let k: BigInt = Self::challenge(&cl_pub_key, &a1, &a2, &b1, &b2, &stat.cipher);
        let k_fe: FE = ECScalar::from(&k);
        let r1_left = G * z1;
        let r1_right = a1 + &(c3 * &k_fe);
        let r2_left = group.gq.exp(&z2);
        let c1k = c1.exp(&k);
        let r2_right = b1.compose(&c1k).reduce();
        let x_ec_left = G * z3 + H * z1;
        let x_ec_right = a2 + &(c4 * &k_fe);
        let pkz2 = cl_pub_key.0.exp(&z2);
        let fz3 = BinaryQF::expo_f(&FE::q(), &group.delta_q, &z3.to_big_int());
        let x_cl_left = pkz2.compose(&fz3).reduce();
        let c2k = c2.exp(&k);
        let x_cl_right = b2.compose(&c2k).reduce();
        if r1_left == r1_right
            && r2_left == r2_right
            && x_cl_left == x_cl_right
            && x_ec_left == x_ec_right
        {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}
