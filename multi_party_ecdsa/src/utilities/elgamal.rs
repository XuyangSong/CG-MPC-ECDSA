use super::error::MulEcdsaError;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use serde::{Deserialize, Serialize};
use std::ops::Add;
use zeroize::Zeroize;

// This part gives an ecnryption algorithm. And also gives a knowledge proof for elegmal ciphertexts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElgamalCipher {
    pub c1: GE,
    pub c2: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElgamalProof {
    pub a1: GE,
    pub a2: GE,
    pub z1: FE,
    pub z2: FE,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElgamalWit {
    pub x: FE,
    pub r: FE,
}

impl ElgamalCipher {
    pub fn encrypt(p_key: &GE, x: &FE) -> (Self, FE) {
        let base: GE = ECPoint::generator();
        let r: FE = ECScalar::new_random();
        let c1 = base.scalar_mul(&r.get_element());
        let hr = p_key.scalar_mul(&r.get_element());
        let gx = base.scalar_mul(&x.get_element());
        let c2 = hr + gx;
        (ElgamalCipher { c1, c2 }, r)
    }
    pub fn encrypt_with_determained_randomness(p_key: &GE, wit: &ElgamalWit) -> Self {
        let base: GE = ECPoint::generator();
        let c1 = base.scalar_mul(&wit.r.get_element());
        let hr = p_key.scalar_mul(&wit.r.get_element());
        let gx = base.scalar_mul(&wit.x.get_element());
        let c2 = hr + gx;
        ElgamalCipher { c1, c2 }
    }
}

impl Add for ElgamalCipher {
    type Output = ElgamalCipher;

    fn add(self, rhs: ElgamalCipher) -> ElgamalCipher {
        ElgamalCipher {
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl ElgamalProof {
    pub fn prove(cipher: &ElgamalCipher, p_key: &GE, wit: &ElgamalWit) -> Self {
        let base: GE = GE::generator();
        let mut s1: FE = FE::new_random();
        let mut s2: FE = FE::new_random();
        let a1 = base * s1;
        let mut a21 = p_key * &s1;
        let mut a22 = base * s2;
        let a2 = a21 + a22;
        let e = HSha256::create_hash_from_ge(&[p_key, &cipher.c1, &cipher.c2, &a1, &a2]);
        let z1 = if wit.r != FE::zero() {
            s1 + wit.r * e
        } else {
            s1
        }; // check that if x=0.
        let z2 = s2 + wit.x * e;
        s1.zeroize();
        s2.zeroize();
        a21.zeroize();
        a22.zeroize();
        ElgamalProof { a1, a2, z1, z2 }
    }
    pub fn verify(&self, cipher: &ElgamalCipher, p_key: &GE) -> Result<(), MulEcdsaError> {
        let e = HSha256::create_hash_from_ge(&[p_key, &cipher.c1, &cipher.c2, &self.a1, &self.a2]);
        let base: GE = GE::generator();
        let gz1 = base * self.z1;
        let rcheck = cipher.c1 * e + self.a1;
        let hz1gz2 = p_key * &self.z1 + base * self.z2;
        let xcheck = cipher.c2 * e + self.a2;
        if gz1 == rcheck && hz1gz2 == xcheck {
            Ok(())
        } else {
            Err(MulEcdsaError::VrfyElgamalProofFailed)
        }
    }
}

impl ElgamalWit {
    pub fn new_random() -> Self {
        Self {
            x: ECScalar::new_random(),
            r: ECScalar::new_random(),
        }
    }
}

#[test]
fn elgamal_test() {
    use super::eckeypair::EcKeyPair;
    let keypair = EcKeyPair::new();
    let witness = ElgamalWit::new_random();
    let cipher =
        ElgamalCipher::encrypt_with_determained_randomness(&keypair.public_share, &witness);
    let proof = ElgamalProof::prove(&cipher, &keypair.public_share, &witness);
    proof.verify(&cipher, &keypair.public_share).unwrap();
}
