use super::error::MulEcdsaError;
use super::SECURITY_PARAMETER;
use class_group::primitives::cl_dl_public_setup::{CLGroup, Ciphertext as CLCipher, PK};
use class_group::BinaryQF;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLEncState {
    pub cipher: CLCipher,
    pub cl_pub_key: PK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLEncProof {
    pub t1: BinaryQF,
    pub t2: BinaryQF,
    pub u1: BigInt,
    pub u2: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLEncWit {
    pub a: FE,
    pub r: BigInt,
}

impl CLEncProof {
    pub fn prove(group: &CLGroup, state: &CLEncState, witness: &CLEncWit) -> Self {
        let r1: BigInt = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)),
        );
        let r2: FE = FE::new_random();

        let t1 = group.gq.exp(&r1);
        let fr = BinaryQF::expo_f(&FE::q(), &group.delta_q, &r2.to_big_int());
        let pkr1 = state.cl_pub_key.0.exp(&r1);
        let t2 = fr.compose(&pkr1).reduce();

        let k = Self::challenge(state, &t1, &t2);
        let k_fe: FE = ECScalar::from(&k);

        let u1 = r1 + &witness.r * &k;
        let u2 = r2 + witness.a * &k_fe;

        Self { t1, t2, u1, u2 }
    }

    pub fn challenge(state: &CLEncState, t1: &BinaryQF, t2: &BinaryQF) -> BigInt {
        let hash256 = HSha256::create_hash(&[
            &BigInt::from(state.cipher.c1.to_bytes().as_ref()),
            &BigInt::from(state.cipher.c2.to_bytes().as_ref()),
            &BigInt::from(state.cl_pub_key.0.to_bytes().as_ref()),
            &BigInt::from(t1.to_bytes().as_ref()),
            &BigInt::from(t2.to_bytes().as_ref()),
        ]);

        let hash128 = &BigInt::to_vec(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from(hash128)
    }

    pub fn verify(&self, group: &CLGroup, state: &CLEncState) -> Result<(), MulEcdsaError> {
        let k = Self::challenge(state, &self.t1, &self.t2);
        // let k_fe: FE = ECScalar::from(&k);

        let left1 = group.gq.exp(&self.u1);
        let c1k = state.cipher.c1.exp(&k);
        let right1 = self.t1.compose(&c1k).reduce();

        let pku1 = state.cl_pub_key.0.exp(&self.u1);
        let fu2 = BinaryQF::expo_f(&FE::q(), &group.delta_q, &self.u2.to_big_int());
        let left2 = pku1.compose(&fu2).reduce();
        let c2k = state.cipher.c2.exp(&k);
        let right2 = self.t2.compose(&c2k).reduce();
        if left1 == right1 && left2 == right2 {
            Ok(())
        } else {
            Err(MulEcdsaError::VrfyClEncProofFailed)
        }
    }
}
