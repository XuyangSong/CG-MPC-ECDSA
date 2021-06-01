use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: GE,
    pub secret_share: FE,
}

impl EcKeyPair {
    pub fn new() -> Self {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base.scalar_mul(&secret_share.get_element());
        Self {
            secret_share,
            public_share,
        }
    }

    pub fn get_public_key(&self) -> &GE {
        &self.public_share
    }

    pub fn get_secret_key(&self) -> &FE {
        &self.secret_share
    }
}
