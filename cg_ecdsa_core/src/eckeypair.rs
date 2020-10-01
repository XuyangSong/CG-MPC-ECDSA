use curv::elliptic::curves::traits::*;
use curv::{FE, GE};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    public_share: GE,
    secret_share: FE,
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
