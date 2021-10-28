use crate::utilities::error::MulEcdsaError;
use curv::arithmetic::traits::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: FE,
    pub r: FE,
}

impl Signature {
    pub fn verify(&self, pubkey: &GE, message: &FE) -> Result<(), MulEcdsaError> {
        let q = FE::q();

        let s_inv_fe = self.s.invert();
        let u1 = GE::generator() * (*message * s_inv_fe);
        let u2 = *pubkey * (self.r * s_inv_fe);

        // second condition is against malleability
        let u1_plus_u2 = (u1 + u2).x_coor().unwrap().mod_floor(&q);

        if self.r.to_big_int() == u1_plus_u2
            && self.s.to_big_int() < FE::q() - self.s.to_big_int()
        {
            Ok(())
        } else {
            return Err(MulEcdsaError::GeneralError);
        }
    }
}
