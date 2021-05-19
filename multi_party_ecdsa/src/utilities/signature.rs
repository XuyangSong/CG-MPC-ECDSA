use super::error::MulEcdsaError;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: FE,
    pub r: FE,
}

impl Signature {
    pub fn verify(signature: &Signature, pubkey: &GE, message: &FE) -> Result<(), MulEcdsaError> {
        let q = FE::q();

        let s_inv_fe = signature.s.invert();
        let u1 = GE::generator() * (*message * s_inv_fe);
        let u2 = *pubkey * (signature.r * s_inv_fe);

        // second condition is against malleability
        let u1_plus_u2 = (u1 + u2).x_coor().unwrap().mod_floor(&q);

        if signature.r.to_big_int() == u1_plus_u2
            && signature.s.to_big_int() < FE::q() - signature.s.to_big_int()
        {
            Ok(())
        } else {
            return Err(MulEcdsaError::GeneralError);
        }
    }
}
