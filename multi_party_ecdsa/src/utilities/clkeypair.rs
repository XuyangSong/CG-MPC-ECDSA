use class_group::primitives::cl_dl_public_setup::{CLGroup, PK, SK};
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::traits::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClKeyPair {
    pub cl_pub_key: PK,
    pub cl_priv_key: SK,
}

impl ClKeyPair {
    pub fn new(group: &CLGroup) -> Self {
        let (cl_priv_key, cl_pub_key) = group.keygen();
        Self {
            cl_pub_key,
            cl_priv_key,
        }
    }

    pub fn update_pk_exp_p(&mut self) {
        let new_pk = self.cl_pub_key.0.exp(&FE::q());
        self.cl_pub_key = PK(new_pk);
    }

    pub fn get_public_key(&self) -> &PK {
        &self.cl_pub_key
    }

    pub fn get_secret_key(&self) -> &SK {
        &self.cl_priv_key
    }
}
