//use class_group::primitives::cl_dl_public_setup::{CLGroup, PK, SK};
use crate::utilities::class_group::*;
use classgroup::ClassGroup;
// use curv::elliptic::curves::secp256_k1::FE;
// use curv::elliptic::curves::traits::*;
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

    pub fn from_sk(sk: SK, group: &CLGroup) -> Self {
        let cl_pub_key = group.pk_for_sk(sk.clone());
        Self {
            cl_pub_key,
            cl_priv_key: sk,
        }
    }

    pub fn update_pk_exp_p(&mut self) {
        let mut new_pk = self.cl_pub_key.0.clone();
        new_pk.pow(q());
        self.cl_pub_key = PK(new_pk);
    }

    pub fn get_public_key(&self) -> &PK {
        &self.cl_pub_key
    }

    pub fn get_secret_key(&self) -> &SK {
        &self.cl_priv_key
    }
}
