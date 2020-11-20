use crate::eccl_setup::{CLGroup, PK, SK};

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

    pub fn get_public_key(&self) -> &PK {
        &self.cl_pub_key
    }

    pub fn get_secret_key(&self) -> &SK {
        &self.cl_priv_key
    }
}
