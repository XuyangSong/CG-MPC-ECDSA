use curv::elliptic::curves::traits::*;
use curv::FE;
use curv::GE;
use serde::{Deserialize, Serialize};

use crate::eccl_setup::{verifiably_encrypt, CLDLProof, CLGroup, ECCLcipher, PK, SK};
use crate::eckeypair::EcKeyPair;

#[derive(Debug, Serialize, Deserialize)]
pub struct HSMCL {
    pub public: PK,
    pub secret: SK,
    pub ec_base: GE,
    pub ec_public: GE,
    pub encrypted_share: ECCLcipher,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HSMCLPublic {
    pub cl_pub_key: PK,
    pub ec_pub_base: GE,
    pub ec_pub_key: GE,
    pub proof: CLDLProof,
    pub encrypted_share: ECCLcipher,
}

impl HSMCL {
    pub fn generate_keypair_and_encrypted_share_and_proof(
        keygen: &EcKeyPair,
        cl_group: &CLGroup,
    ) -> (HSMCL, HSMCLPublic) {
        let (secret_key, public_key) = cl_group.keygen();
        let g: GE = GE::generator();
        let ecsk: FE = FE::new_random();
        let h: GE = g.scalar_mul(&ecsk.get_element());
        let (ciphertext, proof) = verifiably_encrypt(
            &cl_group,
            &public_key,
            (keygen.get_secret_key(), keygen.get_public_key()),
            (&g, &h),
        );

        (
            HSMCL {
                public: public_key.clone(),
                secret: secret_key,
                ec_base: g.clone(),
                ec_public: h.clone(),
                encrypted_share: ciphertext.clone(),
            },
            HSMCLPublic {
                cl_pub_key: public_key,
                ec_pub_base: g,
                ec_pub_key: h,
                proof,
                encrypted_share: ciphertext,
            },
        )
    }
}
