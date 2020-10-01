use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::traits::*;
use cg_ecdsa_core::dl_com_zk::*;
use cg_ecdsa_core::eccl_setup::{
    encrypt, eval_scal, eval_sum, CLGroup, Ciphertext as CLCiphertext,
};
use cg_ecdsa_core::eckeypair::EcKeyPair;
use cg_ecdsa_core::hsmcl::HSMCLPublic;
use curv::FE;
use curv::GE;
use serde::{Deserialize, Serialize};

//****************** Begin: Party Two structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenInit {
    pub keypair: EcKeyPair,
    pub msg: DLogProof,
}

impl KeyGenInit {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let d_log_proof = DLogProof::prove(keypair.get_secret_key());
        Self {
            keypair,
            msg: d_log_proof,
        }
    }

    pub fn verify_received_dl_com_zk(
        commitment: &DLCommitments,
        witness: &CommWitness,
    ) -> Result<(), ProofError> {
        // TBD: handle the error
        DLComZK::verify(commitment, witness).unwrap();

        Ok(())
    }

    pub fn verify_setup_and_zkcldl_proof(
        cl_group: &CLGroup,
        hsmcl_public: &HSMCLPublic,
        party_one_pub_key: &GE,
    ) -> Result<(), ProofError> {
        // TBD: need to do this?
        // let setup_verify = cl_group.setup_verify(seed);

        // TBD: handle the error
        hsmcl_public
            .proof
            .verify(
                cl_group,
                &hsmcl_public.cl_pub_key,
                &hsmcl_public.encrypted_share,
                &hsmcl_public.ec_pub_base,
                &hsmcl_public.ec_pub_key,
                party_one_pub_key,
            )
            .unwrap();

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhase {
    pub keypair: EcKeyPair,
    pub msg: DLogProof,
}

impl SignPhase {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let d_log_proof = DLogProof::prove(keypair.get_secret_key());
        Self {
            keypair,
            msg: d_log_proof,
        }
    }

    pub fn verify_received_dl_com_zk(
        commitment: &DLCommitments,
        witness: &CommWitness,
    ) -> Result<(), ProofError> {
        // TBD: handle the error
        DLComZK::verify(commitment, witness).unwrap();

        Ok(())
    }

    pub fn compute_public_share_key(&self, received_r_1: &GE) -> GE {
        received_r_1 * self.keypair.get_secret_key()
    }

    pub fn sign(
        &self,
        cl_group: &CLGroup,
        hsmcl_public: &HSMCLPublic,
        ephemeral_public_share: &GE,
        secret_key: &FE,
        message: &FE,
    ) -> CLCiphertext {
        let q = FE::q();
        let r_x: FE = ECScalar::from(&ephemeral_public_share.x_coor().unwrap().mod_floor(&q));
        let k2_inv = self.keypair.get_secret_key().invert();
        let k2_inv_m = k2_inv * message;

        let c1 = encrypt(cl_group, &hsmcl_public.cl_pub_key, &k2_inv_m);
        let v = k2_inv * r_x * secret_key;
        // TBD: Get random t and add it.

        let clcipher = CLCiphertext {
            c1: hsmcl_public.encrypted_share.c1.clone(),
            c2: hsmcl_public.encrypted_share.c2.clone(),
        };
        let c2 = eval_scal(&clcipher, &v.to_big_int());
        eval_sum(&c1.0, &c2)
    }
}
