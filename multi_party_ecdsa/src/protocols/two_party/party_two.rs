use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::hsmcl::HSMCLPublic;
use class_group::primitives::cl_dl_public_setup::{
    encrypt_without_r, eval_scal, eval_sum, CLGroup, Ciphertext as CLCiphertext,
};
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::FE;
use curv::GE;
use serde::{Deserialize, Serialize};

//****************** Begin: Party Two structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenInit {
    pub keypair: EcKeyPair,
    pub msg: DLogProof,
    pub received_msg: DLCommitments,
    pub public_signing_key: GE,
}

impl KeyGenInit {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let d_log_proof = DLogProof::prove(keypair.get_secret_key());
        Self {
            public_signing_key: ECPoint::generator(), // Compute later
            keypair,
            msg: d_log_proof,
            received_msg: DLCommitments::default(),
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

    pub fn set_dl_com(&mut self, msg: DLCommitments) {
        self.received_msg = msg;
    }

    pub fn compute_public_key(&mut self, received_r_1: &GE) {
        self.public_signing_key = received_r_1 * self.keypair.get_secret_key();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhase {
    pub keypair: EcKeyPair,
    pub msg: DLogProof,
    pub received_round_one_msg: DLCommitments,
    pub precompute_c1: CLCiphertext,
}

impl SignPhase {
    pub fn new(cl_group: &CLGroup, message: &FE) -> Self {
        let keypair = EcKeyPair::new();
        let d_log_proof = DLogProof::prove(keypair.get_secret_key());

        // Precompute c1
        let k2_inv = keypair.get_secret_key().invert();
        let k2_inv_m = k2_inv * message;
        let c1 = encrypt_without_r(cl_group, &k2_inv_m);

        Self {
            keypair,
            msg: d_log_proof,
            received_round_one_msg: DLCommitments::default(),
            precompute_c1: c1.0,
        }
    }

    pub fn set_dl_com(&mut self, msg: DLCommitments) {
        self.received_round_one_msg = msg;
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
        // message: &FE,
    ) -> (CLCiphertext, FE) {
        let q = FE::q();
        let r_x: FE = ECScalar::from(&ephemeral_public_share.x_coor().unwrap().mod_floor(&q));
        let k2_inv = self.keypair.get_secret_key().invert();
        // let k2_inv_m = k2_inv * message;

        // let c1 = encrypt_without_r(cl_group, &k2_inv_m);
        let v = k2_inv * r_x * secret_key;
        let t = BigInt::sample_below(&(&cl_group.stilde * BigInt::from(2).pow(40) * &q));
        let t_p = ECScalar::from(&t.mod_floor(&q));
        let t_plus = t + v.to_big_int();
        let clcipher = CLCiphertext {
            c1: hsmcl_public.encrypted_share.c1.clone(),
            c2: hsmcl_public.encrypted_share.c2.clone(),
        };
        let c2 = eval_scal(&clcipher, &t_plus);

        (eval_sum(&self.precompute_c1, &c2), t_p)
    }
}
