use std::cmp;

use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::traits::*;
use curv::FE;
use curv::GE;
use serde::{Deserialize, Serialize};

use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::hsmcl::HSMCL;
use class_group::primitives::cl_dl_public_setup::{decrypt, CLGroup, Ciphertext as CLCiphertext};

//****************** Begin: Party One structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenInit {
    pub keypair: EcKeyPair,
    pub round_one_msg: DLCommitments,
    pub round_two_msg: CommWitness,
    pub public_signing_key: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhase {
    pub keypair: EcKeyPair,
    pub round_one_msg: DLCommitments,
    pub round_two_msg: CommWitness,
    pub received_msg: DLogProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: FE,
    pub r: FE,
}

impl KeyGenInit {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);
        Self {
            public_signing_key: ECPoint::generator(), // Compute later
            keypair,
            round_one_msg: dl_com_zk.commitments,
            round_two_msg: dl_com_zk.witness,
        }
    }

    // TBD: remove return value
    pub fn verify_and_get_next_msg(
        &self,
        dl_proof: &DLogProof,
    ) -> Result<CommWitness, ProofError> {
        // TBD: handle the error
        DLogProof::verify(dl_proof).unwrap();

        Ok(self.round_two_msg.clone())
    }

    // TBD: remove return value
    pub fn compute_public_key(&mut self, received_r_2: &GE) -> GE {
        self.public_signing_key = received_r_2 * self.keypair.get_secret_key();
        self.public_signing_key
    }
}

impl SignPhase {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);
        let received_msg = DLogProof{
            pk: GE::generator(),
            pk_t_rand_commitment: GE::generator(),
            challenge_response: FE::zero(),
        };

        Self {
            keypair,
            round_one_msg: dl_com_zk.commitments,
            round_two_msg: dl_com_zk.witness,
            received_msg,
        }
    }

    pub fn set_received_msg(&mut self, msg: DLogProof) {
        self.received_msg = msg;
    }

    pub fn verify_and_get_next_msg(
        &self,
        dl_proof: &DLogProof,
    ) -> Result<CommWitness, ProofError> {
        // TBD: handle the error
        DLogProof::verify(dl_proof).unwrap();
        Ok(self.round_two_msg.clone())
    }

    pub fn compute_public_share_key(&self, received_r_2: &GE) -> GE {
        received_r_2 * self.keypair.get_secret_key()
    }

    pub fn sign(
        &self,
        cl_group: &CLGroup,
        hsmcl: &HSMCL,
        partial_sig_c3: &CLCiphertext,
        ephemeral_public_share: &GE,
        secret_key: &FE,
        t_p: &FE,
    ) -> Signature {
        let q = FE::q();
        let r_x: FE = ECScalar::from(&ephemeral_public_share.x_coor().unwrap().mod_floor(&q));
        let k1_inv = self.keypair.get_secret_key().invert();
        let x1_mul_tp = *secret_key * t_p;
        let s_tag = decrypt(cl_group, &hsmcl.secret, &partial_sig_c3).sub(&x1_mul_tp.get_element());
        let s_tag_tag = k1_inv * s_tag;
        let s = cmp::min(s_tag_tag.to_big_int(), q - s_tag_tag.to_big_int());
        Signature {
            s: ECScalar::from(&s),
            r: r_x,
        }
    }

    pub fn verify(signature: &Signature, pubkey: &GE, message: &FE) -> Result<(), ProofError> {
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
            return Err(ProofError);
        }
    }
}
