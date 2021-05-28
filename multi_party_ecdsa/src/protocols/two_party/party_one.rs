use std::cmp;

use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::traits::*;
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::secp256_k1::GE;
use curv::arithmetic::traits::*;
use serde::{Deserialize, Serialize};

use crate::utilities::class::update_class_group_by_p;
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::promise_sigma::*;
use class_group::primitives::cl_dl_public_setup::SK;
use class_group::primitives::cl_dl_public_setup::{
    decrypt, CLGroup, Ciphertext as CLCiphertext, PK,
};
use class_group::BinaryQF;

//****************** Begin: Party One structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenInit {
    pub cl_group: CLGroup,
    pub keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub h_caret: PK,
    pub round_one_msg: DLCommitments,
    pub round_two_msg: CommWitness,
    pub public_signing_key: GE,
    pub promise_state: PromiseState,
    pub promise_proof: PromiseProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhase {
    pub cl_group: CLGroup,
    pub keypair: EcKeyPair,
    pub round_one_msg: DLCommitments,
    pub round_two_msg: CommWitness,
    pub received_msg: DLogProof<GE>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: FE,
    pub r: FE,
}

impl KeyGenInit {
    pub fn new(group: &CLGroup) -> Self {
        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);

        // Generate cl keypair
        let mut cl_keypair = ClKeyPair::new(&group);
        let h_caret = cl_keypair.get_public_key().clone();
        cl_keypair.update_pk_exp_p();

        let new_class_group = update_class_group_by_p(group);

        // Precomputation: promise proof
        let cipher = PromiseCipher::encrypt(
            &new_class_group,
            cl_keypair.get_public_key(),
            keypair.get_secret_key(),
        );

        let promise_state = PromiseState {
            cipher: cipher.0,
            cl_pub_key: cl_keypair.cl_pub_key.clone(),
        };
        let promise_wit = PromiseWit {
            m: keypair.get_secret_key().clone(),
            r: cipher.1,
        };
        let promise_proof = PromiseProof::prove(&new_class_group, &promise_state, &promise_wit);

        Self {
            public_signing_key: ECPoint::generator(), // Compute later
            keypair,
            round_one_msg: dl_com_zk.commitments,
            round_two_msg: dl_com_zk.witness,
            cl_keypair,
            h_caret,
            promise_state,
            promise_proof,
            cl_group: new_class_group,
        }
    }

    pub fn get_class_group_pk(&self) -> (PK, PK, BinaryQF) {
        (
            self.h_caret.clone(),
            self.cl_keypair.get_public_key().clone(),
            self.cl_group.gq.clone(),
        )
    }

    // TBD: remove return value
    pub fn verify_and_get_next_msg(
        &self,
        dl_proof: &DLogProof<GE>,
    ) -> Result<CommWitness, MulEcdsaError> {
        // TBD: handle the error
        DLogProof::verify(dl_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        Ok(self.round_two_msg.clone())
    }

    // TBD: remove return value
    pub fn compute_public_key(&mut self, received_r_2: &GE) -> GE {
        self.public_signing_key = received_r_2 * self.keypair.get_secret_key();
        self.public_signing_key
    }

    pub fn get_promise_proof(&self) -> (PromiseState, PromiseProof) {
        (self.promise_state.clone(), self.promise_proof.clone())
    }
}

impl SignPhase {
    pub fn new(cl_group: CLGroup) -> Self {
        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);
        let received_msg = DLogProof {
            pk: GE::generator(),
            pk_t_rand_commitment: GE::generator(),
            challenge_response: FE::zero(),
        };

        Self {
            cl_group,
            keypair,
            round_one_msg: dl_com_zk.commitments,
            round_two_msg: dl_com_zk.witness,
            received_msg,
        }
    }

    pub fn set_received_msg(&mut self, msg: DLogProof<GE>) {
        self.received_msg = msg;
    }

    pub fn verify_and_get_next_msg(
        &self,
        dl_proof: &DLogProof<GE>,
    ) -> Result<CommWitness, MulEcdsaError> {
        // TBD: handle the error
        DLogProof::verify(dl_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        Ok(self.round_two_msg.clone())
    }

    pub fn compute_public_share_key(&self, received_r_2: &GE) -> GE {
        received_r_2 * self.keypair.get_secret_key()
    }

    pub fn sign(
        &self,
        cl_sk: &SK,
        partial_sig_c3: &CLCiphertext,
        ephemeral_public_share: &GE,
        secret_key: &FE,
        t_p: &FE,
    ) -> Result<Signature, MulEcdsaError> {
        let q = FE::q();
        let r_x: FE = ECScalar::from(
            &ephemeral_public_share
                .x_coor()
                .ok_or(MulEcdsaError::XcoorNone)?
                .mod_floor(&q),
        );
        let k1_inv = self.keypair.get_secret_key().invert();
        let x1_mul_tp = *secret_key * t_p;
        let s_tag = decrypt(&self.cl_group, cl_sk, &partial_sig_c3).sub(&x1_mul_tp.get_element());
        let s_tag_tag = k1_inv * s_tag;
        let s = cmp::min(s_tag_tag.to_big_int(), q - s_tag_tag.to_big_int());
        Ok(Signature {
            s: ECScalar::from(&s),
            r: r_x,
        })
    }

    pub fn verify(signature: &Signature, pubkey: &GE, message: &FE) -> Result<(), MulEcdsaError> {
        let q = FE::q();

        let s_inv_fe = signature.s.invert();
        let u1 = GE::generator() * (*message * s_inv_fe);
        let u2 = *pubkey * (signature.r * s_inv_fe);

        // second condition is against malleability
        let u1_plus_u2 = (u1 + u2)
            .x_coor()
            .ok_or(MulEcdsaError::XcoorNone)?
            .mod_floor(&q);

        if signature.r.to_big_int() == u1_plus_u2
            && signature.s.to_big_int() < FE::q() - signature.s.to_big_int()
        {
            Ok(())
        } else {
            return Err(MulEcdsaError::VrfyTwoECDSAFailed);
        }
    }
}
