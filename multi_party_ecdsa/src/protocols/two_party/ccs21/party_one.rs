use crate::protocols::two_party::ccs21::party_two::KeyGenSecRoungMsg;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::signature::*;
use curv::arithmetic::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use serde::{Deserialize, Serialize};
use std::cmp;
use crate::utilities::error::MulEcdsaError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGen {
    pub keypair: EcKeyPair,
    pub dl_com_zk_com: DLCommitments,
    pub dl_com_zk_wit: CommWitness,
    pub public_share_rec: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenResult {
    pub keypair: EcKeyPair,
    pub public_signing_key: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sign {
    pub dl_com_zk_com_rec: DLCommitments,
    pub reshared_keypair: EcKeyPair,
    pub keygen_result: KeyGenResult,
    pub nonce_pair: EcKeyPair,
    pub r1: FE,
    pub r_x: FE,
    pub message: FE,
    pub dl_proof: DLogProof<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaConsistencyMsg {
    pub reshared_public_share: GE,
    pub r1: FE,
    pub cc: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceKEMsg {
    pub nonce_public_key: GE,
    pub dl_proof: DLogProof<GE>,
}

impl KeyGen {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);
        Self {
            keypair,
            dl_com_zk_com: dl_com_zk.commitments,
            dl_com_zk_wit: dl_com_zk.witness,
            public_share_rec: GE::random_point(),
        }
    }

    pub fn generate_first_round_msg(&self) -> DLCommitments {
        self.dl_com_zk_com.clone()
    }

    pub fn get_msg_and_generate_third_roung_msg(
        &mut self,
        received_msg: KeyGenSecRoungMsg,
    ) -> Result<CommWitness, String> {
        DLogProof::verify(&received_msg.dl_proof).map_err(|_| "Verify DLog failed".to_string())?;
        self.public_share_rec = received_msg.public_share;
        Ok(self.dl_com_zk_wit.clone())
    }

    pub fn generate_key_result(&self) -> KeyGenResult {
        KeyGenResult {
            keypair: self.keypair.clone(),
            public_signing_key: self.public_share_rec + self.keypair.public_share,
        }
    }
}

impl Sign {
    pub fn new(keygen_result_string: &String, message_str: &String) -> Result<Self, String> {
        let reshared_keypair: EcKeyPair = EcKeyPair::new();
        let keygen_result: KeyGenResult = serde_json::from_str(keygen_result_string).unwrap();
        // Process the message to sign
        let message_bigint = BigInt::from_hex(&message_str).map_err(|_| "From hex failed")?;
        let message = ECScalar::from(&message_bigint);
        let nonce_pair = EcKeyPair::new();
        let dl_proof = DLogProof::<GE>::prove(&nonce_pair.secret_share);
        let ret = Self {
            dl_com_zk_com_rec: DLCommitments::default(),
            reshared_keypair,
            keygen_result,
            nonce_pair,
            r1: ECScalar::new_random(),
            r_x: ECScalar::new_random(),
            message,
            dl_proof,
        };
        Ok(ret)
    }

    pub fn get_nonce_com(&mut self, dl_com_zk_com_rec: DLCommitments) {
        self.dl_com_zk_com_rec = dl_com_zk_com_rec;
    }

    pub fn generate_mta_consistency(&self, t_a: FE) -> MtaConsistencyMsg {
        let cc: FE = (t_a
            + self
                .reshared_keypair
                .secret_share
                .mul(&self.r1.get_element()))
                .sub(&self.keygen_result.keypair.secret_share.get_element());
        MtaConsistencyMsg {
            reshared_public_share: self.reshared_keypair.public_share,
            r1: self.r1,
            cc,
        }
    }

    pub fn generate_nonce_ke_msg(&mut self) -> NonceKEMsg {
        NonceKEMsg {
            nonce_public_key: self.nonce_pair.public_share,
            dl_proof: self.dl_proof.clone(),
        }
    }

    pub fn verify_nonce_ke_msg(&mut self, nonce_ke_rec: &CommWitness) -> Result<(), MulEcdsaError> {
        DLComZK::verify(&self.dl_com_zk_com_rec, nonce_ke_rec)?;
        DLogProof::verify(&nonce_ke_rec.d_log_proof)
            .map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        let base: GE = ECPoint::generator();
        let r = nonce_ke_rec.public_share * self.nonce_pair.secret_share
            + base * self.nonce_pair.secret_share * self.r1;
        self.r_x = ECScalar::from(&r.x_coor().ok_or(MulEcdsaError::XcoorNone)?.mod_floor(&FE::q()));
        Ok(())
    }

    pub fn online_sign(&self, s2_rec: FE) -> Result<Signature, MulEcdsaError> {
        let s_tag = self.nonce_pair.secret_share.invert()
            * (s2_rec + self.r_x * self.reshared_keypair.secret_share);
        let s = cmp::min(s_tag.to_big_int(), FE::q() - s_tag.to_big_int());
        let signature = Signature { r: self.r_x, s: ECScalar::from(&s) };
        signature.verify(&self.keygen_result.public_signing_key, &self.message)?;
        return Ok(signature);
    }
}
