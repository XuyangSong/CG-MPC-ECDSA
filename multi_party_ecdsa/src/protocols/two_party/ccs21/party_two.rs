use crate::protocols::two_party::ccs21::party_one::{MtaConsistencyMsg, NonceKEMsg};
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use curv::arithmetic::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use crate::utilities::error::MulEcdsaError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGen {
    pub keypair: EcKeyPair,
    pub dl_com_zk_com_rec: DLCommitments,
    pub dl_com_zk_wit_rec: Option<CommWitness>,
    pub dlog_proof: DLogProof<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenResult {
    pub keypair: EcKeyPair,
    pub public_signing_key: GE,
    pub other_public_key: GE,
}

pub struct KeyGenSecRoungMsg {
    pub public_share: GE,
    pub dl_proof: DLogProof<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sign {
    pub nonce_pair: EcKeyPair,
    pub dl_com_zk_com: DLComZK,
    pub keygen_result: KeyGenResult,
    pub message: FE,
    pub reshared_secret_share: FE,
    pub r1_rec: FE,
    pub r_x: FE,
}

impl KeyGen {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let dlog_proof = DLogProof::<GE>::prove(&keypair.secret_share);
        Self {
            keypair,
            dl_com_zk_com_rec: DLCommitments::default(),
            dl_com_zk_wit_rec: None,
            dlog_proof,
        }
    }

    pub fn get_msg_and_generate_second_round_msg(
        &mut self,
        dl_com_zk_com_rec: DLCommitments,
    ) -> KeyGenSecRoungMsg {
        self.dl_com_zk_com_rec = dl_com_zk_com_rec;
        KeyGenSecRoungMsg {
            public_share: self.keypair.public_share,
            dl_proof: self.dlog_proof.clone(),
        }
    }

    pub fn verify_third_roung_msg(&mut self, dl_com_zk_wit: &CommWitness) -> Result<(), MulEcdsaError> {
        DLComZK::verify(&self.dl_com_zk_com_rec, dl_com_zk_wit)?;
        DLogProof::verify(&dl_com_zk_wit.d_log_proof)
            .map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        self.dl_com_zk_wit_rec = Some(dl_com_zk_wit.clone());
        Ok(())
    }

    pub fn generate_key_result(&self) -> KeyGenResult {
        KeyGenResult {
            keypair: self.keypair.clone(),
            public_signing_key: self.keypair.public_share
                + self.dl_com_zk_wit_rec.clone().unwrap().public_share,
            other_public_key: self.dl_com_zk_wit_rec.clone().unwrap().public_share
        }
    }
}

impl Sign {
    pub fn new(keygen_result_string: &String, message_str: &String) -> Result<Self, String> {
        let nonce_pair = EcKeyPair::new();
        let dl_com_zk_com = DLComZK::new(&nonce_pair);
        let keygen_result: KeyGenResult = serde_json::from_str(keygen_result_string).unwrap();
        // Process the message to sign
        let message_bigint = BigInt::from_hex(&message_str).map_err(|_| "From hex failed")?;
        let message = ECScalar::from(&message_bigint);
        let ret = Self {
            nonce_pair,
            dl_com_zk_com: dl_com_zk_com,
            keygen_result,
            message,
            reshared_secret_share: FE::new_random(),
            r1_rec: FE::new_random(),
            r_x: FE::new_random(),
        };
        Ok(ret)
    }

    pub fn generate_nonce_com(&self) -> DLCommitments {
        self.dl_com_zk_com.commitments.clone()
    }

    pub fn verify_generate_mta_consistency(
        &mut self,
        t_b: FE,
        mta_consis_rec: MtaConsistencyMsg,
    ) -> Result<(), String> {
        let base: GE = ECPoint::generator();
        if base * (t_b + mta_consis_rec.cc)
            != (mta_consis_rec.reshared_public_share
                * (mta_consis_rec.r1 + self.nonce_pair.secret_share))
                .sub_point(&self.keygen_result.other_public_key.get_element())
        {
            return Err("Verify Mta Consistency Failed".to_string());
        }
        let reshared_secret_share = self
            .keygen_result
            .keypair
            .secret_share
            .sub(&t_b.get_element())
            .sub(&mta_consis_rec.cc.get_element());
        self.reshared_secret_share = reshared_secret_share;
        self.r1_rec = mta_consis_rec.r1;
        Ok(())
    }

    pub fn verify_send_nonce_ke_msg(&mut self, nonce_ke_rec: &NonceKEMsg) -> Result<CommWitness, String> {
        DLogProof::verify(&nonce_ke_rec.dl_proof).map_err(|_| "Verify DLog failed".to_string())?;
        let r = nonce_ke_rec.nonce_public_key * (self.r1_rec + self.nonce_pair.secret_share);
        self.r_x = ECScalar::from(&r.x_coor().ok_or("get x coor failed")?.mod_floor(&FE::q()));
        Ok(self.dl_com_zk_com.witness.clone())
    }

    pub fn online_sign(&self) -> FE {
        let s_2 = (self.r1_rec + self.nonce_pair.secret_share).invert()
            * (self.message + self.r_x * self.reshared_secret_share);
        return s_2;
    }
}
