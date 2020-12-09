use super::eckeypair::EcKeyPair;
use super::error::ProofError;
use super::SECURITY_BITS;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, GE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlogCommitment {
    pub commitment: BigInt,
    pub open: DlogCommitmentOpen,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlogCommitmentOpen {
    pub blind_factor: BigInt,
    pub public_share: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLComZK {
    pub commitments: DLCommitments,
    pub witness: CommWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLCommitments {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}

impl DlogCommitment {
    pub fn new(public_share: &GE) -> Self {
        let blind_factor = BigInt::sample(SECURITY_BITS);
        let commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &blind_factor,
        );

        Self {
            commitment,
            open: DlogCommitmentOpen {
                blind_factor,
                public_share: public_share.clone(),
            },
        }
    }

    pub fn verify(&self) -> Result<(), ProofError> {
        if HashCommitment::create_commitment_with_user_defined_randomness(
            &self.open.public_share.bytes_compressed_to_big_int(),
            &self.open.blind_factor,
        ) != self.commitment
        {
            return Err(ProofError);
        }

        Ok(())
    }

    pub fn verify_dlog(commitment: &BigInt, open: &DlogCommitmentOpen) -> Result<(), ProofError> {
        if HashCommitment::create_commitment_with_user_defined_randomness(
            &open.public_share.bytes_compressed_to_big_int(),
            &open.blind_factor,
        ) != *commitment
        {
            return Err(ProofError);
        }

        Ok(())
    }

    pub fn get_public_share(&self) -> GE {
        self.open.public_share
    }
}

impl DLComZK {
    pub fn new(keypair: &EcKeyPair) -> Self {
        let d_log_proof = DLogProof::prove(keypair.get_secret_key());
        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &keypair.get_public_key().bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
        );

        let commitments = DLCommitments {
            pk_commitment,
            zk_pok_commitment,
        };

        let witness = CommWitness {
            pk_commitment_blind_factor,
            zk_pok_blind_factor,
            public_share: keypair.get_public_key().clone(),
            d_log_proof,
        };

        Self {
            commitments,
            witness,
        }
    }

    pub fn verify_commitments_and_dlog_proof(&self) -> Result<(), ProofError> {
        // Verify the commitment of DL
        if HashCommitment::create_commitment_with_user_defined_randomness(
            &self.witness.public_share.bytes_compressed_to_big_int(),
            &self.witness.pk_commitment_blind_factor,
        ) != self.commitments.pk_commitment
        {
            return Err(ProofError);
        }

        // Verify the commitment of proof
        if HashCommitment::create_commitment_with_user_defined_randomness(
            &self
                .witness
                .d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &self.witness.zk_pok_blind_factor,
        ) != self.commitments.zk_pok_commitment
        {
            return Err(ProofError);
        }

        // Verify DL proof
        // TBD: handle the error
        DLogProof::verify(&self.witness.d_log_proof).unwrap();

        Ok(())
    }

    pub fn verify(commitment: &DLCommitments, witness: &CommWitness) -> Result<(), ProofError> {
        // Verify the commitment of DL
        if HashCommitment::create_commitment_with_user_defined_randomness(
            &witness.public_share.bytes_compressed_to_big_int(),
            &witness.pk_commitment_blind_factor,
        ) != commitment.pk_commitment
        {
            return Err(ProofError);
        }

        // Verify the commitment of proof
        if HashCommitment::create_commitment_with_user_defined_randomness(
            &witness
                .d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &witness.zk_pok_blind_factor,
        ) != commitment.zk_pok_commitment
        {
            return Err(ProofError);
        }

        // Verify DL proof
        // TBD: handle the error
        DLogProof::verify(&witness.d_log_proof).unwrap();

        Ok(())
    }

    pub fn get_public_share(&self) -> GE {
        self.witness.public_share
    }
}

impl CommWitness {
    pub fn get_public_key(&self) -> &GE {
        &self.public_share
    }
}

#[test]
fn dl_com_zk_test() {
    let keypair = EcKeyPair::new();

    let dl_com_zk = DLComZK::new(&keypair);

    dl_com_zk.verify_commitments_and_dlog_proof().unwrap();
}
