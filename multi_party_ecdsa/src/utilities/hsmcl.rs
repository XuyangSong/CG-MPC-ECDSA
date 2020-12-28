#![allow(non_upper_case_globals)]

use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use serde::{Deserialize, Serialize};

use super::eckeypair::EcKeyPair;
use super::error::ProofError;
use super::promise_sigma::PromiseCipher;
use super::SECURITY_PARAMETER;
use class_group::primitives::cl_dl_public_setup::{encrypt, CLGroup, PK, SK};
use class_group::BinaryQF;
use curv::arithmetic::traits::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct HSMCL {
    pub public: PK,
    pub secret: SK,
    pub ec_base: GE,
    pub ec_public: GE,
    pub encrypted_share: PromiseCipher,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HSMCLPublic {
    pub cl_pub_key: PK,
    pub ec_pub_base: GE,
    pub ec_pub_key: GE,
    pub proof: EGCLDLProof,
    pub encrypted_share: PromiseCipher,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Firstcomit {
    pub t1: BinaryQF,
    pub t2: BinaryQF,
    pub t3: GE,
    pub t4: GE,
    pub t: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U1U2U3 {
    pub u1: BigInt,
    pub u2: BigInt,
    pub u3: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EGCLDLProof {
    first_message: Firstcomit,
    second_message: U1U2U3,
}

impl EGCLDLProof {
    fn prove(
        group: &CLGroup,
        witness: (&FE, &SK, &FE),
        statement: (&PK, &PromiseCipher, &GE, &GE, &GE),
    ) -> Self {
        // unsafe { pari_init(10000000, 2) };
        let (x, r1, r2) = witness;
        let (public_key, ciphertext, big_x, g, h) = statement;

        let s1 = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)),
        );
        let s_fe: FE = FE::new_random();
        let s = s_fe.to_big_int();
        let s2: FE = FE::new_random();
        let fr = BinaryQF::expo_f(&FE::q(), &group.delta_q, &s);
        let pkr1 = public_key.0.exp(&s1);
        let t2 = fr.compose(&pkr1).reduce();
        let t = GE::generator() * s_fe;
        let t1 = group.gq.exp(&s1);
        let t3 = g * &s2;
        let t41 = h * &s2;
        let t42 = g * &s_fe;
        let t4 = t41 + t42;
        let firstmessage = Firstcomit { t1, t2, t3, t4, t };

        let k = Self::challenge(public_key, &firstmessage, ciphertext, big_x);

        let u1 = s1 + &k * &r1.0;
        let u2 = BigInt::mod_add(&s, &(&k * x.to_big_int()), &FE::q());
        let u31 = BigInt::mod_add(&s2.to_big_int(), &(&k * r2.to_big_int()), &FE::q());
        let u3: FE = ECScalar::from(&u31);
        let secondmessage = U1U2U3 { u1, u2, u3 };

        Self {
            first_message: firstmessage,
            second_message: secondmessage,
        }
    }

    /// Compute the Fiat-Shamir challenge for the proof.
    fn challenge(
        public_key: &PK,
        t: &Firstcomit,
        ciphertext: &PromiseCipher,
        big_x: &GE,
    ) -> BigInt {
        // use curv::arithmetic::traits::Converter;
        let hash256 = HSha256::create_hash(&[
            // hash the statement i.e. the discrete log of Q is encrypted in (c1,c2) under encryption key h.
            &big_x.bytes_compressed_to_big_int(),
            &BigInt::from(ciphertext.c1.to_bytes().as_ref()),
            &BigInt::from(ciphertext.c2.to_bytes().as_ref()),
            &BigInt::from(public_key.0.to_bytes().as_ref()),
            // hash Sigma protocol commitments
            &BigInt::from(t.t1.to_bytes().as_ref()),
            &BigInt::from(t.t2.to_bytes().as_ref()),
            &t.t.bytes_compressed_to_big_int(),
        ]);

        let hash128 = &BigInt::to_vec(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from(hash128)
    }

    pub fn verify(
        &self,
        group: &CLGroup,
        public_key: &PK,
        ciphertext: &PromiseCipher,
        g: &GE,
        h: &GE,
        big_x: &GE,
    ) -> Result<(), ProofError> {
        // unsafe { pari_init(10000000, 2) };
        let mut flag = true;

        // reconstruct k
        let k = Self::challenge(public_key, &self.first_message, ciphertext, big_x);

        let sample_size = &group.stilde
            * (BigInt::from(2).pow(40))
            * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
            * (BigInt::from(2).pow(40) + BigInt::one());

        //length test u1:
        if &self.second_message.u1 > &sample_size || &self.second_message.u1 < &BigInt::zero() {
            flag = false;
        }
        // length test u2:
        if &self.second_message.u2 > &FE::q() || &self.second_message.u2 < &BigInt::zero() {
            flag = false;
        }

        let c1k = ciphertext.c1.exp(&k);
        let t1c1k = self.first_message.t1.compose(&c1k).reduce();
        let gqu1 = group.gq.exp(&&self.second_message.u1);
        if t1c1k != gqu1 {
            flag = false;
        };

        let k_bias_fe: FE = ECScalar::from(&(k.clone() + BigInt::one()));
        let gg = GE::generator();
        let t2kq = (self.first_message.t + big_x * &k_bias_fe).sub_point(&big_x.get_element());
        let u2p = &gg * &ECScalar::from(&self.second_message.u2);
        if t2kq != u2p {
            flag = false;
        }
        let c3k = (ciphertext.c3 * k_bias_fe).sub_point(&ciphertext.c3.get_element());
        let t3c3k = self.first_message.t3 + &c3k;
        let ggu3 = &gg * &self.second_message.u3;
        if t3c3k != ggu3 {
            flag = false;
        }
        let k_fe: FE = ECScalar::from(&k);
        let c4k = ciphertext.c4 * &k_fe;
        let t4c4k = self.first_message.t4 + &c4k;
        let hu3 = *&h * &self.second_message.u3;
        let u2 = &self.second_message.u2;
        let u2_fe: FE = ECScalar::from(&u2);
        let gu2 = *&g * &u2_fe;
        let hu3gu2 = &hu3 + &gu2;
        if t4c4k != hu3gu2 {
            flag = false;
        }

        let pku1 = public_key.0.exp(&self.second_message.u1);
        let fu2 = BinaryQF::expo_f(&FE::q(), &group.delta_q, &self.second_message.u2);
        let c2k = ciphertext.c2.exp(&k);
        let t2c2k = self.first_message.t2.compose(&c2k).reduce();
        let pku1fu2 = pku1.compose(&fu2).reduce();
        if t2c2k != pku1fu2 {
            flag = false;
        }
        match flag {
            true => Ok(()),
            false => Err(ProofError),
        }
    }
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
        let (ciphertext, proof) = Self::verifiably_encrypt(
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

    fn verifiably_encrypt(
        group: &CLGroup,
        public_key: &PK,
        dl_pair: (&FE, &GE),
        ec_pair: (&GE, &GE),
    ) -> (PromiseCipher, EGCLDLProof) {
        let (x, big_x) = dl_pair;
        let (g, h) = ec_pair;
        let (ciphertext1, r1) = encrypt(group, public_key, x);
        let r2: FE = ECScalar::new_random();
        let gr = g * &r2;
        let _hr = h * &r2;
        let mg = g * x;
        let (c3, c4) = (gr, _hr + mg);
        let hpscipher = PromiseCipher {
            c1: ciphertext1.c1.clone(),
            c2: ciphertext1.c2.clone(),
            c3,
            c4,
        };

        let proof =
            EGCLDLProof::prove(group, (&x, &r1, &r2), (public_key, &hpscipher, big_x, g, h));
        (hpscipher, proof)
    }
}
