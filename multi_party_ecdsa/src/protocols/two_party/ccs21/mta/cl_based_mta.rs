use crate::utilities::cl_dl_proof::*;
use crate::utilities::class_group::*;
use crate::utilities::clkeypair::*;
use curv::arithmetic::*;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;

#[derive(Clone, Debug)]
pub struct PartyOne {
    pub b: FE,
    pub t_b: FE,
    pub cl_keypair: ClKeyPair,
}

#[derive(Clone, Debug)]
pub struct PartyTwo {
    pub a: FE,
    pub t_a: FE,
}

impl PartyOne {
    pub fn new(b: FE) -> Self {
        let cl_keypair = ClKeyPair::new(&GROUP_128);
        Self {
            b,
            t_b: FE::new_random(),
            cl_keypair,
        }
    }

    pub fn generate_send_msg(&self, cl_pk: &PK) -> (CLDLProof, CLDLState) {
        let b_pub = GE::generator() * self.b;
        let (c_b, r) = CLGroup::encrypt(&GROUP_128, cl_pk, &self.b);
        let witness = CLDLWit { dl_priv: self.b, r };
        let statement = CLDLState {
            cipher: c_b,
            cl_pub_key: (*cl_pk).clone(),
            dl_pub: b_pub,
        };
        let cl_dl_proof = CLDLProof::prove(&GROUP_128, witness, statement.clone());
        (cl_dl_proof, statement)
    }

    pub fn handle_receive_msg(&mut self, cl_sk: &SK, c_a: &Ciphertext) {
        let beta_tag_bigint = CLGroup::decrypt(&GROUP_128, cl_sk, c_a).to_big_int();
        let beta: FE = ECScalar::from(&beta_tag_bigint.mod_floor(&FE::q()));
        self.t_b = beta;
    }
}

impl PartyTwo {
    pub fn new(a: FE) -> Self {
        Self {
            a,
            t_a: FE::new_random(),
        }
    }

    pub fn receive_and_send_msg(
        &mut self,
        proof_cl: CLDLProof,
        statement: CLDLState,
    ) -> Result<Ciphertext, String> {
        let alpha_tag = FE::new_random();
        let alpha = FE::zero().sub(&alpha_tag.get_element());
        self.t_a = alpha;

        //verify cl-encryption dl proof
        proof_cl
            .verify(&GROUP_128, statement.clone())
            .map_err(|_| "verify cl encryption dl proof failed")?;
        let encrypted_alpha_tag = CLGroup::encrypt(&GROUP_128, &statement.cl_pub_key, &alpha_tag);
        let a_scal_c_b = CLGroup::eval_scal(&statement.cipher, into_mpz(&self.a));
        let c_a = CLGroup::eval_sum(&a_scal_c_b, &encrypted_alpha_tag.0);
        return Ok(c_a);
    }
}
