use curv::elliptic::curves::secp256_k1::{FE, GE};
use class_group::primitives::cl_dl_public_setup::*;
use class_group::primitives::cl_dl_public_setup::Ciphertext as CLCiphertext;
use curv::elliptic::curves::traits::*;
use curv::arithmetic::*;
use crate::utilities::class::GROUP_128;

#[derive(Clone, Debug)]
pub struct PartyOne {
     pub b: FE,
     pub t_b: FE,
}

#[derive(Clone, Debug)]
pub struct PartyTwo {
     pub a: FE,
     pub t_a: FE
}

#[derive(Clone, Debug)]
pub struct Statement {
     pk: PK,
     ciphertext: Ciphertext,
     public: GE
}

impl PartyOne {
     pub fn new(b: FE) -> Self {
          Self {
               b,
               t_b: FE::new_random(),
          }
     }

     pub fn generate_send_msg(&self, cl_pk: &PK) -> (CLDLProof, Statement) {
          let b_pub = GE::generator() * self.b;
          let (c_b, cl_dl_proof) = verifiably_encrypt(&GROUP_128, cl_pk, (&self.b, &b_pub));
          let statement = Statement {
               pk: (*cl_pk).clone(),
               ciphertext: c_b,
               public: b_pub,
          };
          (cl_dl_proof, statement)
     }

     pub fn handle_receive_msg(&mut self, cl_sk: &SK, c_a: &Ciphertext) {
          let beta_tag_bigint = decrypt(&GROUP_128, cl_sk, c_a).to_big_int();
          let beta: FE = ECScalar::from(&beta_tag_bigint.mod_floor(&FE::q()));
          self.t_b = beta;
     }
}

impl PartyTwo {
     pub fn new(a: FE) -> Self {
          Self {
               a,
               t_a: FE::new_random()
          }
     }

     pub fn receive_and_send_msg(&mut self, proof_cl: CLDLProof, statement: Statement) -> Result<CLCiphertext, String>{
          let alpha_tag = FE::new_random();
          let alpha = FE::zero().sub(&alpha_tag.get_element());
          self.t_a = alpha;

          //verify cl-encryption dl proof
          proof_cl.verify(&GROUP_128, &statement.pk, &statement.ciphertext, &statement.public).map_err(|_| "verify cl encryption dl proof failed")?;
          let encrypted_alpha_tag = encrypt(&GROUP_128, &statement.pk, &alpha_tag);
          let a_scal_c_b = eval_scal(&statement.ciphertext, &self.a.to_big_int());
          let c_a = eval_sum(&a_scal_c_b, &encrypted_alpha_tag.0);
          return Ok(c_a)
     }
}