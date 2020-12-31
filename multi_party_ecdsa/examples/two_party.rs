extern crate time;
use class_group::primitives::cl_dl_public_setup::CLGroup;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::two_party::*;
use multi_party_ecdsa::utilities::hsmcl::HSMCL;

fn main() {
    // init class group, cl keypair and elegamal keypair:
    let setup_start = time::now();
    let seed: BigInt = str::parse(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();
    let cl_group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348
    let (_secret_key_test, _public_key_test) = cl_group.keygen(); //class group key generation
    let g_test: GE = GE::generator();
    let ecsk_test: FE = FE::new_random();
    let _h: GE = g_test.clone().scalar_mul(&ecsk_test.get_element()); // elegamal key generation
    assert!(cl_group.setup_verify(&seed).is_ok());
    let setup_end = time::now();
    println!("duration:{:?}", setup_end - setup_start);

    // keygen starts
    let keygen_start = time::now();

    // Party one round 1: send party_one_key_gen_init.round_one_msg
    let mut party_one_key_gen_init = party_one::KeyGenInit::new();
    let party_one_init_round_one_msg = party_one_key_gen_init.round_one_msg.clone();

    // Party two round 1: send party_two_key_gen_init.msg
    let party_two_key_gen_init = party_two::KeyGenInit::new();
    let party_two_key_gen_round_one_msg = party_two_key_gen_init.msg;

    // Party one round 2: verify received msg and send round 2 msg
    let party_one_init_round_two_msg = party_one_key_gen_init
        .verify_and_get_next_msg(&party_two_key_gen_round_one_msg)
        .unwrap();
    let party_one_share_key =
        party_one_key_gen_init.compute_public_key(&party_two_key_gen_round_one_msg.pk);

    // Party two round 2: verify received msg
    party_two::KeyGenInit::verify_received_dl_com_zk(
        &party_one_init_round_one_msg,
        &party_one_init_round_two_msg,
    )
    .unwrap();
    // let party_two_share_key =

    // TBD: Party one, Simulate CL check
    let q = FE::q();
    cl_group.gq.exp(&q);
    cl_group.gq.exp(&q);

    // Party one: Generate HSMCL
    let (hsmcl_private, hsmcl_public) = HSMCL::generate_keypair_and_encrypted_share_and_proof(
        &party_one_key_gen_init.keypair,
        &cl_group,
    );

    // TBD: Party one, Simulate CL check
    cl_group.gq.exp(&q);
    cl_group.gq.exp(&q);

    // Party two: verify HSMCL
    party_two::KeyGenInit::verify_setup_and_zkcldl_proof(
        &cl_group,
        &hsmcl_public,
        party_one_init_round_two_msg.get_public_key(),
    )
    .unwrap();

    let keygen_end = time::now();

    ////////// Start Signing /////////////////
    // creating the ephemeral private shares:
    let sign_start = time::now();

    // Party one round 1: send party_one_key_gen_init.round_one_msg
    let party_one_sign_new = party_one::SignPhase::new();
    let party_one_sign_round_one_msg = party_one_sign_new.round_one_msg.clone();

    // Party two round 1: send party_two_key_gen_init.msg
    let party_two_sign_new = party_two::SignPhase::new();
    let party_two_sign_round_one_msg = party_two_sign_new.msg.clone();

    // Party one round 2: verify received msg and send round 2 msg
    let party_one_sign_round_two_msg = party_one_sign_new
        .verify_and_get_next_msg(&party_two_sign_round_one_msg)
        .unwrap();

    // Party two round 2: verify received msg
    party_two::SignPhase::verify_received_dl_com_zk(
        &party_one_sign_round_one_msg,
        &party_one_sign_round_two_msg,
    )
    .unwrap();

    let sign_message = ECScalar::new_random();
    // Party two: compute partial signature
    let ephemeral_public_share_2 =
        party_two_sign_new.compute_public_share_key(party_one_sign_round_two_msg.get_public_key());
    let (last_msg, t_p) = party_two_sign_new.sign(
        &cl_group,
        &hsmcl_public,
        &ephemeral_public_share_2,
        party_two_key_gen_init.keypair.get_secret_key(),
        &sign_message,
    );

    // Party one: finish signature
    let ephemeral_public_share_1 =
        party_one_sign_new.compute_public_share_key(&party_two_sign_round_one_msg.pk);
    let signature = party_one_sign_new.sign(
        &cl_group,
        &hsmcl_private,
        &last_msg,
        &ephemeral_public_share_1,
        party_one_key_gen_init.keypair.get_secret_key(),
        &t_p,
    );

    let sign_end = time::now();

    party_one::SignPhase::verify(&signature, &party_one_share_key, &sign_message).unwrap();

    println!(
        "keygen_duration:{:?},sign_duration:{:?}",
        keygen_end - keygen_start,
        sign_end - sign_start
    );
}
