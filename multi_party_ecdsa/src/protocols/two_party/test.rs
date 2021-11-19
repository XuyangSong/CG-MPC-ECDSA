use super::*;
use class_group::primitives::cl_dl_public_setup::CLGroup;
use curv::arithmetic::Converter;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use curv::BigInt;

#[test]
fn two_party_test() {
    let setup_start = time::now();
    let seed: BigInt = BigInt::from_hex(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();
    let cl_group = CLGroup::new_from_setup(&1827, &seed); //discriminant 1827
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
    let mut party_one_key_gen_init = party_one::KeyGenPhase::new();
    let party_one_init_round_one_msg = party_one_key_gen_init.round_one_msg.clone();

    // Party two round 1: send party_two_key_gen_init.msg
    let mut party_two_key_gen_init = party_two::KeyGenPhase::new();
    let party_two_key_gen_round_one_msg = party_two_key_gen_init.msg.clone();

    // Party one round 2: verify received msg and send round 2 msg
    let party_one_init_round_two_msg = party_one_key_gen_init
        .verify_and_get_next_msg(&party_two_key_gen_round_one_msg)
        .unwrap();
    party_one_key_gen_init.compute_public_key(&party_two_key_gen_round_one_msg.pk);

    // Party two round 2: verify received msg
    party_two::KeyGenPhase::verify_received_dl_com_zk(
        &party_one_init_round_one_msg,
        &party_one_init_round_two_msg,
    )
    .unwrap();
    // let party_two_share_key =

    // Party one: get class group pk and pk'
    let (h_caret, h, gp) = party_one_key_gen_init.get_class_group_pk();

    // Party two: verify class group pk and pk'
    party_two_key_gen_init
        .verify_class_group_pk(&h_caret, &h, &gp)
        .unwrap();

    // Party one: Generate promise proof
    let (state, proof) = party_one_key_gen_init.get_promise_proof();

    // Party two: verify promise protocol
    party_two_key_gen_init
        .verify_promise_proof(&state, &proof)
        .unwrap();
    party_two_key_gen_init.compute_public_key(&party_one_init_round_two_msg.get_public_key());

    let keygen_end = time::now();
    ////////// Start Signing /////////////////
    // creating the ephemeral private shares:
    let sign_message =
        Some("eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d".to_string());
    let sign_start = time::now();

    // Party one round 1: send party_one_key_gen_init.round_one_msg
    let party_one_keygen_result = party_one_key_gen_init
        .generate_result_json_string()
        .unwrap();
    let mut party_one_sign_new = party_one::SignPhase::new(&sign_message, false).unwrap();
    party_one_sign_new
        .load_keygen_result(&party_one_keygen_result)
        .unwrap();
    let party_one_sign_round_one_msg = party_one_sign_new.round_one_msg.clone();

    // Party two round 1: send party_two_key_gen_init.msg
    let party_two_keygen_result = party_two_key_gen_init
        .generate_result_json_string(&state)
        .unwrap();
    let mut party_two_sign_new = party_two::SignPhase::new(&sign_message, false).unwrap();
    party_two_sign_new
        .load_keygen_result(&party_two_keygen_result)
        .unwrap();
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

    // Party two: compute partial signature
    let ephemeral_public_share_2 =
        party_two_sign_new.compute_public_share_key(party_one_sign_round_two_msg.get_public_key());
    let (cipher, t_p) = party_two_sign_new.sign(&ephemeral_public_share_2).unwrap();

    // Party one: finish signature
    let ephemeral_public_share_1 =
        party_one_sign_new.compute_public_share_key(&party_two_sign_round_one_msg.pk);
    let signature = party_one_sign_new
        .sign(
            &cipher,
            &ephemeral_public_share_1,
            &t_p,
            party_one_sign_new.message,
        )
        .unwrap();

    let sign_end = time::now();

    println!("signature: {:?}", signature);

    println!(
        "keygen_duration:{:?},sign_duration:{:?}",
        keygen_end - keygen_start,
        sign_end - sign_start
    );
}

#[test]
fn online_offline_two_party() {
    let setup_start = time::now();
    let seed: BigInt = BigInt::from_hex(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();
    let cl_group = CLGroup::new_from_setup(&1827, &seed); //discriminant 1827
    let (_secret_key_test, _public_key_test) = cl_group.keygen(); //class group key generation
    let g_test: GE = GE::generator();
    let ecsk_test: FE = FE::new_random();
    let _h: GE = g_test.clone().scalar_mul(&ecsk_test.get_element()); // elegamal key generation
    assert!(cl_group.setup_verify(&seed).is_ok());
    let setup_end = time::now();
    println!("setup_duration:{:?}", setup_end - setup_start);

    // keygen starts
    let keygen_start = time::now();

    // Party one round 1: send party_one_key_gen_init.round_one_msg
    let mut party_one_key_gen_init = party_one::KeyGenPhase::new();
    let party_one_init_round_one_msg = party_one_key_gen_init.round_one_msg.clone();

    // Party two round 1: send party_two_key_gen_init.msg
    let mut party_two_key_gen_init = party_two::KeyGenPhase::new();
    let party_two_key_gen_round_one_msg = party_two_key_gen_init.msg.clone();

    // Party one round 2: verify received msg and send round 2 msg
    let party_one_init_round_two_msg = party_one_key_gen_init
        .verify_and_get_next_msg(&party_two_key_gen_round_one_msg)
        .unwrap();
    party_one_key_gen_init.compute_public_key(&party_two_key_gen_round_one_msg.pk);

    // Party two round 2: verify received msg
    party_two::KeyGenPhase::verify_received_dl_com_zk(
        &party_one_init_round_one_msg,
        &party_one_init_round_two_msg,
    )
    .unwrap();
    // let party_two_share_key =

    // Party one: get class group pk and pk'
    let (h_caret, h, gp) = party_one_key_gen_init.get_class_group_pk();

    // Party two: verify class group pk and pk'
    party_two_key_gen_init
        .verify_class_group_pk(&h_caret, &h, &gp)
        .unwrap();

    // Party one: Generate promise proof
    let (state, proof) = party_one_key_gen_init.get_promise_proof();

    // Party two: verify promise protocol
    party_two_key_gen_init
        .verify_promise_proof(&state, &proof)
        .unwrap();
    party_two_key_gen_init.compute_public_key(&party_one_init_round_two_msg.get_public_key());

    let keygen_end = time::now();

    ////////// Start Signing /////////////////
    // creating the ephemeral private shares:
    let sign_offline_start = time::now();

    // Party one round 1: send party_one_key_gen_init.round_one_msg
    let party_one_keygen_result = party_one_key_gen_init
        .generate_result_json_string()
        .unwrap();
    let mut party_one_sign_new = party_one::SignPhase::new(&None, true).unwrap();
    party_one_sign_new
        .load_keygen_result(&party_one_keygen_result)
        .unwrap();
    let party_one_sign_round_one_msg = party_one_sign_new.round_one_msg.clone();

    // Party two round 1: send party_two_key_gen_init.msg
    let party_two_keygen_result = party_two_key_gen_init
        .generate_result_json_string(&state)
        .unwrap();
    let mut party_two_sign_new =
        party_two::SignPhase::new(&None, true).unwrap();
    party_two_sign_new
    .load_keygen_result(&party_two_keygen_result)
    .unwrap();
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

    // Party two: compute partial signature
    let ephemeral_public_share_2 =
        party_two_sign_new.compute_public_share_key(party_one_sign_round_two_msg.get_public_key());
    let (c_2, t_p) = party_two_sign_new
        .sign(
            &ephemeral_public_share_2,
        )
        .unwrap();
    let ephemeral_public_share_1 =
    party_one_sign_new.compute_public_share_key(&party_two_sign_round_one_msg.pk);
    let sign_offline_end = time::now();

    let message_str = "eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d".to_string();
    party_one_sign_new.set_msg(message_str.clone()).unwrap();
    party_two_sign_new.set_msg(message_str).unwrap();

    let sign_online_start = time::now();

    let cipher = party_two_sign_new.online(&party_two_sign_new.message, &c_2).unwrap();
   
    // Party one: finish signature
    
    let signature = party_one_sign_new
        .sign(
            &cipher,
            &ephemeral_public_share_1,
            &t_p,
            party_one_sign_new.message,
        )
        .unwrap();
    let sign_online_end = time::now();
    println!("signature: {:?}", signature);
    println!(
        "keygen_duration:{:?}",
        keygen_end - keygen_start
    );
    println!(
        "sign_offline_duration:{:?}",
        sign_offline_end - sign_offline_start
    );
    println!(
        "sign_online_duration:{:?}",
        sign_online_end - sign_online_start
    );
}
