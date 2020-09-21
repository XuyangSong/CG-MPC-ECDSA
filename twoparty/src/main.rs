extern crate time;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::{FE, GE};
use twoparty::protocols::eccl_setup::CLGroup;
use twoparty::protocols::*;
fn main() {
    // init class group, cl keypair and elegamal keypair:
    let setup_start = time::now();
    let seed: BigInt = str::parse(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();
    let cl_group_test = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348
    let (_secret_key_test, _public_key_test) = cl_group_test.keygen(); //class group key generation
    let g_test: GE = GE::generator();
    let ecsk_test: FE = FE::new_random();
    let _h: GE = g_test.clone().scalar_mul(&ecsk_test.get_element()); // elegamal key generation
    assert!(cl_group_test.setup_verify(&seed).is_ok());
    let setup_end = time::now();
    println!("duration:{:?}", setup_end - setup_start);
    //keygen starts
    let keygen_start = time::now();
    let (_party_one_private_share_gen, comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (_party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();

    // TBD: Party1: Verify X_2 and DLproof from party2.

    // TBD: Party2: Verify commitment and proof from party1.

    //pi (nothing up my sleeve)

    let (party_one_hsmcl, hsmcl_public) =
        party_one::HSMCL::generate_keypair_and_encrypted_share_and_proof(
            &ec_key_pair_party1,
            &seed,
        );

    let party1_private =
        party_one::Party1Private::set_private_key(&ec_key_pair_party1, &party_one_hsmcl);

    let party_two_hsmcl_pub = party_two::Party2Public::verify_setup_and_zkcldl_proof(
        &hsmcl_public,
        &seed,
        &comm_witness.public_share,
    )
    .expect("proof error");

    let keygen_end = time::now();

    ////////// Start Signing /////////////////
    // creating the ephemeral private shares:
    let sign_start = time::now();

    // TBD: Which parth should send the first msg? either is ok?
    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();

    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();

    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");

    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
    let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
    // TBD: use longer message, the same size as security bits. Or make a hash.
    let message = BigInt::from(1234);

    let partial_sig = party_two::PartialSig::compute(
        party_two_hsmcl_pub,
        &party2_private,
        &eph_ec_key_pair_party2,
        &eph_party_one_first_message.public_share,
        &message,
    );

    let _signature = party_one::Signature::compute(
        &party_one_hsmcl,
        &party1_private,
        partial_sig.c3,
        &eph_ec_key_pair_party1,
        &eph_party_two_second_message.comm_witness.public_share,
    );
    let sign_end = time::now();
    println!(
        "keygen_duration:{:?},sign_duration:{:?}",
        keygen_end - keygen_start,
        sign_end - sign_start
    );

    // TBD: Add signature verify.
}
