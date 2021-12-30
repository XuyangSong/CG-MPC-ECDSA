use super::*;
use crate::mta::*;
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::class::GROUP_128;
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::traits::*;

#[test]
fn mta_test(){
     let a = FE::new_random();
     let b = FE::new_random();
     let cl_keypair = ClKeyPair::new(&GROUP_128);
     let mut mta_party_one = cl_based_mta::PartyOne::new(a);
     let mut mta_party_two = cl_based_mta::PartyTwo::new(b);
     let mta_first_round_msg = mta_party_one.generate_send_msg(&cl_keypair.cl_pub_key);
     let mta_second_round_msg = mta_party_two.receive_and_send_msg(mta_first_round_msg.0, mta_first_round_msg.1).unwrap();
     mta_party_one.handle_receive_msg(&cl_keypair.cl_priv_key, &mta_second_round_msg);
     assert_eq!(a*b, mta_party_two.t_a+mta_party_one.t_b);
}
#[test]
fn party_two_test() {
     //keygen bigin
    let mut party_one_keygen = party_one::KeyGen::new();
    let mut party_two_keygen = party_two::KeyGen::new();
    let party_one_first_round = party_one_keygen.generate_first_round_msg();
    let party_two_sec_round =
        party_two_keygen.get_msg_and_generate_second_round_msg(party_one_first_round);
    let party_one_third_round = party_one_keygen.get_msg_and_generate_third_roung_msg(party_two_sec_round);
    party_two_keygen
        .verify_third_roung_msg(&party_one_third_round.unwrap())
        .unwrap();
    let party_one_key = party_one_keygen.generate_key_result();
    let party_two_key = party_two_keygen.generate_key_result();
    println!("party_one_key = {:?}", party_one_key);
    println!("party_two_key = {:?}", party_two_key);

    //sign begin
    let party_one_key_string = serde_json::to_string(&party_one_key).unwrap();
    let party_two_key_string = serde_json::to_string(&party_two_key).unwrap();
    let message_str = "eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d".to_string();
    let mut party_one_sign = party_one::Sign::new(&party_one_key_string, &message_str).unwrap();
    let mut party_two_sign = party_two::Sign::new(&party_two_key_string, &message_str).unwrap();
    let party_two_nonce_com = party_two_sign.generate_nonce_com();
    party_one_sign.get_nonce_com(party_two_nonce_com);

    //mta begin;
    let cl_keypair = ClKeyPair::new(&GROUP_128);
    let mut mta_party_one = cl_based_mta::PartyOne::new(party_one_sign.reshared_keypair.secret_share);
    let mut mta_party_two = cl_based_mta::PartyTwo::new(party_two_sign.nonce_pair.secret_share);
    let mta_first_round_msg = mta_party_one.generate_send_msg(&cl_keypair.cl_pub_key);
    let mta_second_round_msg = mta_party_two.receive_and_send_msg(mta_first_round_msg.0, mta_first_round_msg.1).unwrap();
    mta_party_one.handle_receive_msg(&cl_keypair.cl_priv_key, &mta_second_round_msg);
    let mta_consistency_msg = party_one_sign.generate_mta_consistency(mta_party_one.t_b);

    party_two_sign.verify_generate_mta_consistency(mta_party_two.t_a, mta_consistency_msg).unwrap();

    let party_one_nonce_ke_msg = party_one_sign.generate_nonce_ke_msg();

    let party_two_nonce_ke_msg = party_two_sign.verify_send_nonce_ke_msg(&party_one_nonce_ke_msg).unwrap();

    party_one_sign.verify_nonce_ke_msg(&party_two_nonce_ke_msg).unwrap();

    let s_2 = party_two_sign.online_sign();
    
    let signature = party_one_sign.online_sign(s_2);
    println!("signature = {:?}", signature);
}


