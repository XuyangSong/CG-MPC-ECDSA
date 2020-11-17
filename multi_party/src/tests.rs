use crate::party_i::*;
use cg_ecdsa_core::{CLGroup, DLComZK, Signature};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE};

fn keygen_t_n_parties(params: &Parameters) -> (Vec<KeyGen>, VerifiableSS) {
    let seed: BigInt = str::parse(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
    ).unwrap();
    let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

    // Key Gen Phase 1
    let key_gen_vec = (0..params.share_count)
        .map(|i| KeyGen::phase_one_init(&group, i, params.clone()))
        .collect::<Vec<KeyGen>>();
    let mut my_key_gen = key_gen_vec[0].clone();

    // Key Gen Phase 2
    let dl_com_zk_vec = key_gen_vec
        .iter()
        .map(|key_gen| key_gen.phase_two_generate_dl_com_zk())
        .collect::<Vec<_>>();
    // let my_dl_com_zk = dl_com_zk_vec[0].clone();
    let q_vec = dl_com_zk_vec
        .iter()
        .skip(1)
        .map(|k| k.get_public_share())
        .collect::<Vec<_>>();

    // Key Gen Phase 3
    let (_, received_dl_com_zk) = dl_com_zk_vec.split_at(1);
    my_key_gen
        .phase_three_verify_dl_com_zk_and_generate_signing_key(&received_dl_com_zk.to_vec())
        .unwrap();

    // Key Gen Phase 4
    let vss_vec = key_gen_vec
        .iter()
        .skip(1)
        .map(|k| k.phase_four_generate_vss())
        .collect::<Vec<_>>();
    let received_vss_vec = vss_vec.iter().map(|k| &k.0).collect::<Vec<_>>();
    let received_secret_shares_vec = vss_vec.iter().map(|k| k.1[0]).collect::<Vec<_>>();

    // Key Gen Phase 5
    let dl_log_proof = my_key_gen
        .phase_five_verify_vss_and_generate_pok_dlog(
            &q_vec,
            &received_secret_shares_vec,
            &received_vss_vec,
        )
        .unwrap();

    // Key Gen Phase 6
    let dlog_proofs: Vec<DLogProof> = vec![dl_log_proof.clone(); params.share_count - 1];
    my_key_gen
        .phase_six_verify_dlog_proof(&dlog_proofs)
        .unwrap();

    // test vss


    (key_gen_vec, vss_vec[0].0.clone())
}

fn test_sign(params: &Parameters, key_gen_vec: &Vec<KeyGen>, vss_scheme: &VerifiableSS) {
    let seed: BigInt = str::parse(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
    ).unwrap();
    let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

    // Sign Init
    let party_num = key_gen_vec.len();
    let t = params.threshold as usize;
    assert!(party_num > t);

    let subset = (0..party_num)
        .map(|i| key_gen_vec[i].party_index)
        .collect::<Vec<_>>();

    let sign_vec = (0..party_num)
        .map(|i| {
            SignPhase::init(
                key_gen_vec[i].party_index,
                params.clone(),
                vss_scheme,
                &subset,
                &key_gen_vec[i].share_private_key,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    // let my_sign = sign_vec[0].clone();

    // Sign phase 1
    let phase_one_result_vec = (0..party_num)
        .map(|i| {
            SignPhase::phase_one_generate_promise_sigma_and_com(
                &group,
                &key_gen_vec[i].cl_keypair,
                &key_gen_vec[i].ec_keypair,
            )
        })
        .collect::<Vec<_>>();
    let phase_one_msg_vec = (0..party_num)
        .map(|i| phase_one_result_vec[i].0.clone())
        .collect::<Vec<_>>();
    // Sign phase 2
    let phase_two_result_vec = (0..party_num)
        .map(|i| {
            sign_vec[i].phase_two_generate_homo_cipher(
                &group,
                &phase_one_result_vec[i].2,
                &sign_vec[i].omega,
                &phase_one_msg_vec,
            )
        })
        .collect::<Vec<_>>();
    let mut phase_three_msg_vec: Vec<SignPhaseThreeMsg> = Vec::with_capacity(party_num);
    let mut sigma_vec: Vec<FE> = Vec::with_capacity(party_num);
    for index in 0..party_num {
        let phase_two_msg_vec = phase_two_result_vec
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if i != index {
                    Some(e.0[index].clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let msg = SignPhase::phase_two_decrypt_and_verify(
            &group,
            key_gen_vec[index].cl_keypair.get_secret_key(),
            &phase_one_result_vec[index].1,
            &phase_one_result_vec[index].2,
            &sign_vec[index].omega,
            &phase_two_result_vec[index].1,
            &phase_two_msg_vec,
        );
        phase_three_msg_vec.push(msg.0);
        sigma_vec.push(msg.1);
    }

    // Sign phase 3
    let delta_sum = SignPhase::phase_two_compute_delta_sum(&phase_three_msg_vec);

    // Sign phase 4
    let message: FE = ECScalar::new_random();
    let dl_com_zk_vec = (0..party_num)
        .map(|i| DLComZK {
            commitments: phase_one_result_vec[i].0.commitment.clone(),
            witness: phase_one_result_vec[i].3.witness.clone(),
        })
        .collect::<Vec<_>>();
    // let phase_four_result_vec = (0..party_num)
    //     .map(|i| SignPhase::phase_four_verify_dl_com_zk(&delta_sum, &dl_com_zk_vec).unwrap())
    //     .collect::<Vec<_>>();
    let phase_four_result =
        SignPhase::phase_four_verify_dl_com_zk(&delta_sum, &dl_com_zk_vec).unwrap();

    // Sign phase 5
    // let phase_five_step_one_result_vec = (0..party_num)
    //     .map(|i| {
    //         SignPhase::phase_five_step_onetwo_generate_com_and_zk(
    //             &message,
    //             &phase_one_result_vec[i].1,
    //             &sigma_vec[i],
    //             &phase_four_result.0,
    //             &phase_four_result.1,
    //         )
    //     })
    //     .collect::<Vec<_>>();

    let mut phase_five_step_one_msg_vec: Vec<SignPhaseFiveStepOneMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_two_msg_vec: Vec<SignPhaseFiveStepTwoMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_seven_msg_vec: Vec<SignPhaseFiveStepSevenMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_rho_and_l: Vec<(FE, FE)> = Vec::with_capacity(party_num);
    for i in 0..party_num {
        let ret = SignPhase::phase_five_step_onetwo_generate_com_and_zk(
            &message,
            &phase_one_result_vec[i].1,
            &sigma_vec[i],
            &phase_four_result.0,
            &phase_four_result.1,
        );
        phase_five_step_one_msg_vec.push(ret.0);
        phase_five_step_two_msg_vec.push(ret.1);
        phase_five_step_seven_msg_vec.push(ret.2);
        phase_five_rho_and_l.push((ret.3, ret.4));
    }

    let mut phase_five_step_four_msg_vec: Vec<SignPhaseFiveStepFourMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_five_msg_vec: Vec<SignPhaseFiveStepFiveMsg> =
        Vec::with_capacity(party_num);
    for i in 0..party_num {
        let ret = SignPhase::phase_five_step_three_verify_com_and_zk(
            &message,
            &key_gen_vec[i].public_signing_key,
            &phase_four_result.0,
            &phase_four_result.1,
            &phase_five_rho_and_l[i].0,
            &phase_five_rho_and_l[i].1,
            &phase_five_step_one_msg_vec,
            &phase_five_step_two_msg_vec,
        )
        .unwrap();
        phase_five_step_four_msg_vec.push(ret.0);
        phase_five_step_five_msg_vec.push(ret.1);
    }

    SignPhase::phase_five_step_six_verify_com_and_check_sum_a_t(
        &phase_five_step_four_msg_vec,
        &phase_five_step_five_msg_vec,
    )
    .unwrap();

    let sig = SignPhase::phase_five_step_eight_generate_signature(
        &phase_five_step_seven_msg_vec,
        &phase_four_result.0,
    );

    // Verify Signature
    Signature::verify(&sig, &key_gen_vec[0].public_signing_key, &message).unwrap();
}

#[test]
fn test_key_gen() {

    let params = Parameters {
        threshold: 5,
        share_count: 10,
    };

    let (key_gen_vec, vss_scheme) = keygen_t_n_parties(&params);

    test_sign(&params, &key_gen_vec, &vss_scheme);
}

// #[test]
// fn test_index() {
//     // for i in 0..=2 {
//     //     println!("1");
//     // }

//     let list = vec![1, 2, 3];
//     // let ret = list.iter().enumerate().filter(|&(i, _)| i != 1);//.map(|(_, v)| v).collect::<Vec<_>>();
//     let ret = list
//         .iter()
//         .enumerate()
//         .filter_map(|(i, e)| if i != 1 { Some(e) } else { None })
//         .collect::<Vec<_>>();
//     println!("{:?}", ret);
// }
