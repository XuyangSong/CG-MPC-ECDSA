use crate::party_i::*;
use cg_ecdsa_core::{CLGroup, DLComZK, Signature};
// use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE};

fn keygen_t_n_parties(group: &CLGroup, params: &Parameters) -> (Vec<KeyGen>, VerifiableSS) {
    let n = params.share_count;
    let t = params.threshold;

    // Key Gen Phase 1
    let mut key_gen_vec = (0..n)
        .map(|i| KeyGen::phase_one_init(group, i, params.clone()))
        .collect::<Vec<KeyGen>>();

    // Key Gen Phase 2
    let dl_com_zk_vec = key_gen_vec
        .iter()
        .map(|key_gen| key_gen.phase_two_generate_dl_com_zk())
        .collect::<Vec<_>>();

    let q_vec = dl_com_zk_vec
        .iter()
        .map(|k| k.get_public_share())
        .collect::<Vec<_>>();

    // Key Gen Phase 3
    let (_, received_dl_com_zk) = dl_com_zk_vec.split_at(1);
    key_gen_vec[0]
        .phase_three_verify_dl_com_zk_and_generate_signing_key(&received_dl_com_zk.to_vec())
        .unwrap();

    // Assign public_signing_key
    for i in 1..params.share_count {
        key_gen_vec[i].public_signing_key = key_gen_vec[0].public_signing_key;
    }

    // Key Gen Phase 4
    let vss_result = key_gen_vec
        .iter()
        .map(|k| k.phase_four_generate_vss())
        .collect::<Vec<_>>();

    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();
    for (vss_scheme, secret_shares, index) in vss_result {
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares);
        index_vec.push(index);
    }

    let party_shares = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i]
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    // Key Gen Phase 5
    let mut dlog_proof_vec = Vec::new();
    for i in 0..n {
        let dlog_proof = key_gen_vec[i]
            .phase_five_verify_vss_and_generate_pok_dlog(&q_vec, &party_shares[i], &vss_scheme_vec)
            .expect("invalid vss");
        // shared_keys_vec.push(shared_keys);
        dlog_proof_vec.push(dlog_proof);
    }

    // Key Gen Phase 6
    key_gen_vec[0]
        .phase_six_verify_dlog_proof(&dlog_proof_vec)
        .unwrap();

    // test vss
    let xi_vec = (0..=t)
        .map(|i| key_gen_vec[i].share_private_key)
        .collect::<Vec<FE>>();
    let x = vss_scheme_vec[0]
        .clone()
        .reconstruct(&index_vec[0..=t], &xi_vec);
    let sum_u_i = key_gen_vec.iter().fold(FE::zero(), |acc, x| acc + x.private_signing_key.get_secret_key());

    assert_eq!(x, sum_u_i);

    (key_gen_vec, vss_scheme_vec[0].clone())
}

fn test_sign(group: &CLGroup, params: &Parameters, key_gen_vec: &Vec<KeyGen>, vss_scheme: &VerifiableSS) {
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
                group,
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
                group,
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
            group,
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
    let seed: BigInt = str::parse(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
    ).unwrap();
    let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

    let params = Parameters {
        threshold: 2,
        share_count: 4,
    };

    let (_key_gen_vec, _vss_scheme) = keygen_t_n_parties(&group, &params);

    // test_sign(&group, &params, &key_gen_vec, &vss_scheme);
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
