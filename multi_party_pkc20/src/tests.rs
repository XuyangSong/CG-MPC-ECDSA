use crate::party_i::*;
use cg_ecdsa_core::{CLGroup, Signature};
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE};

fn setup_n(n: usize, discriminant: usize) {
    // Setup Init
    let mut setup_vec = (0..n)
        .map(|_| Setup::init(discriminant))
        .collect::<Vec<Setup>>();

    // Setup Phase 1
    let phase_one_result_vec = (0..n)
        .map(|i| {
            setup_vec[i].phase_one_generate_commitment()
        })
        .collect::<Vec<_>>();

    let phase_one_msg_vec = (0..n)
        .map(|i| phase_one_result_vec[i].0.clone())
        .collect::<Vec<_>>();

    let phase_two_msg_vec = (0..n)
        .map(|i| phase_one_result_vec[i].1.clone())
        .collect::<Vec<_>>();

    let qtilde = setup_vec[0].phase_two_verify_commitment_and_generate_qtilde(&phase_one_msg_vec, &phase_two_msg_vec).unwrap();

    let seed: BigInt = str::parse(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
    ).unwrap();
    let group = Setup::cl_setup(&seed, &qtilde);

    let phase_three_result_vec = (0..n)
        .map(|i| {
            setup_vec[i].phase_three_generate_gi_and_commitment(&group)
        })
        .collect::<Vec<_>>();

    let phase_three_msg_vec = (0..n)
        .map(|i| phase_three_result_vec[i].0.clone())
        .collect::<Vec<_>>();

    let phase_four_msg_vec = (0..n)
        .map(|i| phase_three_result_vec[i].1.clone())
        .collect::<Vec<_>>();

    Setup::phase_four_verify_commitment(&phase_three_msg_vec, &phase_four_msg_vec).unwrap();

    let phase_five_result_vec = (0..n)
        .map(|i| {
            setup_vec[i].phase_five_generate_zkpok(&group)
        })
        .collect::<Vec<_>>();

    let (_, received_zkpok) = phase_five_result_vec.split_at(1);
    setup_vec[0].phase_five_verify_zkpok_and_generate_gq(&group, &received_zkpok.to_vec()).unwrap();

}

fn keygen_t_n_parties(group: &CLGroup, params: &Parameters) -> Vec<KeyGen> {
    let n = params.share_count;
    let t = params.threshold;

    // Key Gen Phase 1
    let mut key_gen_vec = (0..n)
        .map(|i| KeyGen::phase_one_init(group, i, params.clone()))
        .collect::<Vec<KeyGen>>();

    // Key Gen Phase 2
    let dl_com_vec = key_gen_vec
        .iter()
        .map(|key_gen| key_gen.phase_two_generate_dl_com())
        .collect::<Vec<_>>();

    let q_vec = dl_com_vec
        .iter()
        .map(|k| k.get_public_share())
        .collect::<Vec<_>>();

    // Key Gen Phase 3
    let (_, received_dl_com) = dl_com_vec.split_at(1);
    key_gen_vec[0]
        .phase_three_verify_dl_com_and_generate_signing_key(&received_dl_com.to_vec())
        .unwrap();

    // Assign public_signing_key
    for i in 1..n {
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
        dlog_proof_vec.push(dlog_proof);
    }

    // Key Gen Phase 6
    for i in 0..n {
        key_gen_vec[i]
            .phase_six_verify_dlog_proof(&dlog_proof_vec)
            .unwrap();
    }

    // test vss
    let xi_vec = (0..=t)
        .map(|i| key_gen_vec[i].share_private_key)
        .collect::<Vec<FE>>();
    let x = vss_scheme_vec[0]
        .clone()
        .reconstruct(&index_vec[0..=t], &xi_vec);
    let sum_u_i = key_gen_vec.iter().fold(FE::zero(), |acc, x| {
        acc + x.private_signing_key.get_secret_key()
    });

    assert_eq!(x, sum_u_i);

    key_gen_vec
}

fn test_sign(group: &CLGroup, params: &Parameters, key_gen_vec: &Vec<KeyGen>) {
    // Sign Init
    let party_num = key_gen_vec.len();
    let subset = (0..party_num)
        .map(|i| key_gen_vec[i].party_index)
        .collect::<Vec<_>>();

    let mut sign_vec = (0..party_num)
        .map(|i| {
            SignPhase::init(
                key_gen_vec[i].party_index,
                params.clone(),
                &key_gen_vec[i].vss_scheme_vec,
                &subset,
                &key_gen_vec[i].share_public_key,
                &key_gen_vec[i].share_private_key,
                party_num,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Sign phase 1
    let phase_one_result_vec = (0..party_num)
        .map(|i| {
            sign_vec[i].phase_one_generate_cl_enc_proof_and_com(
                group,
                &key_gen_vec[i].cl_keypair,
                // &key_gen_vec[i].ec_keypair,
            )
        })
        .collect::<Vec<_>>();
    let phase_one_msg_vec = (0..party_num)
        .map(|i| phase_one_result_vec[i].0.clone())
        .collect::<Vec<_>>();

    // Sign phase 2
    let phase_two_result_vec = (0..party_num)
        .map(|i| sign_vec[i].phase_two_generate_homo_cipher(group, &phase_one_msg_vec))
        .collect::<Vec<_>>();

    let mut phase_three_msg_vec: Vec<SignPhaseThreeMsg> = Vec::with_capacity(party_num);
    for index in 0..party_num {
        let phase_two_msg_vec = phase_two_result_vec
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if i != index {
                    Some(e[index].clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let msg = sign_vec[index].phase_two_decrypt_and_verify(
            group,
            key_gen_vec[index].cl_keypair.get_secret_key(),
            &phase_two_msg_vec,
        );
        phase_three_msg_vec.push(msg);
    }

    // Sign phase 3
    for i in 0..sign_vec.len() {
        sign_vec[i].phase_two_compute_delta_sum(&phase_three_msg_vec);
    }

    // Sign phase 4
    let message: FE = ECScalar::new_random();
    let phase_four_msg_vec = (0..party_num)
        .map(|i| phase_one_result_vec[i].1.clone())
        .collect::<Vec<_>>();

    for i in 0..sign_vec.len() {
        sign_vec[i]
            .phase_four_verify_dl_com(&phase_one_msg_vec, &phase_four_msg_vec)
            .unwrap();
    }

    // Sign phase 5
    let mut phase_five_step_one_msg_vec: Vec<SignPhaseFiveStepOneMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_two_msg_vec: Vec<SignPhaseFiveStepTwoMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_seven_msg_vec: Vec<SignPhaseFiveStepSevenMsg> =
        Vec::with_capacity(party_num);
    for i in 0..party_num {
        let ret = sign_vec[i].phase_five_step_onetwo_generate_com_and_zk(&message);
        phase_five_step_one_msg_vec.push(ret.0);
        phase_five_step_two_msg_vec.push(ret.1);
        phase_five_step_seven_msg_vec.push(ret.2);
    }

    let mut phase_five_step_four_msg_vec: Vec<SignPhaseFiveStepFourMsg> =
        Vec::with_capacity(party_num);
    let mut phase_five_step_five_msg_vec: Vec<SignPhaseFiveStepFiveMsg> =
        Vec::with_capacity(party_num);
    for i in 0..party_num {
        let ret = sign_vec[i]
            .phase_five_step_three_verify_com_and_zk(
                &message,
                &key_gen_vec[i].public_signing_key,
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

    let sig = sign_vec[0].phase_five_step_eight_generate_signature(&phase_five_step_seven_msg_vec);

    // Verify Signature
    Signature::verify(&sig, &key_gen_vec[0].public_signing_key, &message).unwrap();
}

#[test]
fn test_pkc20() {
    let seed: BigInt = str::parse(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
    ).unwrap();
    let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

    let params = Parameters {
        threshold: 2,
        share_count: 3,
    };

    let key_gen_vec = keygen_t_n_parties(&group, &params);

    test_sign(&group, &params, &key_gen_vec);
}

#[test]
fn test_pkc20_setup() {
    setup_n(5, 1348);
}