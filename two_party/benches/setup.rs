use criterion::criterion_main;

mod bench {
    use criterion::{criterion_group, Criterion};
    use curv::arithmetic::traits::Samplable;
    use curv::elliptic::curves::traits::*;
    use curv::BigInt;
    use curv::{FE, GE};
    use twoparty::protocols::eccl_setup::CLGroup;
    use twoparty::protocols::*;

    pub fn bench_parameter_generating_time(c: &mut Criterion) {
        c.bench_function("setup", move |b| {
            b.iter(|| {
                // init class group, cl keypair and elegamal keypair:
                let seed: BigInt = str::parse(
                    "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
                ).unwrap();
                let cl_group_test = CLGroup::new_from_setup(&1348, &seed);//discriminant 1348
                let (secret_key_test, public_key_test) = cl_group_test.keygen();//class group key generation
                let g_test: GE= GE::generator();
                let ecsk_test: FE = FE::new_random();
                let h: GE=g_test.clone().scalar_mul(&ecsk_test.get_element());// elegamal key generation
                assert!(cl_group_test.setup_verify(&seed).is_ok());
            })
        });
    }

    criterion_group! {
    name = setup;
    config = Criterion::default().sample_size(10);
    targets =self::bench_parameter_generating_time}
}

criterion_main!(bench::setup);
