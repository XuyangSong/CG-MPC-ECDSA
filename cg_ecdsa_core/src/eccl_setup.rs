use super::is_prime;
use super::numerical_log;
use super::prng;
use super::ErrorReason;
use crate::bn_to_gen;
use crate::curv::arithmetic::traits::Modulo;
use crate::curv::cryptographic_primitives::hashing::traits::Hash;
use crate::isprime;
use crate::pari_init;
use crate::BinaryQF;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};
use std::os::raw::c_int;

const SECURITY_PARAMETER: usize = 128;
const C: usize = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLGroup {
    pub delta_k: BigInt,
    pub delta_q: BigInt,
    pub gq: BinaryQF,
    pub stilde: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Ciphertext {
    pub c1: BinaryQF,
    pub c2: BinaryQF,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ECCLcipher {
    pub c1: BinaryQF,
    pub c2: BinaryQF,
    pub c3: GE,
    pub c4: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Firstcomit {
    pub t1: BinaryQF,
    pub t2: BinaryQF,
    pub t3: GE,
    pub t4: GE,
    pub T: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U1U2U3 {
    pub u1: BigInt,
    pub u2: BigInt,
    pub u3: FE,
}

#[derive(Debug, Clone)]
pub struct ProofError;

impl CLGroup {
    pub fn new_from_setup(lam: &usize, seed: &BigInt) -> Self {
        let q = &FE::q();
        unsafe { pari_init(100000000, 2) };
        let mu = q.bit_length();
        assert!(lam > &(mu + 2));
        let k = lam - mu;
        let two = BigInt::from(2);
        let mut r = BigInt::sample_range(
            &two.pow((k - 1) as u32),
            &(two.pow(k as u32) - BigInt::one()),
        );

        let mut qtilde = next_probable_prime(&r);

        while (q * &qtilde).mod_floor(&BigInt::from(4)) != BigInt::from(3)
            || jacobi(q, &qtilde).unwrap() != -1
        {
            r = BigInt::sample_range(
                &two.pow((k - 1) as u32),
                &(two.pow(k as u32) - BigInt::one()),
            );
            qtilde = next_probable_prime(&r);
        }

        debug_assert!(&(BigInt::from(4) * q) < &qtilde);

        let delta_k = -q * &qtilde;
        let delta_q = &delta_k * q.pow(2);

        let delta_k_abs: BigInt = -delta_k.clone();
        let log_delta_k_abs = numerical_log(&delta_k_abs);
        let delta_k_abs_sqrt = delta_k_abs.sqrt();
        let stilde = log_delta_k_abs * delta_k_abs_sqrt;

        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let mut r = BigInt::from(3);
        let ln_delta_k = numerical_log(&(-&delta_k));

        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&delta_k, &r));
            r = next_probable_small_prime(&r);
            i = i + 1;
        }
        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&delta_k);

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i.clone(), 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i = rand_bits_i + 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent = prod_exponent * &rand_bits_i;
            i = i + 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square.phi_q_to_the_minus_1(&q).reduce();

        let gq = gq_tmp.exp(&q);

        CLGroup {
            delta_k,
            delta_q,
            gq,
            stilde,
        }
    }

    pub fn new_from_qtilde(seed: &BigInt, input_qtilde: &BigInt) -> Self {
        let q = &FE::q();
        unsafe { pari_init(100000000, 2) };
        // let mu = q.bit_length();
        // assert!(lam > &(mu + 2));
        // let k = lam - mu;
        // let two = BigInt::from(2);
        // let mut r = BigInt::sample_range(
        //     &two.pow((k - 1) as u32),
        //     &(two.pow(k as u32) - BigInt::one()),
        // );

        let mut qtilde = input_qtilde.clone();

        while (q * &qtilde).mod_floor(&BigInt::from(4)) != BigInt::from(3)
            || jacobi(q, &qtilde).unwrap() != -1
        {
            // r = BigInt::sample_range(
            //     &two.pow((k - 1) as u32),
            //     &(two.pow(k as u32) - BigInt::one()),
            // );
            qtilde = next_probable_prime(&qtilde);
        }

        debug_assert!(&(BigInt::from(4) * q) < &qtilde);

        let delta_k = -q * &qtilde;
        let delta_q = &delta_k * q.pow(2);

        let delta_k_abs: BigInt = -delta_k.clone();
        let log_delta_k_abs = numerical_log(&delta_k_abs);
        let delta_k_abs_sqrt = delta_k_abs.sqrt();
        let stilde = log_delta_k_abs * delta_k_abs_sqrt;

        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let mut r = BigInt::from(3);
        let ln_delta_k = numerical_log(&(-&delta_k));

        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&delta_k, &r));
            r = next_probable_small_prime(&r);
            i = i + 1;
        }
        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&delta_k);

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i.clone(), 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i = rand_bits_i + 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent = prod_exponent * &rand_bits_i;
            i = i + 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square.phi_q_to_the_minus_1(&q).reduce();

        let gq = gq_tmp.exp(&q);

        CLGroup {
            delta_k,
            delta_q,
            gq,
            stilde,
        }
    }

    pub fn setup_verify(&self, seed: &BigInt) -> Result<(), ErrorReason> {
        unsafe { pari_init(100000000, 2) };

        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let ln_delta_k = numerical_log(&(-&self.delta_k));
        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut r = BigInt::from(3);
        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&self.delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&self.delta_k, &r));
            r = next_probable_small_prime(&r);
            i = i + 1;
        }

        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&self.delta_k);

        //pseudo random element of class group Cl(delta_k) : prod f_p^e_p, with pairwise coprime exponents
        // generate enough pseudo randomness : 15 bits per exponents e_p

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i.clone(), 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i = rand_bits_i + 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent = prod_exponent * &rand_bits_i;
            i = i + 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square.phi_q_to_the_minus_1(&FE::q()).reduce();

        let gq = gq_tmp.exp(&FE::q());
        match gq == self.gq {
            true => Ok(()),
            false => Err(ErrorReason::SetupError),
        }
    }

    /// randomly sample a scalar (secret key) and compute its corresponding group element (public key) by multiplying g_q
    pub fn keygen(&self) -> (SK, PK) {
        let sk = SK(BigInt::sample_below(
            &(&self.stilde * BigInt::from(2).pow(40)),
        ));
        let pk = self.pk_for_sk(&sk);
        (sk, pk)
    }

    /// Return the CL public key for a given secret key
    pub fn pk_for_sk(&self, sk: &SK) -> PK {
        let group_element = self.gq.exp(&sk.0);
        PK(group_element)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PK(pub BinaryQF);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SK(pub BigInt);

impl From<SK> for BigInt {
    fn from(sk: SK) -> Self {
        sk.0
    }
}

impl From<BigInt> for SK {
    fn from(bi: BigInt) -> Self {
        Self(bi)
    }
}

fn jacobi(a: &BigInt, n: &BigInt) -> Option<i8> {
    let zero = BigInt::zero();
    // jacobi symbol is only defined for odd positive moduli
    if n.mod_floor(&BigInt::from(2)) == zero || n <= &BigInt::zero() {
        return None;
    }

    // Raise a mod n, then start the unsigned algorithm
    let mut acc = 1;
    let mut num = a.mod_floor(&n);
    let mut den = n.clone();
    loop {
        // reduce numerator
        num = num.mod_floor(&den);
        if num == zero {
            return Some(0);
        }

        // extract factors of two from numerator
        while num.mod_floor(&BigInt::from(2)) == zero {
            acc *= two_over(&den);
            num = num.div_floor(&BigInt::from(2));
        }
        // if numerator is 1 => this sub-symbol is 1
        if num == BigInt::one() {
            return Some(acc);
        }
        // shared factors => one sub-symbol is zero
        if num.gcd(&den) > BigInt::one() {
            return Some(0);
        }
        // num and den are now odd co-prime, use reciprocity law:
        acc *= reciprocity(&num, &den);
        let tmp = num;
        num = den.clone();
        den = tmp;
    }
}

fn two_over(n: &BigInt) -> i8 {
    if n.mod_floor(&BigInt::from(8)) == BigInt::one()
        || n.mod_floor(&BigInt::from(8)) == BigInt::from(7)
    {
        1
    } else {
        -1
    }
}

fn reciprocity(num: &BigInt, den: &BigInt) -> i8 {
    if num.mod_floor(&BigInt::from(4)) == BigInt::from(3)
        && den.mod_floor(&BigInt::from(4)) == BigInt::from(3)
    {
        -1
    } else {
        1
    }
}

pub fn next_probable_prime(r: &BigInt) -> BigInt {
    let one = BigInt::from(1);
    let mut qtilde = r + &one;
    while !is_prime(&qtilde) {
        qtilde = qtilde + &one;
    }
    qtilde
}

fn next_probable_small_prime(r: &BigInt) -> BigInt {
    let one = BigInt::from(1);
    let mut qtilde = r + &one;
    let mut qtilde_gen = bn_to_gen(&(r + &one));
    unsafe {
        while isprime(qtilde_gen) as c_int != 1 {
            qtilde = qtilde + &one;
            qtilde_gen = bn_to_gen(&qtilde);
        }
    }
    qtilde
}

impl Ciphertext {
    pub fn encrypt(group: &CLGroup, public_key: &PK, m: &FE) -> (Ciphertext, SK) {
        // unsafe { pari_init(10000000, 2) };
        let (r, R) = group.keygen();
        let exp_f = BinaryQF::expo_f(&FE::q(), &group.delta_q, &m.to_big_int());
        let h_exp_r = public_key.0.exp(&r.0);

        (
            Ciphertext {
                c1: R.0,
                c2: h_exp_r.compose(&exp_f).reduce(),
            },
            r,
        )
    }

    pub fn encrypt_without_r(group: &CLGroup, m: &FE) -> (Ciphertext, SK) {
        // unsafe { pari_init(10000000, 2) };
        let r = SK::from(BigInt::from(0));
        let R = group.pk_for_sk(&r);
        let exp_f = BinaryQF::expo_f(&FE::q(), &group.delta_q, &m.to_big_int());

        (Ciphertext { c1: R.0, c2: exp_f }, r)
    }

    pub fn encrypt_predefined_randomness(
        group: &CLGroup,
        public_key: &PK,
        m: &FE,
        r: &SK,
    ) -> Ciphertext {
        // unsafe { pari_init(10000000, 2) };
        let exp_f = BinaryQF::expo_f(&FE::q(), &group.delta_q, &m.to_big_int());
        let h_exp_r = public_key.0.exp(&r.0);

        Ciphertext {
            c1: group.gq.exp(&r.0),
            c2: h_exp_r.compose(&exp_f).reduce(),
        }
    }

    pub fn verifiably_encrypt(
        group: &CLGroup,
        public_key: &PK,
        DL_pair: (&FE, &GE),
        EC_pair: (&GE, &GE),
    ) -> (ECCLcipher, CLDLProof) {
        let (x, X) = DL_pair;
        let (g, h) = EC_pair;
        let (ciphertext1, r1) = encrypt(group, public_key, x);
        let r2: FE = ECScalar::new_random();
        let gr = g * &r2;
        let _hr = h * &r2;
        let mg = g * x;
        let (c3, c4) = (gr, _hr + mg);
        let hpscipher = ECCLcipher {
            c1: ciphertext1.c1.clone(),
            c2: ciphertext1.c2.clone(),
            c3,
            c4,
        };

        let proof = CLDLProof::prove(group, (&x, &r1, &r2), (public_key, &hpscipher, X, g, h));
        (hpscipher, proof)
    }
    pub fn decrypt(group: &CLGroup, secret_key: &SK, c: &Ciphertext) -> FE {
        // unsafe { pari_init(10000000, 2) };
        let c1_x = c.c1.exp(&secret_key.0);
        let c1_x_inv = c1_x.inverse();
        let tmp = c.c2.compose(&c1_x_inv).reduce();
        let plaintext = BinaryQF::discrete_log_f(&FE::q(), &group.delta_q, &tmp);
        debug_assert!(plaintext < FE::q());
        ECScalar::from(&plaintext)
    }

    /// Multiplies the encrypted value by `val`.
    pub fn eval_scal(c: &Ciphertext, val: &BigInt) -> Ciphertext {
        // unsafe { pari_init(10000000, 2) };
        let c_new = Ciphertext {
            c1: c.c1.exp(&val),
            c2: c.c2.exp(&val),
        };
        c_new
    }

    /// Homomorphically adds two ciphertexts so that the resulting ciphertext is the sum of the two input ciphertexts
    pub fn eval_sum(c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
        // unsafe { pari_init(10000000, 2) };
        let c_new = Ciphertext {
            c1: c1.c1.compose(&c2.c1).reduce(),
            c2: c1.c2.compose(&c2.c2).reduce(),
        };
        c_new
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLDLProof {
    first_message: Firstcomit,
    second_message: U1U2U3,
}

impl CLDLProof {
    fn prove(
        group: &CLGroup,
        witness: (&FE, &SK, &FE),
        statement: (&PK, &ECCLcipher, &GE, &GE, &GE),
    ) -> Self {
        // unsafe { pari_init(10000000, 2) };
        let (x, r1, r2) = witness;
        let (public_key, ciphertext, X, g, h) = statement;

        let s1 = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)),
        );
        let s_fe: FE = FE::new_random();
        let s = s_fe.to_big_int();
        let s2: FE = FE::new_random();
        let fr = BinaryQF::expo_f(&FE::q(), &group.delta_q, &s);
        let pkr1 = public_key.0.exp(&s1);
        let t2 = fr.compose(&pkr1).reduce();
        let T = GE::generator() * s_fe;
        let t1 = group.gq.exp(&s1);
        let t3 = g * &s2;
        let t41 = h * &s2;
        let t42 = g * &s_fe;
        let t4 = t41 + t42;
        let firstmessage = Firstcomit { t1, t2, t3, t4, T };

        let k = Self::challenge(public_key, &firstmessage, ciphertext, X);

        let u1 = s1 + &k * &r1.0;
        let u2 = BigInt::mod_add(&s, &(&k * x.to_big_int()), &FE::q());
        let u31 = BigInt::mod_add(&s2.to_big_int(), &(&k * r2.to_big_int()), &FE::q());
        let u3: FE = ECScalar::from(&u31);
        let secondmessage = U1U2U3 { u1, u2, u3 };

        Self {
            first_message: firstmessage,
            second_message: secondmessage,
        }
    }

    /// Compute the Fiat-Shamir challenge for the proof.
    fn challenge(public_key: &PK, t: &Firstcomit, ciphertext: &ECCLcipher, X: &GE) -> BigInt {
        use crate::curv::arithmetic::traits::Converter;
        let hash256 = HSha256::create_hash(&[
            // hash the statement i.e. the discrete log of Q is encrypted in (c1,c2) under encryption key h.
            &X.bytes_compressed_to_big_int(),
            &BigInt::from(ciphertext.c1.to_bytes().as_ref()),
            &BigInt::from(ciphertext.c2.to_bytes().as_ref()),
            &BigInt::from(public_key.0.to_bytes().as_ref()),
            // hash Sigma protocol commitments
            &BigInt::from(t.t1.to_bytes().as_ref()),
            &BigInt::from(t.t2.to_bytes().as_ref()),
            &t.T.bytes_compressed_to_big_int(),
        ]);

        let hash128 = &BigInt::to_vec(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from(hash128)
    }

    pub fn verify(
        &self,
        group: &CLGroup,
        public_key: &PK,
        ciphertext: &ECCLcipher,
        g: &GE,
        h: &GE,
        X: &GE,
    ) -> Result<(), ProofError> {
        // unsafe { pari_init(10000000, 2) };
        let mut flag = true;

        // reconstruct k
        let k = Self::challenge(public_key, &self.first_message, ciphertext, X);

        let sample_size = &group.stilde
            * (BigInt::from(2).pow(40))
            * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
            * (BigInt::from(2).pow(40) + BigInt::one());

        //length test u1:
        if &self.second_message.u1 > &sample_size || &self.second_message.u1 < &BigInt::zero() {
            flag = false;
        }
        // length test u2:
        if &self.second_message.u2 > &FE::q() || &self.second_message.u2 < &BigInt::zero() {
            flag = false;
        }

        let c1k = ciphertext.c1.exp(&k);
        let t1c1k = self.first_message.t1.compose(&c1k).reduce();
        let gqu1 = group.gq.exp(&&self.second_message.u1);
        if t1c1k != gqu1 {
            flag = false;
        };

        let k_bias_fe: FE = ECScalar::from(&(k.clone() + BigInt::one()));
        let gg = GE::generator();
        let t2kq = (self.first_message.T + X * &k_bias_fe).sub_point(&X.get_element());
        let u2p = &gg * &ECScalar::from(&self.second_message.u2);
        if t2kq != u2p {
            flag = false;
        }
        let c3k = (ciphertext.c3 * k_bias_fe).sub_point(&ciphertext.c3.get_element());
        let t3c3k = self.first_message.t3 + &c3k;
        let ggu3 = &gg * &self.second_message.u3;
        if t3c3k != ggu3 {
            flag = false;
        }
        let k_fe: FE = ECScalar::from(&k);
        let c4k = ciphertext.c4 * &k_fe;
        let t4c4k = self.first_message.t4 + &c4k;
        let hu3 = *&h * &self.second_message.u3;
        let u2 = &self.second_message.u2;
        let u2_fe: FE = ECScalar::from(&u2);
        let gu2 = *&g * &u2_fe;
        let hu3gu2 = &hu3 + &gu2;
        if t4c4k != hu3gu2 {
            flag = false;
        }

        let pku1 = public_key.0.exp(&self.second_message.u1);
        let fu2 = BinaryQF::expo_f(&FE::q(), &group.delta_q, &self.second_message.u2);
        let c2k = ciphertext.c2.exp(&k);
        let t2c2k = self.first_message.t2.compose(&c2k).reduce();
        let pku1fu2 = pku1.compose(&fu2).reduce();
        if t2c2k != pku1fu2 {
            flag = false;
        }
        match flag {
            true => Ok(()),
            false => Err(ProofError),
        }
    }
}

/// Multiplies the encrypted value by `val`.
pub fn encrypt(group: &CLGroup, public_key: &PK, m: &FE) -> (Ciphertext, SK) {
    // unsafe { pari_init(10000000, 2) };
    let (r, R) = group.keygen();
    let exp_f = BinaryQF::expo_f(&FE::q(), &group.delta_q, &m.to_big_int());
    let h_exp_r = public_key.0.exp(&r.0);

    (
        Ciphertext {
            c1: R.0,
            c2: h_exp_r.compose(&exp_f).reduce(),
        },
        r,
    )
}

pub fn encrypt_predefined_randomness(
    group: &CLGroup,
    public_key: &PK,
    m: &FE,
    r: &SK,
) -> Ciphertext {
    // unsafe { pari_init(10000000, 2) };
    let exp_f = BinaryQF::expo_f(&FE::q(), &group.delta_q, &m.to_big_int());
    let h_exp_r = public_key.0.exp(&r.0);

    Ciphertext {
        c1: group.gq.exp(&r.0),
        c2: h_exp_r.compose(&exp_f).reduce(),
    }
}

pub fn verifiably_encrypt(
    group: &CLGroup,
    public_key: &PK,
    DL_pair: (&FE, &GE),
    EC_pair: (&GE, &GE),
) -> (ECCLcipher, CLDLProof) {
    let (x, X) = DL_pair;
    let (g, h) = EC_pair;
    let (ciphertext1, r1) = encrypt(group, public_key, x);
    let r2: FE = ECScalar::new_random();
    let gr = g * &r2;
    let _hr = h * &r2;
    let mg = g * x;
    let (c3, c4) = (gr, _hr + mg);
    let hpscipher = ECCLcipher {
        c1: ciphertext1.c1.clone(),
        c2: ciphertext1.c2.clone(),
        c3,
        c4,
    };

    let proof = CLDLProof::prove(group, (&x, &r1, &r2), (public_key, &hpscipher, X, g, h));
    (hpscipher, proof)
}

pub fn decrypt(group: &CLGroup, secret_key: &SK, c: &Ciphertext) -> FE {
    // unsafe { pari_init(10000000, 2) };
    let c1_x = c.c1.exp(&secret_key.0);
    let c1_x_inv = c1_x.inverse();
    let tmp = c.c2.compose(&c1_x_inv).reduce();
    let plaintext = BinaryQF::discrete_log_f(&FE::q(), &group.delta_q, &tmp);
    debug_assert!(plaintext < FE::q());
    ECScalar::from(&plaintext)
}

/// Multiplies the encrypted value by `val`.
pub fn eval_scal(c: &Ciphertext, val: &BigInt) -> Ciphertext {
    // unsafe { pari_init(10000000, 2) };
    let c_new = Ciphertext {
        c1: c.c1.exp(&val),
        c2: c.c2.exp(&val),
    };
    c_new
}

/// Homomorphically adds two ciphertexts so that the resulting ciphertext is the sum of the two input ciphertexts
pub fn eval_sum(c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    // unsafe { pari_init(10000000, 2) };
    let c_new = Ciphertext {
        c1: c1.c1.compose(&c2.c1).reduce(),
        c2: c1.c2.compose(&c2.c2).reduce(),
    };
    c_new
}

#[cfg(test)]
mod test {
    use super::*;

    const seed: &'static str =  "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848";
    #[test]
    fn encrypt_and_decrypt() {
        let group = CLGroup::new_from_setup(&1600, &str::parse(seed).unwrap());
        let (secret_key, public_key) = group.keygen();
        let message = FE::new_random();
        let (ciphertext, _) = encrypt(&group, &public_key, &message);
        let plaintext = decrypt(&group, &secret_key, &ciphertext);
        assert_eq!(plaintext, message);
    }

    #[test]
    fn compute_discrete_log_in_DLEasy_subgroup() {
        let group = CLGroup::new_from_setup(&1600, &str::parse(seed).unwrap());
        let m = BigInt::from(10000);
        let exp_f = BinaryQF::expo_f(&FE::q(), &group.delta_q, &m);
        let m_tag = BinaryQF::discrete_log_f(&FE::q(), &group.delta_q, &exp_f);
        assert_eq!(m, m_tag);
    }

    #[test]
    fn verifiably_encrypt_verify_and_decrypt() {
        let group = CLGroup::new_from_setup(&1600, &str::parse(seed).unwrap());
        let (secret_key, public_key) = group.keygen();
        let dl_keypair = {
            let sk = FE::new_random();
            let pk = GE::generator() * sk;
            (sk, pk)
        };
        let ec_pair = {
            let g: GE = GE::generator();
            let key = FE::new_random();
            let h = &g * &key;
            (g, h)
        };
        let (ciphertext, proof) = verifiably_encrypt(
            &group,
            &public_key,
            (&dl_keypair.0, &dl_keypair.1),
            (&ec_pair.0, &ec_pair.1),
        );

        let wrong_dl_pk = dl_keypair.1 + &GE::generator();

        assert!(
            proof
                .verify(
                    &group,
                    &public_key,
                    &ciphertext,
                    &ec_pair.0,
                    &ec_pair.1,
                    &dl_keypair.1
                )
                .is_ok(),
            "proof is valid against valid DL key"
        );

        assert!(
            proof
                .verify(
                    &group,
                    &public_key,
                    &ciphertext,
                    &ec_pair.0,
                    &ec_pair.1,
                    &wrong_dl_pk
                )
                .is_err(),
            "proof is invalid against invalid DL key"
        );
        let clciphertext = Ciphertext {
            c1: ciphertext.c1.clone(),
            c2: ciphertext.c2.clone(),
        };
        assert_eq!(
            decrypt(&group, &secret_key, &clciphertext),
            dl_keypair.0,
            "plaintext matches what was encrypted"
        );
    }

    #[test]
    fn multiply_ciphertext_by_scalar() {
        let group = CLGroup::new_from_setup(&1600, &str::parse(seed).unwrap());
        let (secret_key, public_key) = group.keygen();
        let scalar = FE::new_random();

        let (ciphertext, _) = encrypt(&group, &public_key, &scalar);

        let multiply_by = FE::new_random();
        let mutated_ciphertext = eval_scal(&ciphertext, &multiply_by.to_big_int());
        let plaintext = decrypt(&group, &secret_key, &mutated_ciphertext);
        let expected = scalar * multiply_by;

        assert_eq!(plaintext, expected, "plaintext was multiplied");
    }

    #[test]
    fn add_ciphertexts() {
        let group = CLGroup::new_from_setup(&1600, &str::parse(seed).unwrap());
        let (secret_key, public_key) = group.keygen();
        let scalar1 = FE::new_random();
        let scalar2 = FE::new_random();

        let (ciphertext1, _) = encrypt(&group, &public_key, &scalar1);
        let (ciphertext2, _) = encrypt(&group, &public_key, &scalar2);

        let combined = eval_sum(&ciphertext1, &ciphertext2);
        let plaintext = decrypt(&group, &secret_key, &combined);
        let expected = scalar1 + scalar2;

        assert_eq!(plaintext, expected, "ciphertexts were added");
    }

    #[test]
    fn cl_dl_test_setup() {
        let parsed_seed = str::parse(seed).unwrap();
        let group = CLGroup::new_from_setup(&1600, &parsed_seed);
        assert!(group.setup_verify(&parsed_seed).is_ok());
    }
}
