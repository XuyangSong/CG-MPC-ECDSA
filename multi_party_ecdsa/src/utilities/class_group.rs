use classgroup::gmp::mpz::Mpz;
use classgroup::gmp_classgroup::*;
use std::str::FromStr;
use classgroup::ClassGroup;
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::traits::ECScalar;
use curv::arithmetic::Converter;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use curv::BigInt;
use curv::arithmetic::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLGroup {
    pub delta_k: Mpz,
    pub gq: GmpClassGroup,
    pub stilde: Mpz,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PK(pub GmpClassGroup);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Ciphertext {
    pub c1: GmpClassGroup,
    pub c2: GmpClassGroup,
}

impl From<PK> for GmpClassGroup {
    fn from(pk: PK) -> Self {
        pk.0
    }
}

impl From<GmpClassGroup> for PK {
    fn from(cl: GmpClassGroup) -> Self {
        Self(cl)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SK(pub Mpz);

impl From<SK> for Mpz {
    fn from(sk: SK) -> Self {
        sk.0
    }
}

impl From<Mpz> for SK {
    fn from(mpz: Mpz) -> Self {
        Self(mpz)
    }
}

impl CLGroup {
    pub fn new() -> Self {
        let delta_k = Mpz::from_str("-5612960460354297586496608465355436736175385121665162536528003724349027131555226649274328061478036486426974235182817460231858406454328229705097433539599357659030732986212902896965288623752937699627896244889952350312271535460213196686033784826094098560791044370859682930856242386198578254852455887200105136848768296981731378965699234956909793269449142655809687632817484368532297652832818925682445449730939672558315001010323704348812542103398759340104715127787089082447127193712577594846384285770469931817870736146192486488946997648500323172668328291265422577316785106221217309556660122713505680384876843920057653776862871100907889289236674725514431").unwrap();
        let a = Mpz::from_str("3379933361837959750444281267886081834476751587152191195702130129876229099797314884670653751744957540137083102210369145718831424083421213040698452363387299065826090566614550509104171596193940708452801446727936908797340323098201338663853170233065328696856790082422069275092967399794413723895514088363951458374936750806184395472544267780653575123461655052057240595359404437943529185106860238910043016082").unwrap();
        let b = Mpz::from_str("58358596530709071629230628954813789065094567413901151732504604054459961302465715041370372364950254062052414177175583619344532154277172761099891464143583046235404103174114873829883081661462607082144282568946995469931366172071928031362252538721358169137643386731728896321136677327778862260030176007687015790858390775199286445826383171957023481318023285705914617463624817890014105071550499557399120835").unwrap();
        let discriminant = Mpz::from_str("-75257495770792601579408435348799912112609846029965206820064851604692987230254538914853608976971793980958712372789231634579578971529235823075608739231635687425758158575368321348137900869894119507551586698602273331769113654968615517566745786072923103207661147676790644792111452136974276225728730910712947503901232735129687891775293591232029998265064837518833536297518857716272011348573253397254136847763813364524813537416619588617528698171849359403663703760169261184343946919401092992684996593982744033815507830560787451354075275532210193117085590501285653650352846925182015277946751628767130269342252523310043345421861896214174850131607385236887381965429994384214519104490505249675175386383257705274311668138257554180057201072703457873180274207162029503126883077609392094864657038777406276133886450239").unwrap();
        let gq = ClassGroup::from_ab_discriminant(a, b, discriminant);
        let stilde = Mpz::from_str("70874029964003222178994413383062782755071292199599732976843764646488791400299245173357367622414689715904677764175683692699088623752022377648358556868028456505343659927114861398173913787770528036913753917714784290366762147149325499950491790497996441006302782823370615596812470224184985789821376325103006605987671787325355230432").unwrap();
        Self {
            delta_k,
            gq,
            stilde
        }
    }

    pub fn keygen(&self) -> (SK, PK) {
        let sk = SK(bigint_to_mpz(BigInt::sample_below(
            &(&(mpz_to_bigint(self.stilde.clone())) * BigInt::from(2).pow(40))))
        );
        let mut generator = self.gq.clone();
        generator.pow(sk.clone().0);
        let pk = PK(generator);
        (sk, pk)
    }

    pub fn encrypt(group: &CLGroup, public_key: &PK, m: &FE) -> (Ciphertext, SK) {
        //unsafe { pari_init(10000000, 2) };
        let k = into_mpz(m);
        let (r, r_big) = group.keygen();
        let delta = group.gq.discriminant().clone();
        let exp_f = expo_f(&q(), &delta, &k);
        let mut h_exp_r = public_key.0.clone();
        h_exp_r.pow(r.0.clone());
    
        (
            Ciphertext {
                c1: r_big.0,
                c2: h_exp_r*exp_f,
            },
            r,
        )
    }

    pub fn decrypt(group: &CLGroup, secret_key: &SK, c: &Ciphertext) -> FE {
        let mut c1_x_inv = c.c1.clone();
        c1_x_inv.pow(secret_key.0.clone());
        c1_x_inv.inverse();
        let tmp = c.c2.clone() * &c1_x_inv;
        let plaintext = discrete_log_f(&q(), &group.gq.discriminant(), &tmp);
        debug_assert!(plaintext < q());
        let plaintext_big = BigInt::from_str_radix(&plaintext.to_str_radix(16), 16).unwrap();
        ECScalar::from(&plaintext_big)
    }

    pub fn encrypt_without_r(group: &CLGroup, m: &FE) -> (Ciphertext, SK) {
        let r = SK::from(Mpz::from(0));
        let r_big = group.pk_for_sk(r.clone());
        let m_mpz = Mpz::from_str(&m.to_big_int().to_str_radix(10)).unwrap();
        let exp_f = expo_f(&q(), &group.gq.discriminant(), &m_mpz);
    
        (Ciphertext { c1: r_big.0, c2: exp_f }, r)
    }

    pub fn pk_for_sk(&self, sk: SK) -> PK {
        let mut group_element = self.gq.clone();
        group_element.pow(sk.0);
        PK(group_element)
    }

    pub fn eval_scal(c: &Ciphertext, val: Mpz) -> Ciphertext {
        let mut c1 = c.c1.clone();
        c1.pow(val.clone());
        let mut c2 = c.c2.clone();
        c2.pow(val);
        let c_new = Ciphertext {
            c1,
            c2,
        };
        c_new
    }
    
    /// Homomorphically adds two ciphertexts so that the resulting ciphertext is the sum of the two input ciphertexts
    pub fn eval_sum(c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
        let c_new = Ciphertext {
            c1: c1.c1.clone() * c2.c1.clone(),
            c2: c1.c2.clone() * c2.c2.clone(),
        };
        c_new
    }
}

pub fn q() -> Mpz {
    let q = Mpz::from_str(&FE::q().to_str_radix(10)).unwrap();
    q
}

pub fn from_discriminant(delta: &Mpz) -> GmpClassGroup {
    let a = Mpz::one();
    let b = Mpz::one();
    assert_eq!(delta.mod_floor(&Mpz::from(4)), Mpz::one());
    assert!(delta < &Mpz::zero()); // in general delta can be positive but we don't deal with that case 
    ClassGroup::from_ab_discriminant(a, b, (*delta).clone())
}

pub fn expo_f(p: &Mpz, delta: &Mpz, k: &Mpz) -> GmpClassGroup {
    if k == &Mpz::zero() {
        let group = from_discriminant(delta);
        return group
    }
    let mut k_inv = k.invert(p).unwrap();
    if k_inv.mod_floor(&Mpz::from(2)) == Mpz::zero() {
        k_inv = k_inv - p;
    };
    let k_inv_p = k_inv * p;
    let qf = ClassGroup::from_ab_discriminant(p * p, k_inv_p, (*delta).clone());
    qf
}

pub fn discrete_log_f(p: &Mpz, delta: &Mpz, c: &GmpClassGroup) -> Mpz {
    let principal_qf =  from_discriminant(delta);
    if c == &principal_qf {
        return Mpz::zero();
    } else {
        let lk = c.b.div_floor(p);
        let lk_inv = lk.invert(p).unwrap();
        return lk_inv;
    }
}

pub fn mpz_to_bigint(value: Mpz) -> BigInt {
    BigInt::from_str_radix(&value.to_str_radix(16), 16).unwrap()
}

pub fn bigint_to_mpz(value: BigInt) -> Mpz {
    Mpz::from_str_radix(&value.to_str_radix(16), 16).unwrap()
}

pub fn update_class_group_by_p(group: &CLGroup) -> CLGroup {
    let q = q();
    let mut gq_new = group.gq.clone();
    gq_new.pow(q);
    CLGroup {
        delta_k: group.delta_k.clone(),
        gq: gq_new,
        stilde: group.stilde.clone(),
    }
}

pub fn into_mpz(f: &FE) -> Mpz {
    Mpz::from_str(&f.to_big_int().to_str_radix(10)).unwrap()
}

lazy_static! {
    pub static ref GROUP_128: CLGroup = CLGroup::new();
}

lazy_static! {
    pub static ref GROUP_UPDATE_128: CLGroup = update_class_group_by_p(&GROUP_128);
}

#[test]
pub fn test_expo_f() {
    use curv::elliptic::curves::traits::ECScalar;
    use curv::BigInt;
    use curv::arithmetic::Converter;
    use class_group::BinaryQF;
    let p_bigint = FE::q();
    let disc_bigint = BigInt::from_str_radix("-427591883024055094237166135622616655692519934789141165516706756107713228024295574699944370011492039773032284231197067920516476468952667833450787437565142878414690959601489749046040711938128287296782189616537717688270214244402769076279798454569992482605974226864130564559661953774942648236131809818008262290621847888715639292230937796387198730350695926159265589312774352775617969025314432860667259678434940630540543035480609747636331455190603326444795763211972135959921012248669035956143099101074949371262559470141902477520013849988014387063025822245215125266145907356818350851633878657454104378492479085550260787918948512444782208939491", 10).unwrap();
    let k_bigint = BigInt::from_str_radix("12345", 10).unwrap();
    let result_1 = BinaryQF::expo_f(&p_bigint, &disc_bigint, &k_bigint);
    println!("result_1 = {:?}", result_1);

    let p_mpz = Mpz::from_str("115792089237316195423570985008687907852837564279074904382605163141518161494337").unwrap();
    let disc_mpz = Mpz::from_str("-427591883024055094237166135622616655692519934789141165516706756107713228024295574699944370011492039773032284231197067920516476468952667833450787437565142878414690959601489749046040711938128287296782189616537717688270214244402769076279798454569992482605974226864130564559661953774942648236131809818008262290621847888715639292230937796387198730350695926159265589312774352775617969025314432860667259678434940630540543035480609747636331455190603326444795763211972135959921012248669035956143099101074949371262559470141902477520013849988014387063025822245215125266145907356818350851633878657454104378492479085550260787918948512444782208939491").unwrap();
    let k_mpz = Mpz::from_str("12345").unwrap();
    let result_2 = expo_f(&p_mpz, &disc_mpz, &k_mpz);
    println!("result_2 = {:?}", result_2);
}

#[test]
pub fn test_compose() {
    use crate::utilities::class::GROUP_128;
    use curv::BigInt;
    use curv::arithmetic::Converter;
    let a = Mpz::from_str("3379933361837959750444281267886081834476751587152191195702130129876229099797314884670653751744957540137083102210369145718831424083421213040698452363387299065826090566614550509104171596193940708452801446727936908797340323098201338663853170233065328696856790082422069275092967399794413723895514088363951458374936750806184395472544267780653575123461655052057240595359404437943529185106860238910043016082").unwrap();
    let b = Mpz::from_str("58358596530709071629230628954813789065094567413901151732504604054459961302465715041370372364950254062052414177175583619344532154277172761099891464143583046235404103174114873829883081661462607082144282568946995469931366172071928031362252538721358169137643386731728896321136677327778862260030176007687015790858390775199286445826383171957023481318023285705914617463624817890014105071550499557399120835").unwrap();
    let discriminant = Mpz::from_str("-75257495770792601579408435348799912112609846029965206820064851604692987230254538914853608976971793980958712372789231634579578971529235823075608739231635687425758158575368321348137900869894119507551586698602273331769113654968615517566745786072923103207661147676790644792111452136974276225728730910712947503901232735129687891775293591232029998265064837518833536297518857716272011348573253397254136847763813364524813537416619588617528698171849359403663703760169261184343946919401092992684996593982744033815507830560787451354075275532210193117085590501285653650352846925182015277946751628767130269342252523310043345421861896214174850131607385236887381965429994384214519104490505249675175386383257705274311668138257554180057201072703457873180274207162029503126883077609392094864657038777406276133886450239").unwrap();
    let gq: GmpClassGroup = ClassGroup::from_ab_discriminant(a.clone(), b.clone(), discriminant.clone());
    let mut d = gq.clone();
    d.pow(Mpz::from_str("123").unwrap());
    let mul = gq*d;
    println!("mul = {:?}", mul);

    let gq_1 = GROUP_128.gq.clone();
    let d_1 = GROUP_128.gq.clone();
    let d_2 = d_1.exp(&BigInt::from_str_radix("123", 10).unwrap());
    let comp = gq_1.compose(&d_2).reduce();
    println!("comp = {:?}", comp);
}

#[test] 
pub fn test_encrypt_decrypt() {
    let m = FE::new_random();
    let (sk, pk) = GROUP_128.keygen();
    let c = CLGroup::encrypt(&GROUP_128, &pk, &m);
    let m_new = CLGroup::decrypt(&GROUP_128, &sk, &c.0);
    assert_eq!(m ,m_new);
}

#[test]
pub fn exp_a() {
    use crate::utilities::class::GROUP_128;
    let a = GROUP_128.gq.clone();
    let b = BigInt::from_str_radix("123", 10).unwrap();
    let start = time::now();
    let _c = a.exp(&b);
    let end = time::now();
    println!("time = {:?}", end - start);
}

#[test]
pub fn pow_a() {
    let mut a = GROUP_128.gq.clone();
    let b = Mpz::from_str_radix("123", 10).unwrap();
    let start = time::now();
    a.pow(b);
    let end = time::now();
    println!("time = {:?}", end - start);
}

#[test]
fn test_big_to_mpz() {
    let a = BigInt::from_str_radix("123", 16).unwrap();
    let start = time::now();
    let _b = bigint_to_mpz(a);
    let end = time::now();
    println!("duration = {:?}", end - start);
}



