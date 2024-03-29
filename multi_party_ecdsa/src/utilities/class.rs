use class_group::primitives::cl_dl_public_setup::CLGroup;
use curv::arithmetic::Converter;
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use lazy_static::lazy_static;

pub fn update_class_group_by_p(group: &CLGroup) -> CLGroup {
    let q = FE::q();
    let gq = group.gq.exp(&q);
    CLGroup {
        delta_k: group.delta_k.clone(),
        delta_q: group.delta_q.clone(),
        gq,
        stilde: group.stilde.clone(),
    }
}

lazy_static! {
    pub static ref SEED: BigInt = BigInt::from_hex(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
    ).unwrap();
}
// discriminant: 1348, lambda: 112
lazy_static! {
    pub static ref QTLIDE_112: BigInt = BigInt::from_hex("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();
}
// discriminant: 1827, lambda: 128
lazy_static! {
    pub static ref QTLIDE_128: BigInt = BigInt::from_hex("23134629277267369792843354241183585965289672542849276532207430015120455980466994354663282525744929223097771940566085692607836906398587331469747248600524817812682304621106507179764371100444437141969242248158429617082063052414988242667563996070192147160738941577591048902446543474661282744240565430969463246910793975505673398580796242020117195767211576704240148858827298420892993584245717232048052900060035847264121684747571088249105643535567823029086931610261875021794804631").unwrap();
}
lazy_static! {
    pub static ref GROUP_112: CLGroup = CLGroup::new_from_qtilde(&SEED, &QTLIDE_112);
}
lazy_static! {
    pub static ref GROUP_128: CLGroup = CLGroup::new_from_qtilde(&SEED, &QTLIDE_128);
}
lazy_static! {
    pub static ref GROUP_UPDATE_128: CLGroup = update_class_group_by_p(&GROUP_128);
}

#[test]
pub fn group_print(){
    println!("gq = {:?}", GROUP_UPDATE_128.gq);
    println!("stilde = {:?}", GROUP_128.stilde);
    println!("discri = {:?}", GROUP_128.delta_q);
    println!("delta_k = {:?}", GROUP_128.delta_k);
}
