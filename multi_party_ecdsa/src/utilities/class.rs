use class_group::primitives::cl_dl_public_setup::CLGroup;
use curv::elliptic::curves::traits::*;
use curv::FE;

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
