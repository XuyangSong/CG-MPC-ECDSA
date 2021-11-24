use curv::elliptic::curves::secp256_k1::FE;

pub  trait Slice {
    fn key_to_slice(&self) -> Vec<FE>;
    fn slice_to_key(slices: Vec<FE>) -> Self;
}

