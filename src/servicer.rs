use crate::utils::{hash_sha256, KeyPair};
use k256::{EncodedPoint, Scalar};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub struct Servicer {
    pub id: u8,
    pub r: EncodedPoint,
    pub s: BigUint,
}
