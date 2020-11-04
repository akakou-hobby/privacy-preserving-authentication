use crate::utils::{generate_public_key, hash_sha256};
use k256::{EncodedPoint, Scalar};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub struct Servicer {
    pub id: u8,
    pub R: EncodedPoint,
    pub S: BigUint,
}
