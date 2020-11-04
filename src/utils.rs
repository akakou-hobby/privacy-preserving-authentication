use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint, Secp256k1};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

pub struct KeyPair {
    pub secret_key: NonZeroScalar,
    pub public_key: EncodedPoint,
}

impl KeyPair {
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        let secret_key = NonZeroScalar::random(rng);
        let public_key = (ProjectivePoint::generator() * &*secret_key)
            .to_affine()
            .into();

        Self {
            secret_key: secret_key,
            public_key: public_key,
        }
    }
}

pub fn hash_sha256(binary: &[u8]) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(binary);
    let hash = &hasher.finalize();

    BigUint::from_bytes_le(&hash.to_vec())
}

#[test]
fn test_generate_key_pair() {
    let mut rng = rand::thread_rng();
    let key_pair = KeyPair::random(rng);
}

#[test]
fn test_hash_sha256() {
    use hex_literal::hex;

    let result = hash_sha256(b"hello world");

    assert_eq!(
        result,
        BigUint::from_bytes_le(
            &hex!(
                "
    b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
"
            )
            .to_vec()
        )
    );
}
