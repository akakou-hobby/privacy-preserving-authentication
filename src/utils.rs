use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint, Secp256k1};
use rand::{CryptoRng, RngCore};

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

#[test]
fn test_generate_key_pair() {
    let mut rng = rand::thread_rng();
    let key_pair = KeyPair::random(rng);
}
