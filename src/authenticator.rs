use k256::{EncodedPoint, Secp256k1, NonZeroScalar, ProjectivePoint};
use rand::{CryptoRng, RngCore};


pub struct Authenticator {
    secret_key: NonZeroScalar,
    public_key: EncodedPoint
}

impl Authenticator {
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        let secret_key = NonZeroScalar::random(rng);
        let public_key = (ProjectivePoint::generator() * &*secret_key)
            .to_affine()
            .into();

        Self {
            secret_key: secret_key,
            public_key: public_key
        }
    }
}

#[test]
fn auth_random() {
    let mut rng = rand::thread_rng();
    let authenticator = Authenticator::random(rng);
}