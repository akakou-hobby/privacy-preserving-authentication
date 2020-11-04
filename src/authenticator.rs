use crate::utils::KeyPair;
use rand::{CryptoRng, RngCore};

pub struct Authenticator {
    pub key_pair: KeyPair,
}

impl Authenticator {
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        Self {
            key_pair: KeyPair::random(rng),
        }
    }
}

#[test]
fn test_generate_authenticator() {
    let mut rng = rand::thread_rng();
    let authenticator = Authenticator::random(rng);
}
