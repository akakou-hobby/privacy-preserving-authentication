use crate::servicer::Servicer;
use crate::utils::{hash_sha256, KeyPair};

use k256::{NonZeroScalar, ProjectivePoint};
use num_bigint::BigUint;
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

pub struct ServicerRegistration {
    id: u8,
    r: NonZeroScalar,
}

impl ServicerRegistration {
    pub fn random(id: u8, mut rng: impl CryptoRng + RngCore) -> Self {
        ServicerRegistration {
            id: id,
            r: NonZeroScalar::random(rng),
        }
    }

    pub fn register(&self, key_pair: &KeyPair) -> Servicer {
        let public_key = (ProjectivePoint::generator() * &*self.r).to_affine().into();

        let mut hash = key_pair.public_key.to_bytes().to_vec();
        hash.push(00 as u8);
        hash.push(self.id as u8);

        let hash = hash_sha256(&hash);

        let s = key_pair.secret_key.invert().unwrap().truncate_to_u32();
        let s = BigUint::from(s);

        let r = self.r.invert().unwrap().truncate_to_u32();
        let r = BigUint::from(r);

        let private_key = r + hash * s;

        Servicer {
            id: self.id,
            r: public_key,
            s: private_key,
        }
    }
}

#[test]
fn test_generate_authenticator() {
    let mut rng = rand::thread_rng();
    let authenticator = Authenticator::random(rng);
}


#[test]
fn test_register_servicer() {
    let mut rng = rand::thread_rng();
    let authenticator = Authenticator::random(rng);

    let registration = ServicerRegistration::random(10, rng);
    registration.register(&authenticator.key_pair);
}
