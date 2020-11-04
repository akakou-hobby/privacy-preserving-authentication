use crate::servicer::Servicer;
use crate::utils::{hash_sha256, generate_public_key};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub struct Authority {
    pub s: NonZeroScalar,
    pub PK: EncodedPoint
}

impl Authority {
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        let s = NonZeroScalar::random(rng);
        let pk = generate_public_key(&s);

        Self {
            s: s,
            PK: pk
        }
    }
}

pub struct ServicerRegistration {
    id: u8,
    r: NonZeroScalar,
    s: NonZeroScalar
}

impl ServicerRegistration {
    pub fn random(s: NonZeroScalar, id: u8, mut rng: impl CryptoRng + RngCore) -> Self {
        ServicerRegistration {
            id: id,
            s: s,
            r: NonZeroScalar::random(rng)
        }
    }

    pub fn register(&self) -> Servicer {
        let R = generate_public_key(&self.s);

        let mut hash = R.to_bytes().to_vec();
        hash.push(00 as u8);
        hash.push(self.id as u8);

        let hash = hash_sha256(&hash);

        let r = self.r.invert().unwrap().truncate_to_u32();
        let r = BigUint::from(r);

        let S = self.s.invert().unwrap().truncate_to_u32();
        let S = BigUint::from(S);

        let S = r + hash * S;

        Servicer {
            id: self.id,
            R: R,
            S: S
        }
    }
}

#[test]
fn test_generate_authority() {
    let rng = rand::thread_rng();
    Authority::random(rng);
}


#[test]
fn test_register_servicer() {
    let rng = rand::thread_rng();
    let authority = Authority::random(rng);

    let registration = ServicerRegistration::random(authority.s, 10, rng);
    registration.register();
}
