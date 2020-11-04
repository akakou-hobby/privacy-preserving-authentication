use crate::servicer::Servicer;
use crate::utils::{generate_public_key, hash_sha256, scalar_to_biguint, biguint_to_scalar};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct Authority {
    pub s: NonZeroScalar,
    pub PK: EncodedPoint
}

impl Authority {
    pub fn random(rng: impl RngCore + CryptoRng) -> Self {
        let s = NonZeroScalar::random(rng);
        let PK = generate_public_key(&s);

        Self { s: s, PK: PK}
    }

    pub fn register_servicer(&self, id: u8, rng: &mut (impl CryptoRng + RngCore)) -> Servicer {
        let register = ServicerRegister::random(self.clone(), id, rng);
        register.register(rng)
    }
}

pub struct ServicerRegister {
    id: u8,
    r: NonZeroScalar,
    authority: Authority
}

impl ServicerRegister {
    pub fn random(authority: Authority, id: u8, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            id: id,
            authority: authority,
            r: NonZeroScalar::random(rng)
        }
    }

    pub fn register(&self, rng: &mut (impl CryptoRng + RngCore)) -> Servicer {
        let r = NonZeroScalar::random(rng);
        let R = generate_public_key(&r);

        let mut hash = R.to_bytes().to_vec();
        hash.push(00 as u8);
        hash.push(self.id as u8);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let r = r.as_ref();
        let s = self.authority.s.as_ref();

        let S = r + hash * s;
        let S = NonZeroScalar::new(S).unwrap();

        Servicer {
            id: self.id,
            R: R,
            S: S,
            PK: None,
            PKas: self.authority.PK
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
    let mut rng = rand::thread_rng();

    let authority = Authority::random(rng);
    authority.register_servicer(10, &mut rng);
}
