use crate::servicer::Servicer;
use crate::user::User;
use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

use num_bigint::BigUint;

use k256::{EncodedPoint, NonZeroScalar};
use rand::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct Authority {
    pub s: NonZeroScalar,
    pub PK: EncodedPoint,
}

impl Authority {
    pub fn random(rng: impl RngCore + CryptoRng) -> Self {
        let s = NonZeroScalar::random(rng);
        let PK = generate_public_key(&s);

        Self { s: s, PK: PK }
    }

    pub fn register_servicer(&self, id: u8, rng: &mut (impl CryptoRng + RngCore)) -> Servicer {
        let register = ServicerRegister::random(self.clone(), id, rng);
        register.register(rng)
    }

    pub fn register_user(&self, id: BigUint, h: BigUint, rng: &mut (impl CryptoRng + RngCore)) -> User {
        let register = UserRegister::random(self.clone(), id, h, rng);
        register.register(rng)
    }
}

pub struct ServicerRegister {
    id: u8,
    r: NonZeroScalar,
    authority: Authority,
}

impl ServicerRegister {
    pub fn random(authority: Authority, id: u8, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            id: id,
            authority: authority,
            r: NonZeroScalar::random(rng),
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
            PKas: self.authority.PK,
        }
    }
}

pub struct UserRegister {
    id: BigUint,
    h: BigUint,
    r: NonZeroScalar,
    authority: Authority,
}

impl UserRegister {
    pub fn random(authority: Authority, id: BigUint, h: BigUint, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            id: id,
            h: h,
            authority: authority,
            r: NonZeroScalar::random(rng),
        }
    }

    pub fn register(&self, rng: &mut (impl CryptoRng + RngCore)) -> User {
        // RMU = rMU·P
        let r = NonZeroScalar::random(rng);
        let R = generate_public_key(&r);

        // PIDMU = IDMU⊕H3(rMU‖PK)
        let mut PK = self.authority.PK.to_bytes().to_vec();
        let mut hash1 = R.to_bytes().to_vec();
        hash1.push(00 as u8);
        hash1.append(&mut PK);

        let hash1 = hash_sha256(&hash1);
        let PID = self.id.clone() ^ self.h.clone();

        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut PID_bin = PID.to_bytes_be();
        let mut hash2 = R.to_bytes().to_vec();
        hash2.push(00 as u8);
        hash2.append(&mut PID_bin);

        let hash2 = hash_sha256(&hash2);
        let hash2 = biguint_to_scalar(&hash2);

        let r = r.as_ref();
        let s = self.authority.s.as_ref();

        let S = r + hash2 * s;
        let S = NonZeroScalar::new(S).unwrap();

        // PWVMU = H1(H1(IDMU‖PWMU)‖SMU)
        let S_bin = S.as_ref();
        let mut S_bin = S_bin.to_bytes().to_vec();
        let mut hash3 = self.h.to_bytes_le();
        hash3.push(00 as u8);
        hash3.append(&mut S_bin);

        let hash3 = hash_sha256(&S_bin);
        let PWV = biguint_to_scalar(&hash3);
        let PWV = NonZeroScalar::new(PWV).unwrap();

        User {
            id: self.id.clone(),
            R: R,
            S: S,
            PID: PID,
            PWV: PWV,
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

#[test]
fn test_register_user() {
    let mut rng = rand::thread_rng();

    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);
    let authority = Authority::random(rng);
    authority.register_user(id, h, &mut rng);
}