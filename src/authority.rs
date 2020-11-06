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

    pub fn register_user(
        &self,
        id: BigUint,
        h: BigUint,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> User {
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
            SK: None,
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
    pub fn random(
        authority: Authority,
        id: BigUint,
        h: BigUint,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Self {
        Self {
            id: id,
            h: h,
            authority: authority,
            r: NonZeroScalar::random(rng),
        }
    }

    pub fn register(&self, rng: &mut (impl CryptoRng + RngCore)) -> User {
        let s = self.authority.s.as_ref();

        let mut PK_bin = self.authority.PK.to_bytes().to_vec();
        // RMU = rMU·P
        let r = NonZeroScalar::random(rng);
        let r_ref = r.as_ref();

        let R = generate_public_key(&r);
        let R_bin = R.to_bytes().to_vec();

        // PIDMU = IDMU⊕H3(rMU‖PK)
        let mut hash = R_bin.clone();
        hash.push(00 as u8);
        hash.append(&mut PK_bin);

        let hash = hash_sha256(&hash);

        let PID = self.id.clone() ^ hash.clone();
        let mut PID_bin = PID.to_bytes_be();

        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut hash = R.to_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut PID_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let S = r_ref + hash * s;
        let S = NonZeroScalar::new(S).unwrap();

        let S_bin = S.as_ref();
        let mut S_bin = S_bin.to_bytes().to_vec();

        // PWVMU = H1(H1(IDMU‖PWMU)‖SMU)
        let mut hash = self.h.to_bytes_le();
        hash.push(00 as u8);
        hash.append(&mut S_bin);

        let hash = hash_sha256(&S_bin);

        let PWV = biguint_to_scalar(&hash);
        let PWV = NonZeroScalar::new(PWV).unwrap();

        User {
            id: self.id.clone(),
            R: R,
            S: S,
            PID: PID,
            PWV: PWV,
            PKas: self.authority.PK,
            PK: None,
            S_dash: None,
            a: None,
            P: None,
            SK: None,
            A: None,
        }
    }
}
