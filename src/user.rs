use crate::utils::{biguint_to_scalar, scalar_to_biguint, generate_public_key, hash_sha256};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub struct User {
    pub id: BigUint,
    pub R: EncodedPoint,
    pub S: NonZeroScalar,
    pub PID: BigUint,
    pub PWV: NonZeroScalar,
    pub PKas: EncodedPoint,
}

pub struct AuthRequest {
    pub P: NonZeroScalar,
    pub R_dash: EncodedPoint,
    pub A: EncodedPoint,
    pub ts: BigUint,
    pub Ver: NonZeroScalar
}

impl User {
    pub fn is_valid(&self) -> bool {
        // left
        let left = generate_public_key(&self.S);
        let left = left.decode::<ProjectivePoint>().unwrap();

        // right
        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut PID_bin = self.PID.to_bytes_be(); 
        let mut hash = self.R.to_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut PID_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);
        let hash = NonZeroScalar::new(hash).unwrap();

        let PKas = self.PKas.decode::<ProjectivePoint>().unwrap();
        let R = self.R.decode::<ProjectivePoint>().unwrap();
        let right = R + PKas * &*hash;

        // println!("left. {:?}", left);
        // println!("right. {:?}", right);

        // check
        left == right
    }

    pub fn generate_auth_request(&self, ts: &BigUint, rng1: &mut (impl CryptoRng + RngCore), rng2: &mut (impl CryptoRng + RngCore)) -> AuthRequest {
        // A = a·P
        let a = NonZeroScalar::random(rng1);
        let A = generate_public_key(&a);

        let c = NonZeroScalar::random(rng2);

        // Ppid = c·H1(PIDMU‖RMU),
        let mut PID_bin = self.PID.to_bytes_be(); 
        let mut hash = self.R.to_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut PID_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);
        let hash = NonZeroScalar::new(hash).unwrap();

        let P = c.as_ref() * hash.as_ref();
        let P = NonZeroScalar::new(P).unwrap();

        // R' = c·R
        let R_dash = self.R.decode::<ProjectivePoint>().unwrap();
        let R_dash = R_dash * &*c;

        // S' = c·S
        let S_dash = self.S.as_ref() * &*c;
     
        // H = H(P||ts||R||A)
        let mut ts_bin = ts.to_bytes_be();
        let mut R_bin = self.R.to_bytes().to_vec();
        let mut A_bin = A.to_bytes().to_vec();
        
        let mut H = scalar_to_biguint(&P).unwrap().to_bytes_be();
        H.append(&mut ts_bin);
        H.append(&mut R_bin);
        H.append(&mut A_bin);
        
        let Ver = a.as_ref() + S_dash;
        let Ver = NonZeroScalar::new(Ver).unwrap();

        let R_dash = R_dash.to_affine().into();

        AuthRequest {
            P: P,
            R_dash: R_dash,
            A: A,
            ts: ts.clone(),
            Ver: Ver
        }
    }
}

#[test]
fn test_verify_user() {
    use crate::authority::Authority;

    let mut rng = rand::thread_rng();

    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);

    let authority = Authority::random(rng);
    let user = authority.register_user(id, h, &mut rng);

    let result = user.is_valid();
    assert!(result);
}

#[test]
fn test_generate_auth_request() {
    use crate::authority::Authority;

    let mut rng = rand::thread_rng();
    let mut rng2 = rand::thread_rng();

    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);

    let authority = Authority::random(rng);
    let user = authority.register_user(id, h, &mut rng);

    let ts = BigUint::from(10 as u32);
    let result = user.generate_auth_request(&ts, &mut rng, &mut rng2);
}

