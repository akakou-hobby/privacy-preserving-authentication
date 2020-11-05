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
    pub PK: Option<EncodedPoint>
}

pub struct AuthRequest {
    pub P: NonZeroScalar,
    pub R_dash: EncodedPoint,
    pub A: EncodedPoint,
    pub ts: BigUint,
    pub Ver: NonZeroScalar
}

impl User {
    pub fn is_valid(&mut self) -> bool {
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

        let PK: EncodedPoint = right.to_affine().into();
        self.PK = Some(PK);

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
        println!("{}", hash);
        let hash = biguint_to_scalar(&hash);

        let P = c.as_ref() * &hash;
        let P = NonZeroScalar::new(P).unwrap();

        // R' = c·R
        let R_dash = self.R.decode::<ProjectivePoint>().unwrap();
        let R_dash = R_dash * c.as_ref();
        let R_dash: EncodedPoint = R_dash.to_affine().into();

        // S' = c·S
        let S_dash = self.S.as_ref() * c.as_ref();
     
        // H = H(P||ts||R'||A)
        let mut ts_bin = ts.to_bytes_be();
        let mut R_dash_bin = R_dash.to_bytes().to_vec();
        let mut A_bin = A.to_bytes().to_vec();
        
        let mut H = P.to_bytes().to_vec();

        H.append(&mut ts_bin);
        H.append(&mut R_dash_bin);
        H.append(&mut A_bin);

        let H = hash_sha256(&H);
        println!("{}", H);
        let H = biguint_to_scalar(&H);

        // Ver = a + S'·H
        let Ver = a.as_ref() + S_dash * H;
        let Ver = NonZeroScalar::new(Ver).unwrap();

        AuthRequest {
            P: P,
            R_dash: R_dash,
            A: A,
            ts: ts.clone(),
            Ver: Ver
        }
    }
}


impl AuthRequest {
    pub fn calc_PKmu(&self, PKas: &EncodedPoint) -> ProjectivePoint { 
        let PKas = PKas.decode::<ProjectivePoint>().unwrap();
        let R__dash = self.R_dash.decode::<ProjectivePoint>().unwrap();

        R__dash + PKas * &*self.P
    }
    
    pub fn is_valid(&self, PKas: &EncodedPoint) -> bool {
        // PKmu = R'mu + Ppid * PK
        let PKmu = self.calc_PKmu(PKas);

        // H = H(P||ts||R||A)
        let mut ts_bin = self.ts.to_bytes_be();
        let mut R_dash_bin = self.R_dash.to_bytes().to_vec();
        let mut A_bin = self.A.to_bytes().to_vec();
        
        let mut Hmu = self.P.to_bytes().to_vec();
        Hmu.append(&mut ts_bin);
        Hmu.append(&mut R_dash_bin);
        Hmu.append(&mut A_bin);

        let Hmu = hash_sha256(&Hmu);
        println!("{}", Hmu);
        let Hmu = biguint_to_scalar(&Hmu);
        
        // VerMU·P = A + PKMU·HMU 
        let left = generate_public_key(&self.Ver)
                .decode::<ProjectivePoint>()
                .unwrap();

        let A = self.A.decode::<ProjectivePoint>().unwrap();
        let right = A + PKmu * Hmu;

        right == left
    }
}

#[test]
fn test_verify_user() {
    use crate::authority::Authority;

    let mut rng = rand::thread_rng();

    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);

    let authority = Authority::random(rng);
    let mut user = authority.register_user(id, h, &mut rng);

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
    let mut user = authority.register_user(id, h, &mut rng);

    let ts = BigUint::from(10 as u32);
    let request = user.generate_auth_request(&ts, &mut rng, &mut rng2);

    let result = request.is_valid(&authority.PK);
    assert!(result);
}
