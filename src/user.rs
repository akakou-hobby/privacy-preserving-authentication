use crate::utils::{biguint_to_scalar, scalar_to_biguint, generate_public_key, hash_sha256};
use crate::auth::{AuthRequest, AuthResponse};

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
    pub PK: Option<EncodedPoint>,
    pub S_dash: Option<NonZeroScalar>,
    pub a: Option<NonZeroScalar>,
    pub P: Option<NonZeroScalar>,
    pub SK: Option<NonZeroScalar>,
    pub A: Option<EncodedPoint>
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

    pub fn generate_auth_request(&mut self, ts: &BigUint, rng1: &mut (impl CryptoRng + RngCore), rng2: &mut (impl CryptoRng + RngCore)) -> AuthRequest {
        // A = a·P
        let a = NonZeroScalar::random(rng1);
        let A = generate_public_key(&a);
        
        self.a = Some(a);
        self.A = Some(A);

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
        self.P = Some(P);

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

        let S_dash = NonZeroScalar::new(S_dash).unwrap();
        self.S_dash = Some(S_dash);

        AuthRequest {
            P: P,
            R_dash: R_dash,
            A: A,
            ts: ts.clone(),
            Ver: Ver
        }
    }

    pub fn calc_session_key(&mut self, res: &AuthResponse) {
        // KWS − MU = S'MU·B + a·PKWS
        let PKws = res.PK.decode::<ProjectivePoint>().unwrap();
        let B = res.B.decode::<ProjectivePoint>().unwrap();
        let S_dash = self.S_dash.unwrap().as_ref();
        

        let K : ProjectivePoint = B * self.S.as_ref() + PKws * self.a.unwrap().as_ref();

        // SKMU − WS = H2(Ppid‖IDWS‖KMU − WS)
        let mut IDws_bin = res.id.to_be_bytes().to_vec();
        let mut K_bin : EncodedPoint = K.to_affine().into();
        let mut K_bin = K_bin.to_bytes().to_vec();

        let mut SK = self.P.unwrap().to_bytes().to_vec();
        SK.append(&mut IDws_bin);
        SK.append(&mut K_bin);

        let SK = hash_sha256(&SK);
        let SK = biguint_to_scalar(&SK);
        let SK = NonZeroScalar::new(SK).unwrap();
        
        self.SK = Some(SK);

        assert!(res.is_valid(&SK, &self.A.unwrap()));

    }
}
