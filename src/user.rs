use crate::auth::{AuthRequest, AuthResponse};
use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

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
    pub A: Option<EncodedPoint>,
}

impl User {
    pub fn is_valid(&mut self) -> bool {
        let mut PID_bin = self.PID.to_bytes_be();
        let PKas = self.PKas.decode::<ProjectivePoint>().unwrap();
        let R = self.R.decode::<ProjectivePoint>().unwrap();

        // left
        let left = generate_public_key(&self.S);
        let left = left.decode::<ProjectivePoint>().unwrap();

        // right
        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut hash = self.R.to_bytes().to_vec();
        hash.push(00 as u8);
        hash.append(&mut PID_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);
        let hash = NonZeroScalar::new(hash).unwrap();

        let right = R + PKas * &*hash;

        let PK: EncodedPoint = right.to_affine().into();
        self.PK = Some(PK);

        left == right
    }

    pub fn generate_auth_request(
        &mut self,
        ts: &BigUint,
        rng1: &mut (impl CryptoRng + RngCore),
        rng2: &mut (impl CryptoRng + RngCore),
    ) -> AuthRequest {
        let mut PID_bin = self.PID.to_bytes_be();
        let mut R_bin = self.R.to_bytes().to_vec();
        let mut ts_bin = ts.to_bytes_be();
        let R_dash = self.R.decode::<ProjectivePoint>().unwrap();

        // A = a·P
        let a = NonZeroScalar::random(rng1);
        self.a = Some(a);

        let A = generate_public_key(&a);
        self.A = Some(A);
        let mut A_bin = A.to_bytes().to_vec();

        // c
        let c = NonZeroScalar::random(rng2);

        // Ppid = c·H1(PIDMU‖RMU),
        let mut hash = R_bin.clone();
        hash.push(00 as u8);
        hash.append(&mut PID_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let P = c.as_ref() * &hash;
        let P = NonZeroScalar::new(P).unwrap();
        self.P = Some(P);
        let mut P_bin = P.to_bytes().to_vec();

        // R' = c·R
        let R_dash = R_dash * c.as_ref();
        let R_dash: EncodedPoint = R_dash.to_affine().into();
        let mut R_dash_bin = R_dash.to_bytes().to_vec();

        // S' = c·S
        let S_dash = self.S.as_ref() * c.as_ref();
        let S_dash_scolar = NonZeroScalar::new(S_dash).unwrap();
        self.S_dash = Some(S_dash_scolar);

        // H = H(P||ts||R'||A)
        let mut H = P_bin;
        H.append(&mut ts_bin);
        H.append(&mut R_dash_bin);
        H.append(&mut A_bin);

        let H = hash_sha256(&H);
        let H = biguint_to_scalar(&H);

        // Ver = a + S'·H
        let Ver = a.as_ref() + S_dash * H;
        let Ver = NonZeroScalar::new(Ver).unwrap();

        AuthRequest {
            P: P,
            R_dash: R_dash,
            A: A,
            ts: ts.clone(),
            Ver: Ver,
        }
    }

    pub fn calc_session_key(&mut self, res: &AuthResponse) {
        let PKws = res.PK.decode::<ProjectivePoint>().unwrap();
        let B = res.B.decode::<ProjectivePoint>().unwrap();

        let S_dash = self.S_dash.unwrap();
        let P_bin = self.P.unwrap().to_bytes().to_vec();

        let mut IDws_bin = res.id.to_be_bytes().to_vec();

        // KWS − MU = S'MU·B + a·PKWS
        let K: ProjectivePoint = B * S_dash.as_ref() + PKws * self.a.unwrap().as_ref();
        let mut K_bin: EncodedPoint = K.to_affine().into();
        let mut K_bin = K_bin.to_bytes().to_vec();

        // SKMU − WS = H2(Ppid‖IDWS‖KMU − WS)
        let mut SK = P_bin;
        SK.append(&mut IDws_bin);
        SK.append(&mut K_bin);

        let SK = hash_sha256(&SK);
        let SK = biguint_to_scalar(&SK);
        let SK = NonZeroScalar::new(SK).unwrap();

        self.SK = Some(SK);

        assert!(res.is_valid(&SK, &self.A.unwrap()));
    }
}
