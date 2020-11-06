use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint, Scalar};
use num_bigint::BigUint;

pub struct AuthRequest {
    pub P: NonZeroScalar,
    pub R_dash: EncodedPoint,
    pub A: EncodedPoint,
    pub ts: BigUint,
    pub Ver: NonZeroScalar,
}

pub struct AuthResponse {
    pub Ver: NonZeroScalar,
    pub B: EncodedPoint,
    pub id: u8,
    pub R: EncodedPoint,
    pub PK: EncodedPoint,
}

impl AuthRequest {
    pub fn calc_PKmu(&self, PKas: &EncodedPoint) -> ProjectivePoint {
        let PKas = PKas.decode::<ProjectivePoint>().unwrap();
        let R__dash = self.R_dash.decode::<ProjectivePoint>().unwrap();

        R__dash + PKas * &*self.P
    }

    pub fn is_valid(&self, PKas: &EncodedPoint) -> bool {
        let mut ts_bin = self.ts.to_bytes_be();
        let mut R_dash_bin = self.R_dash.to_bytes().to_vec();
        let mut A_bin = self.A.to_bytes().to_vec();
        let mut P_bin = self.P.to_bytes().to_vec();

        let A = self.A.decode::<ProjectivePoint>().unwrap();

        // PKmu = R'mu + Ppid * PK
        let PKmu = self.calc_PKmu(PKas);

        // H = H(P||ts||R||A)
        let mut Hmu = P_bin;
        Hmu.append(&mut ts_bin);
        Hmu.append(&mut R_dash_bin);
        Hmu.append(&mut A_bin);

        let Hmu = hash_sha256(&Hmu);
        let Hmu = biguint_to_scalar(&Hmu);

        // VerMU·P = A + PKMU·HMU
        let left = generate_public_key(&self.Ver)
            .decode::<ProjectivePoint>()
            .unwrap();

        let right = A + PKmu * Hmu;

        right == left
    }
}

impl AuthResponse {
    pub fn is_valid(&self, SK: &NonZeroScalar, A: &EncodedPoint) -> bool {
        let mut A_bin = A.to_bytes().to_vec();
        let mut SK_bin = SK.to_bytes().to_vec();

        // H1(SKMU − WS‖A)
        let mut hash = SK_bin;
        hash.append(&mut A_bin);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);

        let Ver: Scalar = *self.Ver.as_ref();
        Ver == hash
    }
}
