use crate::utils::{biguint_to_scalar, scalar_to_biguint, generate_public_key, hash_sha256};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

pub struct AuthRequest {
    pub P: NonZeroScalar,
    pub R_dash: EncodedPoint,
    pub A: EncodedPoint,
    pub ts: BigUint,
    pub Ver: NonZeroScalar
}

pub struct AuthResponse {
    pub Ver: NonZeroScalar
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

