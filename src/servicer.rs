use crate::auth::{AuthRequest, AuthResponse};
use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint};
use rand::{CryptoRng, RngCore};

pub struct Servicer {
    pub id: u8,
    pub R: EncodedPoint,
    pub S: NonZeroScalar,
    pub PK: Option<EncodedPoint>,
    pub PKas: EncodedPoint,
    pub SK: Option<NonZeroScalar>,
}

impl Servicer {
    pub fn is_valid(&mut self) -> bool {
        let PKas = self.PKas.decode::<ProjectivePoint>().unwrap();
        let R = self.R.decode::<ProjectivePoint>().unwrap();

        // left
        let left = generate_public_key(&self.S);
        let left = left.decode::<ProjectivePoint>().unwrap();

        // right
        let mut hash = self.R.to_bytes().to_vec();
        hash.push(00 as u8);
        hash.push(self.id as u8);

        let hash = hash_sha256(&hash);
        let hash = biguint_to_scalar(&hash);
        let hash = NonZeroScalar::new(hash).unwrap();

        let right = R + PKas * &*hash;

        let PK = right.to_affine().into();
        self.PK = Some(PK);

        // check
        left == right
    }

    pub fn auth(
        &mut self,
        req: &AuthRequest,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> AuthResponse {
        req.is_valid(&self.PKas);

        let mut IDws_bin = self.id.to_be_bytes().to_vec();
        let mut P_bin = req.P.to_bytes().to_vec();

        let A = req.A.decode::<ProjectivePoint>().unwrap();
        let A_bin: EncodedPoint = A.to_affine().into();
        let mut A_bin = A_bin.to_bytes().to_vec();

        //  B = b·P
        let b = NonZeroScalar::random(rng);
        let B = generate_public_key(&b);

        // KWS − MU = SWS·A + b·PKM
        let PKmu = req.calc_PKmu(&self.PKas);
        let K: ProjectivePoint = A * self.S.as_ref() + PKmu * b.as_ref();
        let mut K_bin: EncodedPoint = K.to_affine().into();
        let mut K_bin = K_bin.to_bytes().to_vec();

        // SKWS − MU = H2(Ppid‖IDWS‖KWS − MU)
        let mut SK = P_bin;
        SK.append(&mut IDws_bin);
        SK.append(&mut K_bin);

        let SK = hash_sha256(&SK);
        let SK = biguint_to_scalar(&SK);
        let SK_bin = SK.to_bytes().to_vec();

        //  VerWS = H1(SKWS − MU‖A)
        let mut Ver = SK_bin;
        Ver.append(&mut A_bin);

        let Ver = hash_sha256(&Ver);
        let Ver = biguint_to_scalar(&Ver);
        let Ver = NonZeroScalar::new(Ver).unwrap();

        self.SK = NonZeroScalar::new(SK);

        AuthResponse {
            Ver: Ver,
            B: B,
            id: self.id,
            R: self.R,
            PK: self.PK.unwrap(),
        }
    }
}
