use crate::utils::{biguint_to_scalar, generate_public_key, hash_sha256};

use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint};
use num_bigint::BigUint;

pub struct User {
    pub id: BigUint,
    pub R: EncodedPoint,
    pub S: NonZeroScalar,
    pub PID: BigUint,
    pub PWV: NonZeroScalar,
    pub PKas: EncodedPoint,
}

impl User {
    pub fn is_valid(&self) -> bool {
        // left
        let left = generate_public_key(&self.S);
        let left = left.decode::<ProjectivePoint>().unwrap();

        // right
        // SMU = rMU + H1(PIDMU‖RMU)·s
        let mut PID_bin = self.PID.to_bytes_be(); 
        let mut hash2 = self.R.to_bytes().to_vec();
        hash2.push(00 as u8);
        hash2.append(&mut PID_bin);

        let hash2 = hash_sha256(&hash2);
        let hash = biguint_to_scalar(&hash2);
        let hash = NonZeroScalar::new(hash).unwrap();

        let PKas = self.PKas.decode::<ProjectivePoint>().unwrap();
        let R = self.R.decode::<ProjectivePoint>().unwrap();
        let right = R + PKas * &*hash;

        // println!("left. {:?}", left);
        // println!("right. {:?}", right);

        // check
        left == right
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
