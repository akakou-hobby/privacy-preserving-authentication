use crate::authority::Authority;
use k256::{NonZeroScalar, Scalar};
use num_bigint::BigUint;

#[test]
fn test_auth() {
    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);
    let ts = BigUint::from(10 as u32);

    let mut rng = rand::thread_rng();
    let mut rng2 = rand::thread_rng();
    let mut rng3 = rand::thread_rng();

    let authority = Authority::random(rng);

    let mut servicer = authority.register_servicer(10, &mut rng);
    assert!(servicer.is_valid());

    let mut user = authority.register_user(id, h, &mut rng);
    assert!(user.is_valid());

    let req = user.generate_auth_request(&ts, &mut rng, &mut rng2);

    let VerWS = servicer.auth(&req, &mut rng3).unwrap();
    user.calc_session_key(&VerWS);

    let SKMU: NonZeroScalar = user.SK.unwrap();
    let SKWS: NonZeroScalar = servicer.SK.unwrap();

    let SKMU: Scalar = *SKMU.as_ref();
    let SKWS: Scalar = *SKWS.as_ref();

    assert!(SKMU == SKWS)
}
