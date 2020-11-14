use crate::authority::Authority;
use k256::{NonZeroScalar, Scalar};
use num_bigint::BigUint;
use rand::SeedableRng;

#[test]
fn test_auth() {
    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);
    let ts = BigUint::from(10 as u32);

    let mut rng = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng2 = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng3 = rand::rngs::StdRng::from_seed([0; 32]);
    let mut rng4 = rand::rngs::StdRng::from_seed([0; 32]);

    let authority = Authority::random(rng);

    let mut servicer = authority.register_servicer(10, &mut rng2);
    assert!(servicer.is_valid());

    let mut user = authority.register_user(id, h, &mut rng3);
    assert!(user.is_valid());

    let req = user.generate_auth_request(&ts, &mut rng4, &mut rng2);

    let VerWS = servicer.auth(&req, &mut rng3).unwrap();
    user.calc_session_key(&VerWS);

    let SKMU: NonZeroScalar = user.SK.unwrap();
    let SKWS: NonZeroScalar = servicer.SK.unwrap();

    let SKMU: Scalar = *SKMU.as_ref();
    let SKWS: Scalar = *SKWS.as_ref();

    assert!(SKMU == SKWS)
}
