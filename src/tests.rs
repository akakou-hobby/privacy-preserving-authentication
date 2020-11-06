use num_bigint::BigUint;
use crate::authority::Authority;
use k256::{EncodedPoint, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1};


#[test]
fn test_auth() {

    let mut rng = rand::thread_rng();

    let authority = Authority::random(rng);
    let mut servicer = authority.register_servicer(10, &mut rng);
    servicer.is_valid();

    let mut rng = rand::thread_rng();
    let mut rng2 = rand::thread_rng();

    let id = BigUint::from(10 as u32);
    let h = BigUint::from(10 as u32);

    let mut user = authority.register_user(id, h, &mut rng);

    let ts = BigUint::from(10 as u32);
    let req = user.generate_auth_request(&ts, &mut rng, &mut rng2);

    println!("{}", req.is_valid(&user.PKas));
    println!("{}", req.is_valid(&authority.PK));
    println!("{}", req.is_valid(&servicer.PKas));

    let mut rng3 = rand::thread_rng();

    let VerWS = servicer.auth(&req, &mut rng3);
    user.calc_session_key(&VerWS);

    let SKMU : NonZeroScalar = user.SK.unwrap();
    let SKWS : NonZeroScalar = servicer.SK.unwrap();

    let SKMU : Scalar = *SKMU.as_ref();
    let SKWS : Scalar = *SKWS.as_ref();
    assert!(SKMU == SKWS)
}
