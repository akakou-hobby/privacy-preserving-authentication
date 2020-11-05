
#[test]
fn test_auth() {
    use num_bigint::BigUint;
    use crate::authority::Authority;

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
}
