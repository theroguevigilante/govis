use generic_ec::{Point, SecretScalar, curves::Secp256k1};

pub struct DkgShares {
    pub commitments: Vec<Point<Secp256k1>>,
    pub secret_shares: Vec<SecretScalar<Secp256k1>>,
}

pub type RefreshShares = DkgShares;
