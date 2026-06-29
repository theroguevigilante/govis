use generic_ec::{Point, SecretScalar, curves::Secp256k1};
use udigest::Digestable;

#[derive(Digestable)]
pub struct Round1Data<'a> {
    pub sid: &'a [u8],
    pub i: u16,
    pub x_public: &'a [Point<Secp256k1>],
    pub y_public: &'a [Point<Secp256k1>],
}

pub struct DkgShares {
    pub commitments: Vec<Point<Secp256k1>>,
    pub secret_shares: Vec<SecretScalar<Secp256k1>>,
}

pub type RefreshShares = DkgShares;
