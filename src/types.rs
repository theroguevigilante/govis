use generic_ec::{Point, SecretScalar, curves::Secp256k1};
use round_based::ProtocolMessage;
use serde::{Deserialize, Serialize};
use udigest::Digestable;

#[derive(Digestable)]
pub struct Round1Data<'a> {
    pub sid: &'a [u8],
    pub i: u16,
    pub x_public: &'a [Point<Secp256k1>],
    pub y_public: &'a [Point<Secp256k1>],
}

#[derive(ProtocolMessage, Clone, Debug, Serialize, Deserialize)]
pub enum Msg {
    Round1(Round1Msg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Msg {
    pub commitment: [u8; 32],
}

pub struct DkgShares {
    pub commitments: Vec<Point<Secp256k1>>,
    pub secret_shares: Vec<SecretScalar<Secp256k1>>,
}

pub type RefreshShares = DkgShares;
