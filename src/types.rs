use generic_ec::{Point, SecretScalar, curves::Secp256k1};
use round_based::ProtocolMsg;
use serde::{Deserialize, Serialize};
use udigest::Digestable;

#[derive(Digestable)]
pub struct Round1Data<'a> {
    pub sid: &'a [u8],
    pub i: u16,
    pub x_public: &'a [Point<Secp256k1>],
    pub y_public: &'a [Point<Secp256k1>],
}

#[derive(ProtocolMsg, Clone, Debug, Serialize, Deserialize)]
pub enum Msg {
    Round1(CommitMsg),
    Round2(RevealMsg),
    Round3(ShareMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitMsg {
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealMsg {
    pub public_coeffs: Vec<Point<Secp256k1>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareMsg {
    pub share: SecretScalar<Secp256k1>,
}

pub struct DkgOutput {
    pub secret_share: SecretScalar<Secp256k1>,
    pub public_key: Point<Secp256k1>,
}

pub struct DkgShares {
    pub commitments: Vec<Point<Secp256k1>>,
    pub secret_shares: Vec<SecretScalar<Secp256k1>>,
}

pub type RefreshShares = DkgShares;
