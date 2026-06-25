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

#[derive(Serialize, Deserialize)]
pub struct LindellKeyData {
    pub protocol: String,
    pub secret_share: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl DkgOutput {
    pub fn to_key_data(&self) -> LindellKeyData {
        LindellKeyData {
            protocol: "lindell".into(),
            secret_share: self.secret_share.as_ref().to_be_bytes().to_vec(),
            public_key: self.public_key.to_bytes(true).to_vec(),
        }
    }

    pub fn from_key_data(data: &LindellKeyData) -> Self {
        assert_eq!(data.protocol, "lindell", "key file protocol mismatch");
        use generic_ec::{Scalar, SecretScalar};
        let mut s = Scalar::<Secp256k1>::from_be_bytes_mod_order(&data.secret_share);
        Self {
            secret_share: SecretScalar::new(&mut s),
            public_key: Point::<Secp256k1>::from_bytes(&data.public_key)
                .expect("invalid public key in key data"),
        }
    }
}

pub struct DkgShares {
    pub commitments: Vec<Point<Secp256k1>>,
    pub secret_shares: Vec<SecretScalar<Secp256k1>>,
}

pub type RefreshShares = DkgShares;

#[derive(Serialize, Deserialize)]
pub struct Cggmp21KeyData {
    pub protocol: String,
    pub ec_share: Vec<u8>,
    pub public_key: Vec<u8>,
}
