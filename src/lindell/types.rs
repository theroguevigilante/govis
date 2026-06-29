use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
use round_based::ProtocolMsg;
use serde::{Deserialize, Serialize};

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

pub struct LindellDkgOutput {
    pub secret_share: SecretScalar<Secp256k1>,
    pub public_key: Point<Secp256k1>,
}

#[derive(Serialize, Deserialize)]
pub struct LindellKeyData {
    pub protocol: String,
    pub party_index: u16,
    pub secret_share: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl LindellDkgOutput {
    pub fn to_key_data(&self, party_index: u16) -> LindellKeyData {
        LindellKeyData {
            protocol: "lindell".into(),
            party_index,
            secret_share: self.secret_share.as_ref().to_be_bytes().to_vec(),
            public_key: self.public_key.to_bytes(true).to_vec(),
        }
    }

    pub fn from_key_data(data: &LindellKeyData) -> Self {
        assert_eq!(data.protocol, "lindell", "key file protocol mismatch");
        let mut s = Scalar::<Secp256k1>::from_be_bytes_mod_order(&data.secret_share);
        Self {
            secret_share: SecretScalar::new(&mut s),
            public_key: Point::<Secp256k1>::from_bytes(&data.public_key)
                .expect("invalid public key in key data"),
        }
    }
}
