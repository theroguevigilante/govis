use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Cggmp21KeygenOutput {
    pub ec_share: generic_ec::SecretScalar<generic_ec::curves::Secp256k1>,
    pub public_key: generic_ec::Point<generic_ec::curves::Secp256k1>,
    pub paillier_sk: crate::paillier::PaillierPrivateKey,
    pub paillier_pk: crate::paillier::PaillierPublicKey,
    pub peer_paillier_pks: Vec<Option<crate::paillier::PaillierPublicKey>>,
}

#[derive(Serialize, Deserialize)]
pub struct Cggmp21KeyData {
    pub protocol: String,
    pub party_index: u16,
    pub ec_share: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Cggmp21KeygenOutput {
    pub fn to_key_data(&self, party_index: u16) -> Cggmp21KeyData {
        Cggmp21KeyData {
            protocol: "cggmp21".into(),
            party_index,
            ec_share: self.ec_share.as_ref().to_be_bytes().to_vec(),
            public_key: self.public_key.to_bytes(true).to_vec(),
        }
    }

    pub fn from_key_data(data: &Cggmp21KeyData) -> Self {
        assert_eq!(data.protocol, "cggmp21", "key file protocol mismatch");
        let mut s = Scalar::<Secp256k1>::from_be_bytes_mod_order(&data.ec_share);
        let paillier_sk = crate::paillier::PaillierPrivateKey {
            lambda: num_bigint::BigUint::from(0u32),
            mu: num_bigint::BigUint::from(0u32),
        };
        let paillier_pk = crate::paillier::PaillierPublicKey {
            n: num_bigint::BigUint::from(0u32),
            n_sq: num_bigint::BigUint::from(0u32),
            g: num_bigint::BigUint::from(0u32),
        };
        Self {
            ec_share: SecretScalar::new(&mut s),
            public_key: Point::<Secp256k1>::from_bytes(&data.public_key)
                .expect("invalid public key in key data"),
            paillier_sk,
            paillier_pk,
            peer_paillier_pks: Vec::new(),
        }
    }
}
