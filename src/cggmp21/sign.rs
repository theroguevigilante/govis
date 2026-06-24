use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
use round_based::ProtocolMsg;
use round_based::mpc::{CompleteRoundErr, Mpc, MpcExecution};
use round_based::round::RoundInput;
use serde::{Deserialize, Serialize};

use super::presign::{Presignature, lagrange_coeff};
use crate::lindell::sign::verify_signature;

#[derive(ProtocolMsg, Clone, Debug, Serialize, Deserialize)]
pub enum OnlineSignMsg {
    Round1(SignatureShareMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureShareMsg {
    pub s_i: Vec<u8>,
}

#[derive(Debug)]
pub struct Signature {
    pub r_bytes: Vec<u8>,
    pub s_bytes: Vec<u8>,
    pub rec_id: u8,
}

#[derive(Debug)]
pub enum Error<RecvErr, SendErr> {
    Round1Send(SendErr),
    Round1Receive(RecvErr),
    ProtocolViolation(&'static str),
    InvalidSignature,
}

pub type ErrorM<M> =
    Error<CompleteRoundErr<M, round_based::round::RoundInputError>, <M as Mpc>::SendErr>;

pub fn recovery_id(r_point: &Point<Secp256k1>) -> u8 {
    use generic_ec::coords::HasAffineXAndParity;
    let (_, parity) = r_point.x_and_parity().expect("r_point cannot be identity");
    if parity.is_odd() { 1 } else { 0 }
}

/// 1-round online signing.
pub async fn run_online_sign<M>(
    mut mpc: M,
    i: u16,
    signers: &[u16],
    ec_share: &SecretScalar<Secp256k1>,
    public_key: &Point<Secp256k1>,
    msg_digest: &[u8; 32],
    presig: &Presignature,
) -> Result<Signature, ErrorM<M>>
where
    M: Mpc<Msg = OnlineSignMsg>,
{
    let local_i = signers
        .iter()
        .position(|s| *s == i)
        .ok_or(Error::ProtocolViolation("party not in signer set"))? as u16;
    let m = signers.len() as u16;

    let round1 = mpc.add_round(RoundInput::<SignatureShareMsg>::p2p(local_i, m));
    let mut mpc = mpc.finish_setup();

    // s_i = k⁻¹ · λ_i · (m + r · x_i)
    let lambda = lagrange_coeff(i, signers);
    let msg = Scalar::<Secp256k1>::from_be_bytes_mod_order(msg_digest);
    let s_i = presig.k_inv * lambda * (msg + presig.r * ec_share.as_ref());
    let s_i_bytes = s_i.to_be_bytes().to_vec();
    for (local_peer, _peer) in signers.iter().enumerate() {
        let local_peer = local_peer as u16;
        if local_peer == local_i {
            continue;
        }
        mpc.send_p2p(
            local_peer,
            OnlineSignMsg::Round1(SignatureShareMsg {
                s_i: s_i_bytes.clone(),
            }),
        )
        .await
        .map_err(Error::Round1Send)?;
    }

    let round1_msgs = mpc.complete(round1).await.map_err(Error::Round1Receive)?;

    // s = Σ s_j (this party's s_i + received peer shares)
    let mut s_total = s_i;
    for (sender_local, _, msg1) in round1_msgs.iter_indexed() {
        if sender_local == local_i {
            continue;
        }
        let s_j = Scalar::<Secp256k1>::from_be_bytes_mod_order(&msg1.s_i);
        s_total += s_j;
    }

    let r_bytes = presig.r.to_be_bytes().to_vec();
    let s_bytes = s_total.to_be_bytes().to_vec();

    if !verify_signature(public_key, msg_digest, &r_bytes, &s_bytes) {
        return Err(Error::InvalidSignature);
    }

    Ok(Signature {
        r_bytes,
        s_bytes,
        rec_id: recovery_id(&presig.r_point),
    })
}
