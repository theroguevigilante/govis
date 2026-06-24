use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_integer::Integer;
use rand_core::{CryptoRng, RngCore};
use round_based::ProtocolMsg;
use round_based::mpc::{CompleteRoundErr, Mpc, MpcExecution, SendMany};
use round_based::round::RoundInput;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mta;
use crate::paillier;
use crate::paillier_zk;

#[derive(ProtocolMsg, Clone, Debug, Serialize, Deserialize)]
pub enum PresignMsg {
    Round1(CommitMsg),
    Round2(RevealMsg),
    Round3(EncryptedKMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitMsg {
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealMsg {
    pub r_point: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedKMsg {
    pub c_k_share: Option<BigInt>,
    pub range_proof: Option<paillier_zk::RangeProof>,
}

#[derive(Clone, Debug)]
pub struct Presignature {
    pub k: Scalar<Secp256k1>,
    pub k_inv: Scalar<Secp256k1>,
    pub r: Scalar<Secp256k1>,
    pub r_point: Point<Secp256k1>,
}

pub fn point_x_coord(point: &Point<Secp256k1>) -> Scalar<Secp256k1> {
    let encoded = point.to_bytes(false);
    Scalar::<Secp256k1>::from_be_bytes_mod_order(&encoded.as_ref()[1..33])
}

pub fn lagrange_coeff(i: u16, signers: &[u16]) -> Scalar<Secp256k1> {
    let xi = Scalar::<Secp256k1>::from(i + 1);
    let mut num = Scalar::<Secp256k1>::one();
    let mut den = Scalar::<Secp256k1>::one();
    for &j in signers {
        if j == i {
            continue;
        }
        let xj = Scalar::<Secp256k1>::from(j + 1);
        num *= Scalar::<Secp256k1>::zero() - xj;
        den *= xi - xj;
    }
    num * den.invert().expect("signer indices must be distinct")
}

fn secp256k1_order() -> BigUint {
    BigUint::from_bytes_be(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ])
}

#[derive(Debug)]
pub enum Error<RecvErr, SendErr> {
    Round1Send(SendErr),
    Round1Receive(RecvErr),
    Round2Send(SendErr),
    Round2Receive(RecvErr),
    Round3Send(SendErr),
    Round3Receive(RecvErr),
    ProtocolViolation(&'static str),
}

pub type ErrorM<M> =
    Error<CompleteRoundErr<M, round_based::round::RoundInputError>, <M as Mpc>::SendErr>;

#[allow(clippy::too_many_arguments)]
pub async fn run_presign<M, R>(
    mut mpc: M,
    i: u16,
    signers: &[u16],
    _ec_share: &SecretScalar<Secp256k1>,
    peer_paillier_pks: &[Option<paillier::PaillierPublicKey>],
    my_paillier_sk: &paillier::PaillierPrivateKey,
    my_paillier_pk: &paillier::PaillierPublicKey,
    mut rng: R,
) -> Result<Presignature, ErrorM<M>>
where
    M: Mpc<Msg = PresignMsg>,
    R: RngCore + CryptoRng,
{
    let local_i = signers
        .iter()
        .position(|s| *s == i)
        .ok_or(Error::ProtocolViolation("party not in signer set"))? as u16;
    let m = signers.len() as u16;

    let round1 = mpc.add_round(RoundInput::<CommitMsg>::reliable_broadcast(local_i, m));
    let round2 = mpc.add_round(RoundInput::<RevealMsg>::reliable_broadcast(local_i, m));
    let round3 = mpc.add_round(RoundInput::<EncryptedKMsg>::p2p(local_i, m));
    let mut mpc = mpc.finish_setup();

    // Round 1: Commit to nonce share R_i = k_i·G
    let k_scalar = Scalar::<Secp256k1>::random(&mut rng);
    let r_point_share = Point::generator() * k_scalar;

    let commitment = {
        let mut h = Sha256::new();
        h.update(b"govis-cggmp21-presign-commit");
        h.update(local_i.to_be_bytes());
        h.update(r_point_share.to_bytes(true).as_ref());
        h.finalize().into()
    };

    mpc.reliably_broadcast(PresignMsg::Round1(CommitMsg { commitment }))
        .await
        .map_err(Error::Round1Send)?;

    let round1_msgs = mpc.complete(round1).await.map_err(Error::Round1Receive)?;

    // Round 2: Open commitment, verify, compute R
    mpc.reliably_broadcast(PresignMsg::Round2(RevealMsg {
        r_point: r_point_share,
    }))
    .await
    .map_err(Error::Round2Send)?;

    let round2_msgs = mpc.complete(round2).await.map_err(Error::Round2Receive)?;

    let mut r_point_total = r_point_share;
    for (sender_local, _, reveal_msg) in round2_msgs.iter_indexed() {
        let expected: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"govis-cggmp21-presign-commit");
            h.update(sender_local.to_be_bytes());
            h.update(reveal_msg.r_point.to_bytes(true).as_ref());
            h.finalize().into()
        };
        let commit_msg = round1_msgs
            .iter_indexed()
            .find(|(s, _, _)| *s == sender_local)
            .map(|(_, _, msg)| msg)
            .unwrap();
        if expected != commit_msg.commitment {
            return Err(Error::ProtocolViolation(
                "commitment mismatch in presign round 2",
            ));
        }
        r_point_total += reveal_msg.r_point;
    }

    let r = point_x_coord(&r_point_total);

    // Round 3: Send encrypted k_i under each signer's Paillier key (P2P)
    let k_bi = mta::scalar_to_bigint(&k_scalar);
    let order = BigInt::from_biguint(num_bigint::Sign::Plus, secp256k1_order());

    let mut send_many = mpc.send_many();
    for (local_peer, &peer) in signers.iter().enumerate() {
        let local_peer = local_peer as u16;
        if local_peer == local_i {
            continue;
        }
        if let Some(ref pk) = peer_paillier_pks[usize::from(peer)] {
            let n_bi = BigInt::from_biguint(num_bigint::Sign::Plus, pk.n.clone());
            let rho = rng.gen_bigint_range(&BigInt::from(1), &n_bi);
            let c_k_enc = pk.encrypt_with_rho(&k_bi, &rho);
            let range_proof = paillier_zk::prove_range(
                pk,
                &c_k_enc,
                &k_bi,
                &rho,
                256,
                b"govis-cggmp21-presign",
                &mut rng,
            );
            send_many
                .send_p2p(
                    local_peer,
                    PresignMsg::Round3(EncryptedKMsg {
                        c_k_share: Some(c_k_enc),
                        range_proof: Some(range_proof),
                    }),
                )
                .await
                .map_err(Error::Round3Send)?;
        }
    }
    let mut mpc = send_many.flush().await.map_err(Error::Round3Send)?;

    let round3_msgs = mpc.complete(round3).await.map_err(Error::Round3Receive)?;

    // Decrypt peer contributions to compute k = Σ k_i (mod q)
    let mut k_bi_total = k_bi.clone();
    for (sender_local, _, msg3) in round3_msgs.iter_indexed() {
        if sender_local == local_i {
            continue;
        }
        if let Some(c_k_share) = &msg3.c_k_share {
            let plaintext = my_paillier_sk.decrypt(my_paillier_pk, c_k_share);
            k_bi_total = (&k_bi_total + &plaintext).mod_floor(&order);
        }
    }

    let k_final = Scalar::<Secp256k1>::from_be_bytes_mod_order(&k_bi_total.to_bytes_be().1);
    let k_inv = k_final
        .invert()
        .expect("k is zero (astronomically unlikely)");

    Ok(Presignature {
        k: k_final,
        k_inv,
        r,
        r_point: r_point_total,
    })
}
