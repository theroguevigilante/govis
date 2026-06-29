use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
use num_bigint::{BigInt, BigUint, RandBigInt};
use round_based::ProtocolMsg;
use round_based::mpc::{CompleteRoundErr, Mpc, MpcExecution};
use round_based::round::RoundInput;
use serde::{Deserialize, Serialize};

use crate::core::{biguint_to_scalar, lagrange_coeff, point_x_coord, scalar_to_bigint};
use crate::paillier;
use crate::paillier_zk;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn verify_signature(
    public_key: &Point<Secp256k1>,
    msg_digest: &[u8; 32],
    r_bytes: &[u8],
    s_bytes: &[u8],
) -> bool {
    let r = Scalar::<Secp256k1>::from_be_bytes_mod_order(r_bytes);
    let s = Scalar::<Secp256k1>::from_be_bytes_mod_order(s_bytes);
    let z = Scalar::<Secp256k1>::from_be_bytes_mod_order(msg_digest);
    let s_inv = s.invert().unwrap_or(Scalar::zero());
    let u1 = z * s_inv;
    let u2 = r * s_inv;
    let p = Point::generator() * u1 + public_key * u2;
    let calculated_r = point_x_coord(&p);
    r == calculated_r
}

pub fn recovery_id(r_point: &Point<Secp256k1>) -> u8 {
    let bytes = r_point.to_bytes(false);
    bytes.as_bytes()[32] % 2
}

pub fn ethereum_signature(
    r_bytes: &[u8],
    s_bytes: &[u8],
    rec_id: u8,
    chain_id: Option<u64>,
) -> Vec<u8> {
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(r_bytes);
    sig.extend_from_slice(s_bytes);
    if let Some(chain) = chain_id {
        sig.push(rec_id + 35 + 2 * chain as u8);
    } else {
        sig.push(rec_id + 27);
    }
    sig
}

pub fn bitcoin_der_signature(r_bytes: &[u8], s_bytes: &[u8]) -> Vec<u8> {
    fn encode_int(bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![];
        let non_zero = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let trimmed = &bytes[non_zero..];
        if trimmed[0] & 0x80 != 0 {
            v.push(0x00);
        }
        v.extend_from_slice(trimmed);
        v
    }

    let mut sig = vec![0x30];
    let r_enc = encode_int(r_bytes);
    let s_enc = encode_int(s_bytes);
    let total_len = 2 + r_enc.len() + 2 + s_enc.len();
    sig.push(total_len as u8);
    sig.push(0x02);
    sig.push(r_enc.len() as u8);
    sig.extend_from_slice(&r_enc);
    sig.push(0x02);
    sig.push(s_enc.len() as u8);
    sig.extend_from_slice(&s_enc);
    sig
}

#[cfg(not(test))]
static PAILLIER_BITS: AtomicUsize = AtomicUsize::new(2048);
#[cfg(test)]
static PAILLIER_BITS: AtomicUsize = AtomicUsize::new(1024);

pub fn paillier_bits() -> usize {
    PAILLIER_BITS.load(Ordering::Relaxed)
}

pub fn set_paillier_bits(bits: usize) {
    PAILLIER_BITS.store(bits, Ordering::Relaxed);
}

const CURVE_BITS: usize = 256;

#[derive(ProtocolMsg, Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SignMsg {
    Round1(Round1Msg),
    Round2(Round2Msg),
    Round3(Round3Msg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Round1Msg {
    P1Data {
        point: Point<Secp256k1>,
        c_k_inv: BigInt,
        pk_n: BigUint,
        pk_g: BigUint,
        range_proof: paillier_zk::RangeProof,
        consistency_proof: paillier_zk::ConsistencyProof,
    },
    Ack,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Round2Msg {
    P2Data {
        c_s2: BigInt,
        mul_proof: paillier_zk::MulProof,
    },
    Ack,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Round3Msg {
    Signature {
        r_bytes: Vec<u8>,
        s_bytes: Vec<u8>,
        rec_id: u8,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error<RecvErr, SendErr> {
    #[error("send at round 1")]
    Round1Send(#[source] SendErr),
    #[error("receive at round 1")]
    Round1Receive(#[source] RecvErr),
    #[error("send at round 2")]
    Round2Send(#[source] SendErr),
    #[error("receive at round 2")]
    Round2Receive(#[source] RecvErr),
    #[error("send at round 3")]
    Round3Send(#[source] SendErr),
    #[error("receive at round 3")]
    Round3Receive(#[source] RecvErr),
    #[error("protocol violation: {0}")]
    ProtocolViolation(&'static str),
    #[error("invalid signature")]
    InvalidSignature,
}

pub type ErrorM<M> =
    Error<CompleteRoundErr<M, round_based::round::RoundInputError>, <M as Mpc>::SendErr>;

type P1State = (
    paillier::PaillierPrivateKey,
    paillier::PaillierPublicKey,
    Scalar<Secp256k1>,
    Scalar<Secp256k1>,
    Vec<u8>,
    BigInt,
);

fn bu2bi(u: &BigUint) -> BigInt {
    BigInt::from_biguint(num_bigint::Sign::Plus, u.clone())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_sign<M>(
    mut mpc: M,
    i: u16,
    n: u16,
    signers: &[u16; 2],
    share: &SecretScalar<Secp256k1>,
    public_key: &Point<Secp256k1>,
    msg_digest: &[u8; 32],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<(Vec<u8>, Vec<u8>, u8), ErrorM<M>>
where
    M: Mpc<Msg = SignMsg>,
{
    assert!(n >= 2);
    assert!(i < n);

    let is_p1 = i == signers[0];
    let is_p2 = i == signers[1];
    let lambda = lagrange_coeff(i, signers);
    let msg = Scalar::<Secp256k1>::from_be_bytes_mod_order(msg_digest);

    let round1 = mpc.add_round(RoundInput::<Round1Msg>::broadcast(i, n));
    let round2 = mpc.add_round(RoundInput::<Round2Msg>::broadcast(i, n));
    let round3 = mpc.add_round(RoundInput::<Round3Msg>::broadcast(i, n));
    let mut mpc = mpc.finish_setup();

    let mut p1_state: Option<P1State> = None;
    if is_p1 {
        let kp = paillier::generate_keypair(paillier_bits());
        let k = Scalar::<Secp256k1>::random(rng);
        let k_inv = k.invert().expect("k is zero (astronomically unlikely)");
        let r_point = Point::generator() * k;
        let m = scalar_to_bigint(&k_inv);

        let n_bi = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n_bi);
        let c_k_inv = kp.pk.encrypt_with_rho(&m, &rho);
        let pk_n = kp.pk.n.clone();
        let pk_g = kp.pk.g.clone();

        let range_proof =
            paillier_zk::prove_range(&kp.pk, &c_k_inv, &m, &rho, CURVE_BITS, b"sign", rng);

        let consistency_proof =
            paillier_zk::prove_consistency(&kp.pk, &m, &rho, &c_k_inv, &r_point, b"sign", rng);

        p1_state = Some((
            kp.sk,
            kp.pk,
            k,
            k_inv,
            r_point.to_bytes(true).to_vec(),
            c_k_inv.clone(),
        ));

        mpc.reliably_broadcast(SignMsg::Round1(Round1Msg::P1Data {
            point: r_point,
            c_k_inv,
            pk_n,
            pk_g,
            range_proof,
            consistency_proof,
        }))
        .await
        .map_err(Error::Round1Send)?;
    } else {
        mpc.reliably_broadcast(SignMsg::Round1(Round1Msg::Ack))
            .await
            .map_err(Error::Round1Send)?;
    }

    let msgs1 = mpc.complete(round1).await.map_err(Error::Round1Receive)?;

    if is_p2 {
        let p1_msg = msgs1
            .into_iter_indexed()
            .find(|(sender, _, _)| *sender == signers[0])
            .map(|(_, _, msg)| msg)
            .ok_or(Error::ProtocolViolation("P2: no P1Data in round 1"))?;

        let (r_point, c_k_inv, pk_n, pk_g, range_proof, consistency_proof) = match p1_msg {
            Round1Msg::P1Data {
                point,
                c_k_inv,
                pk_n,
                pk_g,
                range_proof,
                consistency_proof,
            } => (point, c_k_inv, pk_n, pk_g, range_proof, consistency_proof),
            _ => {
                return Err(Error::ProtocolViolation(
                    "P2: P1 sent Ack instead of P1Data",
                ));
            }
        };

        let p1_pk = paillier::PaillierPublicKey {
            n: pk_n.clone(),
            g: pk_g.clone(),
            n_sq: pk_n.pow(2u32),
        };

        if !paillier_zk::verify_range(&p1_pk, &c_k_inv, CURVE_BITS, b"sign", &range_proof) {
            return Err(Error::ProtocolViolation("P2: P1's range proof failed"));
        }

        if !paillier_zk::verify_consistency(&p1_pk, &c_k_inv, &r_point, b"sign", &consistency_proof)
        {
            return Err(Error::ProtocolViolation(
                "P2: P1's consistency proof failed",
            ));
        }

        // This encrypts k_inv · λ · (m + r·share) under P1's Paillier key
        let r = point_x_coord(&r_point);
        let mul_scalar = lambda * (msg + r * share.as_ref());
        let mul_scalar_bi = scalar_to_bigint(&mul_scalar);

        let n_sq = &p1_pk.n * &p1_pk.n;
        let n_sq_bi = bu2bi(&n_sq);
        let c_s2 = c_k_inv.modpow(&mul_scalar_bi, &n_sq_bi);

        // Re-randomise by multiplying with Enc(0)
        let n_bi2 = bu2bi(&p1_pk.n);
        let rho_s2 = rng.gen_bigint_range(&BigInt::from(1), &n_bi2);
        let enc_zero = p1_pk.encrypt_with_rho(&BigInt::from(0), &rho_s2);
        let c_s2 = (&c_s2 * &enc_zero) % &n_sq_bi;

        // MulProof: proves c_s2 = c_k_inv^scalar · Enc(0) under p1_pk
        let mul_proof = paillier_zk::prove_mul(
            &p1_pk,
            &c_k_inv,
            &c_s2,
            &mul_scalar_bi,
            &rho_s2,
            CURVE_BITS,
            b"sign",
            rng,
        );

        mpc.reliably_broadcast(SignMsg::Round2(Round2Msg::P2Data { c_s2, mul_proof }))
            .await
            .map_err(Error::Round2Send)?;
    } else {
        mpc.reliably_broadcast(SignMsg::Round2(Round2Msg::Ack))
            .await
            .map_err(Error::Round2Send)?;
    }

    let msgs2 = mpc.complete(round2).await.map_err(Error::Round2Receive)?;

    if is_p1 {
        let (my_sk, my_pk, k, k_inv, _r_point_bytes, c_k_inv_val) =
            p1_state.ok_or(Error::ProtocolViolation("P1: no state"))?;

        let p2_data = msgs2
            .into_iter_indexed()
            .find(|(sender, _, _)| *sender == signers[1])
            .map(|(_, _, msg)| msg)
            .ok_or(Error::ProtocolViolation("P1: no P2Data in round 2"))?;

        let (c_s2, mul_proof) = match p2_data {
            Round2Msg::P2Data { c_s2, mul_proof } => (c_s2, mul_proof),
            _ => {
                return Err(Error::ProtocolViolation(
                    "P1: P2 sent Ack instead of P2Data",
                ));
            }
        };

        if !paillier_zk::verify_mul(&my_pk, &c_k_inv_val, &c_s2, CURVE_BITS, b"sign", &mul_proof) {
            return Err(Error::ProtocolViolation("P1: P2's MulProof failed"));
        }

        let s2_biguint = my_sk
            .decrypt(&my_pk, &c_s2)
            .to_biguint()
            .expect("decryption produced negative value");
        let s2_scalar = biguint_to_scalar(&s2_biguint);

        let lambda1 = lagrange_coeff(i, signers);
        let r_point = Point::generator() * k;
        let r = point_x_coord(&r_point);
        let partial_s1 = lambda1 * k_inv * (msg + r * share.as_ref());
        let s1 = partial_s1 + s2_scalar;
        let rec_id = recovery_id(&r_point);

        let s_bytes = s1.to_be_bytes().to_vec();
        let r_bytes = r.to_be_bytes().to_vec();

        mpc.reliably_broadcast(SignMsg::Round3(Round3Msg::Signature {
            r_bytes: r_bytes.clone(),
            s_bytes: s_bytes.clone(),
            rec_id,
        }))
        .await
        .map_err(Error::Round3Send)?;

        if !verify_signature(public_key, msg_digest, &r_bytes, &s_bytes) {
            return Err(Error::InvalidSignature);
        }

        let _msgs3 = mpc.complete(round3).await.map_err(Error::Round3Receive)?;

        Ok((r_bytes, s_bytes, rec_id))
    } else {
        mpc.reliably_broadcast(SignMsg::Round3(Round3Msg::Signature {
            r_bytes: vec![],
            s_bytes: vec![],
            rec_id: 0,
        }))
        .await
        .map_err(Error::Round3Send)?;

        let msgs3 = mpc.complete(round3).await.map_err(Error::Round3Receive)?;

        let sig_msg = msgs3
            .into_iter_indexed()
            .find(|(sender, _, _)| *sender == signers[0])
            .map(|(_, _, msg)| match msg {
                Round3Msg::Signature {
                    r_bytes,
                    s_bytes,
                    rec_id,
                } => (r_bytes, s_bytes, rec_id),
            })
            .ok_or(Error::ProtocolViolation("no Signature in round 3"))?;

        let (r_bytes, s_bytes, rec_id) = sig_msg;

        if !verify_signature(public_key, msg_digest, &r_bytes, &s_bytes) {
            return Err(Error::InvalidSignature);
        }

        Ok((r_bytes, s_bytes, rec_id))
    }
}
