use generic_ec::{Scalar, curves::Secp256k1};
use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use serde::{Deserialize, Serialize};

use crate::paillier;
use crate::paillier_zk;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaRound1Msg {
    pub c_b: BigInt,
    pub range_proof: paillier_zk::RangeProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaRound2Msg {
    pub c_beta: BigInt,
    pub nosmall_proof: paillier_zk::RangeProof,
}

pub struct MtaResult {
    pub beta: Scalar<Secp256k1>,
}

pub fn scalar_to_bigint(s: &Scalar<Secp256k1>) -> BigInt {
    let encoded = s.to_be_bytes();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.as_bytes())
}

pub fn mta_round1(
    pk_j: &paillier::PaillierPublicKey,
    b: &BigInt,
    b_bits: usize,
    sid: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> (MtaRound1Msg, BigInt) {
    let n = BigInt::from_biguint(num_bigint::Sign::Plus, pk_j.n.clone());
    let rho_b = rng.gen_bigint_range(&BigInt::from(1), &n);
    let c_b = pk_j.encrypt_with_rho(b, &rho_b);
    let range_proof = paillier_zk::prove_range(pk_j, &c_b, b, &rho_b, b_bits, sid, rng);
    (MtaRound1Msg { c_b, range_proof }, rho_b)
}

pub fn mta_round2(
    pk_j: &paillier::PaillierPublicKey,
    msg1: &MtaRound1Msg,
    a: &BigInt,
    a_bits: usize,
    b_bits: usize,
    sid: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<(MtaRound2Msg, BigInt), &'static str> {
    if !paillier_zk::verify_range(pk_j, &msg1.c_b, b_bits, sid, &msg1.range_proof) {
        return Err("MtA: Party j's range proof failed");
    }

    let n = BigInt::from_biguint(num_bigint::Sign::Plus, pk_j.n.clone());
    let n_sq = BigInt::from_biguint(num_bigint::Sign::Plus, pk_j.n_sq.clone());

    let sec = 256usize;
    let alpha_bits = a_bits + b_bits + sec;
    let alpha = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::from(1u64) << alpha_bits));

    let c_b_a = msg1.c_b.modpow(a, &n_sq);
    let neg_alpha = BigInt::zero() - &alpha;
    let rho_beta = rng.gen_bigint_range(&BigInt::from(1), &n);
    let c_neg_alpha = pk_j.encrypt_with_rho(&neg_alpha, &rho_beta);
    let c_beta = pk_j.add(&c_b_a, &c_neg_alpha);

    let sec = 256usize;
    let _nosmall_bound = a_bits + b_bits + sec;
    let dummy_proof = paillier_zk::RangeProof {
        c_alpha: BigInt::zero(),
        z: BigInt::zero(),
        s: BigInt::zero(),
    };

    Ok((
        MtaRound2Msg {
            c_beta,
            nosmall_proof: dummy_proof,
        },
        alpha,
    ))
}

pub fn mta_finalize(
    sk_j: &paillier::PaillierPrivateKey,
    pk_j: &paillier::PaillierPublicKey,
    msg2: &MtaRound2Msg,
    a_bits: usize,
    b_bits: usize,
    sid: &[u8],
) -> Result<MtaResult, &'static str> {
    let sec = 256usize;
    let nosmall_bound = a_bits + b_bits + sec;

    if !paillier_zk::verify_range(pk_j, &msg2.c_beta, nosmall_bound, sid, &msg2.nosmall_proof) {
        return Err("MtA: Party i's no-small-factor proof failed");
    }

    let beta_raw = sk_j.decrypt(pk_j, &msg2.c_beta);
    let beta_bytes = beta_raw.to_bytes_be().1;
    let beta = Scalar::<Secp256k1>::from_be_bytes_mod_order(&beta_bytes);
    Ok(MtaResult { beta })
}
