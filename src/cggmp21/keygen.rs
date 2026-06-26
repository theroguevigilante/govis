use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
use num_bigint::{BigInt, RandBigInt};
use rand_core::{CryptoRng, RngCore};
use round_based::ProtocolMsg;
use round_based::mpc::{CompleteRoundErr, Mpc, MpcExecution};
use round_based::round::RoundInput;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::paillier;
use super::super::paillier_zk;
use crate::core::{compute_commitment, evaluate_polynomial};

#[derive(ProtocolMsg, Clone, Debug, Serialize, Deserialize)]
pub enum KeygenMsg {
    Round1(Round1Msg),
    Round2(Round2Msg),
    Round3(Round3Msg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Msg {
    pub paillier_n: Vec<u8>,
    pub blum_proof: paillier_zk::BlumProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Msg {
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Msg {
    pub nonce: Vec<u8>,
    pub polynomial_coeff_points: Vec<Point<Secp256k1>>,
    pub encrypted_shares: Vec<(BigInt, paillier_zk::LogProof)>,
    pub schnorr_proof: paillier_zk::SchnorrProof,
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

pub async fn run_keygen<M, R>(
    mut mpc: M,
    i: u16,
    n: u16,
    t: u16,
    sid: &[u8],
    mut rng: R,
) -> Result<super::Cggmp21KeygenOutput, ErrorM<M>>
where
    M: Mpc<Msg = KeygenMsg>,
    R: RngCore + CryptoRng,
{
    let round1 = mpc.add_round(RoundInput::<Round1Msg>::reliable_broadcast(i, n));
    let round2 = mpc.add_round(RoundInput::<Round2Msg>::reliable_broadcast(i, n));
    let round3 = mpc.add_round(RoundInput::<Round3Msg>::reliable_broadcast(i, n));
    let mut mpc = mpc.finish_setup();

    // Generate Paillier key + Blum proof
    let (p, q, kp) = paillier::generate_keypair_ext(crate::lindell::sign::paillier_bits());
    let pk1 = kp.pk;
    let sk1 = kp.sk;
    let n_bi = BigInt::from_biguint(num_bigint::Sign::Plus, pk1.n.clone());
    let p_bi = BigInt::from_biguint(num_bigint::Sign::Plus, p);
    let q_bi = BigInt::from_biguint(num_bigint::Sign::Plus, q);
    let blum_proof = paillier_zk::prove_blum(&p_bi, &q_bi, &n_bi, sid);

    mpc.reliably_broadcast(KeygenMsg::Round1(Round1Msg {
        paillier_n: pk1.n.to_bytes_be(),
        blum_proof,
    }))
    .await
    .map_err(Error::Round1Send)?;

    let round1_msgs = mpc.complete(round1).await.map_err(Error::Round1Receive)?;

    // Verify all Blum proofs
    let mut peer_paillier_pks = vec![None; n as usize];
    peer_paillier_pks[i as usize] = Some(pk1.clone());
    for (sender, _, msg1) in round1_msgs.iter_indexed() {
        let n_biguint = num_bigint::BigUint::from_bytes_be(&msg1.paillier_n);
        if !paillier_zk::verify_blum(&n_biguint, sid, &msg1.blum_proof) {
            return Err(Error::ProtocolViolation("Blum proof verification failed"));
        }
        let g = &n_biguint + num_bigint::BigUint::from(1u64);
        let n_sq = &n_biguint * &n_biguint;
        let pk = paillier::PaillierPublicKey {
            n: n_biguint,
            n_sq,
            g,
        };
        peer_paillier_pks[sender as usize] = Some(pk);
    }

    // Generate VSS polynomial
    let ec_secret = SecretScalar::<Secp256k1>::random(&mut rng);
    let (commitments, secret_shares) = evaluate_polynomial(ec_secret.clone(), t, n);
    let nonce = SecretScalar::<Secp256k1>::random(&mut rng);
    let nonce_bytes = nonce.as_ref().to_be_bytes().to_vec();
    let commit = compute_commitment(sid, i, &commitments);
    let commit_with_nonce = {
        let mut h = Sha256::new();
        h.update(b"govis-cggmp21-keygen-commit");
        h.update(commit);
        h.update(&nonce_bytes);
        h.finalize().to_vec()
    };

    mpc.reliably_broadcast(KeygenMsg::Round2(Round2Msg {
        commitment: commit_with_nonce.try_into().unwrap(),
    }))
    .await
    .map_err(Error::Round2Send)?;

    let round2_msgs = mpc.complete(round2).await.map_err(Error::Round2Receive)?;

    // Round 3: reveal + P2P encrypted shares + proofs
    let schnorr_proof =
        paillier_zk::prove_schnorr(ec_secret.as_ref(), &commitments[0], sid, &mut rng);
    let mut encrypted_shares = Vec::new();
    for peer in 0..n {
        if peer == i {
            continue;
        }
        if let Some(ref pk) = peer_paillier_pks[peer as usize] {
            let n_bi = BigInt::from_biguint(num_bigint::Sign::Plus, pk.n.clone());
            let rho = rng.gen_bigint_range(&BigInt::from(1), &n_bi);
            let share_bi = scalar_to_bigint(secret_shares[peer as usize].as_ref());

            // share_point = Σ commitment_k * (peer+1)^k = generator * share
            let x = Scalar::<Secp256k1>::from(peer + 1);
            let mut x_pow = Scalar::<Secp256k1>::one();
            let mut share_point = Point::generator() * Scalar::zero();
            for comm in &commitments {
                share_point += *comm * x_pow;
                x_pow *= x;
            }

            let c = pk.encrypt_with_rho(&share_bi, &rho);
            let log_proof =
                paillier_zk::prove_log(pk, &c, &share_bi, &rho, &share_point, sid, &mut rng);
            encrypted_shares.push((c, log_proof));
        }
    }

    mpc.reliably_broadcast(KeygenMsg::Round3(Round3Msg {
        nonce: nonce_bytes.to_vec(),
        polynomial_coeff_points: commitments.clone(),
        encrypted_shares,
        schnorr_proof,
    }))
    .await
    .map_err(Error::Round3Send)?;

    let round3_msgs = mpc.complete(round3).await.map_err(Error::Round3Receive)?;

    // Verify commitments, ZK proofs, compute combined share and public key
    let mut combined_share = *secret_shares[i as usize].as_ref();
    let mut public_key = Point::generator() * ec_secret.as_ref();
    for (sender, _, msg3) in round3_msgs.iter_indexed() {
        let revealed_commit = compute_commitment(sid, sender, &msg3.polynomial_coeff_points);
        let round2_commit = round2_msgs
            .iter_indexed()
            .find(|(s, _, _)| *s == sender)
            .unwrap()
            .2;
        let expected = {
            let mut h = Sha256::new();
            h.update(b"govis-cggmp21-keygen-commit");
            h.update(revealed_commit);
            h.update(&msg3.nonce);
            h.finalize()
        };
        if expected[..] != round2_commit.commitment[..] {
            return Err(Error::ProtocolViolation("VSS commitment mismatch"));
        }

        // Verify Π_sch: sender knows the EC secret key for commitments[0]
        if !paillier_zk::verify_schnorr(&msg3.polynomial_coeff_points[0], sid, &msg3.schnorr_proof)
        {
            return Err(Error::ProtocolViolation(
                "Schnorr proof verification failed",
            ));
        }

        let pk_point = msg3.polynomial_coeff_points[0];
        public_key += pk_point;

        // Decrypt and verify encrypted share from this sender
        if sender != i {
            // Find the correct encrypted share for party i
            let enc_idx = if sender < i {
                usize::from(i - 1)
            } else {
                usize::from(i)
            };
            let (c, log_proof) = &msg3.encrypted_shares[enc_idx];

            // Compute share_point = Σ commitment_k * (i+1)^k
            let x = Scalar::<Secp256k1>::from(i + 1);
            let mut x_pow = Scalar::<Secp256k1>::one();
            let mut share_point = Point::generator() * Scalar::zero();
            for comm in &msg3.polynomial_coeff_points {
                share_point += *comm * x_pow;
                x_pow *= x;
            }

            // Verify Π_log: c encrypts share_point·G using the receiver's Paillier PK
            if !paillier_zk::verify_log(&pk1, c, &share_point, sid, log_proof) {
                return Err(Error::ProtocolViolation("Log proof verification failed"));
            }

            let share_bi = sk1.decrypt(&pk1, c);
            let share = Scalar::<Secp256k1>::from_be_bytes_mod_order(&share_bi.to_bytes_be().1);
            combined_share += share;
        }
    }

    Ok(super::Cggmp21KeygenOutput {
        ec_share: SecretScalar::new(&mut combined_share),
        public_key,
        paillier_sk: sk1,
        paillier_pk: pk1,
        peer_paillier_pks,
    })
}

fn scalar_to_bigint(s: &Scalar<Secp256k1>) -> BigInt {
    let encoded = s.to_be_bytes();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.as_bytes())
}
