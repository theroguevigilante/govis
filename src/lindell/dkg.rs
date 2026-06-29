use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
use rand_core::{CryptoRng, RngCore};

use round_based::mpc::{CompleteRoundErr, Mpc, MpcExecution, SendMany};
use round_based::round::RoundInput;

use crate::core::{compute_commitment, evaluate_polynomial};
use crate::lindell::types::{CommitMsg, LindellDkgOutput, Msg, RevealMsg, ShareMsg};

async fn run_vss<M>(
    mut mpc: M,
    i: u16,
    n: u16,
    t: u16,
    sid: &[u8],
    intercept: SecretScalar<Secp256k1>,
) -> Result<(SecretScalar<Secp256k1>, Point<Secp256k1>), ErrorM<M>>
where
    M: Mpc<Msg = Msg>,
{
    let round1 = mpc.add_round(RoundInput::<CommitMsg>::reliable_broadcast(i, n));
    let round2 = mpc.add_round(RoundInput::<RevealMsg>::reliable_broadcast(i, n));
    let round3 = mpc.add_round(RoundInput::<ShareMsg>::p2p(i, n));
    let mut mpc = mpc.finish_setup();

    let (commitments, secret_shares) = evaluate_polynomial(intercept, t, n);

    let commitment = compute_commitment(sid, i, &commitments);
    mpc.reliably_broadcast(Msg::Round1(CommitMsg { commitment }))
        .await
        .map_err(Error::Round1Send)?;

    let commitments_hashes = mpc.complete(round1).await.map_err(Error::Round1Receive)?;

    mpc.reliably_broadcast(Msg::Round2(RevealMsg {
        public_coeffs: commitments.clone(),
    }))
    .await
    .map_err(Error::Round2Send)?;

    let reveals = mpc.complete(round2).await.map_err(Error::Round2Receive)?;

    let mut combined_pk = commitments[0];
    let mut reveals_by_sender: Vec<(u16, RevealMsg)> = Vec::new();
    for ((sender, _, commit), (_, _, reveal)) in commitments_hashes
        .into_iter_indexed()
        .zip(reveals.into_iter_indexed())
    {
        let expected = compute_commitment(sid, sender, &reveal.public_coeffs);
        if expected != commit.commitment {
            return Err(Error::CommitmentMismatch { party: sender });
        }
        combined_pk += reveal.public_coeffs[0];
        reveals_by_sender.push((sender, reveal));
    }

    let mut send_many = mpc.send_many();
    for j in 0..n {
        if j == i {
            continue;
        }
        let share = secret_shares[usize::from(j)].clone();
        send_many
            .send_p2p(j, Msg::Round3(ShareMsg { share }))
            .await
            .map_err(Error::Round3Send)?;
    }
    let mut mpc = send_many.flush().await.map_err(Error::Round3Send)?;

    let shares = mpc.complete(round3).await.map_err(Error::Round3Receive)?;

    let mut final_share = *secret_shares[usize::from(i)].as_ref();
    for (sender, _, share_msg) in shares.into_iter_indexed() {
        let reveal = reveals_by_sender
            .iter()
            .find(|(s, _)| *s == sender)
            .map(|(_, r)| r)
            .ok_or(Error::ShareVerificationFailed { party: sender })?;

        let lhs: Point<Secp256k1> = Point::generator() * share_msg.share.as_ref();
        let x = Scalar::<Secp256k1>::from(i + 1);
        let mut rhs: Point<Secp256k1> = Point::generator() * Scalar::zero();
        let mut x_pow = Scalar::<Secp256k1>::one();
        for coeff in &reveal.public_coeffs {
            rhs += coeff * x_pow;
            x_pow *= &x;
        }
        if lhs != rhs {
            return Err(Error::ShareVerificationFailed { party: sender });
        }

        final_share += share_msg.share.as_ref();
    }

    Ok((SecretScalar::new(&mut final_share), combined_pk))
}

pub async fn run_dkg<M, R>(
    mpc: M,
    i: u16,
    n: u16,
    t: u16,
    sid: &[u8],
    mut rng: R,
) -> Result<LindellDkgOutput, ErrorM<M>>
where
    M: Mpc<Msg = Msg>,
    R: RngCore + CryptoRng,
{
    let (secret_share, public_key) =
        run_vss(mpc, i, n, t, sid, SecretScalar::random(&mut rng)).await?;
    Ok(LindellDkgOutput {
        secret_share,
        public_key,
    })
}

pub async fn run_refresh<M>(
    mpc: M,
    i: u16,
    n: u16,
    t: u16,
    sid: &[u8],
    old_share: &SecretScalar<Secp256k1>,
    master_pk: Point<Secp256k1>,
) -> Result<LindellDkgOutput, ErrorM<M>>
where
    M: Mpc<Msg = Msg>,
{
    let (offset_secret, _) = run_vss(mpc, i, n, t, sid, SecretScalar::zero()).await?;
    let mut new_secret = *old_share.as_ref();
    new_secret += offset_secret.as_ref();
    Ok(LindellDkgOutput {
        secret_share: SecretScalar::new(&mut new_secret),
        public_key: master_pk,
    })
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
    #[error("commitment mismatch from party {party}")]
    CommitmentMismatch { party: u16 },
    #[error("share verification failed for party {party}")]
    ShareVerificationFailed { party: u16 },
}

pub type ErrorM<M> =
    Error<CompleteRoundErr<M, round_based::round::RoundInputError>, <M as Mpc>::SendErr>;
