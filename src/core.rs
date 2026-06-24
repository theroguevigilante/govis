use crate::types::{DkgShares, RefreshShares};
use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// This function is used to generate shares and it can be passed SecretScalar intercept value
/// which decides if the shares are RefreshShares or DkgShares
fn generate_shares_internal<R: RngCore + CryptoRng>(
    intercept: SecretScalar<Secp256k1>,
    threshold: u16,
    total_parties: u16,
    rng: &mut R,
) -> DkgShares {
    assert!(
        threshold <= total_parties,
        "Threshold cannot exceed total parties"
    );

    let mut coeffs = vec![intercept];
    for _ in 1..threshold {
        coeffs.push(SecretScalar::random(rng));
    }

    let commitments = coeffs.iter().map(|a| Point::generator() * a).collect();
    let mut secret_shares = Vec::with_capacity(total_parties as usize);

    for i in 1..=total_parties {
        let x_index = Scalar::<Secp256k1>::from(i);
        let mut current_share = Scalar::<Secp256k1>::zero();
        let mut x_power = Scalar::<Secp256k1>::one();

        for a in &coeffs {
            current_share += a.as_ref() * x_power;
            x_power *= &x_index;
        }
        secret_shares.push(SecretScalar::new(&mut current_share));
    }

    DkgShares {
        commitments,
        secret_shares,
    }
}

/// This is a wrapper function on the generate_shares_internal it generate an DkgShares for a given
/// threshold value and amount of servers
pub fn generate_dkg_shares<R: RngCore + CryptoRng>(t: u16, n: u16, rng: &mut R) -> DkgShares {
    generate_shares_internal(SecretScalar::random(rng), t, n, rng)
}

/// This is a wrapper function on the generate_shares_internal it generate RefreshShares for a given
/// threshold value and amount of servers
pub fn generate_refresh_shares<R: RngCore + CryptoRng>(
    t: u16,
    n: u16,
    rng: &mut R,
) -> RefreshShares {
    generate_shares_internal(SecretScalar::zero(), t, n, rng)
}

pub fn evaluate_polynomial(
    intercept: SecretScalar<Secp256k1>,
    t: u16,
    n: u16,
) -> (Vec<Point<Secp256k1>>, Vec<SecretScalar<Secp256k1>>) {
    let mut coeffs = vec![intercept];
    for _ in 1..t {
        coeffs.push(SecretScalar::random(&mut rand_core::OsRng));
    }

    let commitments: Vec<Point<Secp256k1>> =
        coeffs.iter().map(|a| Point::generator() * a).collect();

    let mut secret_shares = Vec::with_capacity(n as usize);
    for j in 0..n {
        let x = Scalar::<Secp256k1>::from(j + 1);
        let mut share = Scalar::<Secp256k1>::zero();
        let mut x_pow = Scalar::<Secp256k1>::one();
        for a in &coeffs {
            share += a.as_ref() * x_pow;
            x_pow *= &x;
        }
        secret_shares.push(SecretScalar::new(&mut share));
    }

    (commitments, secret_shares)
}

pub fn compute_commitment(
    sid: &[u8],
    party_index: u16,
    commitments: &[Point<Secp256k1>],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"govis-dkg-commit");
    hasher.update(sid);
    hasher.update(party_index.to_be_bytes());
    for point in commitments {
        hasher.update(point.to_bytes(true).as_bytes());
    }
    hasher.finalize().into()
}

/// It takes the received_offsets and using that updates the old_share
pub fn update_private_share(
    old_share: &SecretScalar<Secp256k1>,
    received_offsets: &[SecretScalar<Secp256k1>],
) -> SecretScalar<Secp256k1> {
    let mut total_scalar = *old_share.as_ref();
    for offset in received_offsets {
        total_scalar += offset.as_ref();
    }
    SecretScalar::new(&mut total_scalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::{Point, Scalar};
    use rand_core::OsRng;

    /// TEST 1: Basic Structure
    /// Ensures we get the right amount of data back for a given (t, n).
    #[test]
    fn test_dkg_dimensions() {
        let t = 3;
        let n = 5;
        let dkg = generate_dkg_shares(t, n, &mut OsRng);

        assert_eq!(
            dkg.commitments.len(),
            t as usize,
            "Wrong number of commitments"
        );
        assert_eq!(
            dkg.secret_shares.len(),
            n as usize,
            "Wrong number of shares"
        );
    }

    /// TEST 2: The Hologram Test (Verification)
    /// Proves that the secret shares actually "sit" on the public curve.
    /// This is what every server runs to catch a liar.
    #[test]
    fn test_dkg_verification_math() {
        let t = 2;
        let n = 3;
        let dkg = generate_dkg_shares(t, n, &mut OsRng);

        for (i, share) in dkg.secret_shares.iter().enumerate() {
            let x = Scalar::<Secp256k1>::from((i + 1) as u16);

            // Calculation A: Private side (Share * G)
            let lhs = Point::generator() * share;

            // Calculation B: Public side (A0 + x*A1 + x^2*A2...)
            let mut rhs = dkg.commitments[0];
            let mut x_pow = x;
            for j in 1..t as usize {
                rhs += dkg.commitments[j] * x_pow;
                x_pow *= &x;
            }

            assert_eq!(
                lhs,
                rhs,
                "Share {} failed verification against commitments!",
                i + 1
            );
        }
    }

    /// TEST 3: Persistence of Identity
    /// Proves that a Key Refresh doesn't move the Master Public Key.
    #[test]
    fn test_refresh_persistence() {
        let mut rng = OsRng;
        let (t, n) = (2, 3);

        let dkg = generate_dkg_shares(t, n, &mut rng);
        let original_pk = dkg.commitments[0];

        // Everyone generates their "Net-Zero" wiggles
        let r1 = generate_refresh_shares(t, n, &mut rng);
        let r2 = generate_refresh_shares(t, n, &mut rng);
        let r3 = generate_refresh_shares(t, n, &mut rng);

        // Update Global Commitments
        let mut new_commitments = dkg.commitments.clone();
        for r in [&r1, &r2, &r3] {
            for (i, comm) in r.commitments.iter().enumerate() {
                new_commitments[i] += comm;
            }
        }

        // The "Anchor" (Commitment 0) must remain identical
        assert_eq!(
            original_pk, new_commitments[0],
            "Public Key moved! Identity lost."
        );
    }

    /// TEST 4: The "Self-Healing" Update
    /// Proves that adding wiggles to a share results in a valid new share.
    #[test]
    fn test_share_update_validity() {
        let mut rng = OsRng;
        let (t, n) = (2, 3);

        let dkg = generate_dkg_shares(t, n, &mut rng);
        let r1 = generate_refresh_shares(t, n, &mut rng);

        // Server 1 updates its share with Server 1's refresh offset
        let offsets = [r1.secret_shares[0].clone()];
        let new_p1_share = update_private_share(&dkg.secret_shares[0], &offsets);

        // New commitments for just this one refresh
        let mut new_commitments = dkg.commitments.clone();
        for (i, comm) in r1.commitments.iter().enumerate() {
            new_commitments[i] += comm;
        }

        // Verification: New Share * G == New Polynomial evaluation at x=1
        let x1 = Scalar::<Secp256k1>::from(1);
        let lhs = Point::generator() * &new_p1_share;
        let rhs = new_commitments[0] + (new_commitments[1] * x1);

        assert_eq!(lhs, rhs, "Refreshed share is mathematically broken!");
    }

    /// TEST 5: The Security Guard
    /// Ensures we can't create an unrecoverable key.
    #[test]
    #[should_panic(expected = "Threshold cannot exceed total parties")]
    fn test_invalid_threshold() {
        generate_dkg_shares(10, 5, &mut OsRng);
    }
}
