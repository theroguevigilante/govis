pub mod dkg;
pub mod sign;
pub mod types;

pub use dkg::*;

#[cfg(test)]
mod tests {
    use super::dkg::{run_dkg, run_refresh};
    use super::sign::{run_sign, verify_signature};
    use super::types::LindellDkgOutput;
    use crate::test_helpers::TestRng;
    use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
    use sha2::Digest;

    fn run_dkg_sync(t: u16, n: u16) -> Vec<LindellDkgOutput> {
        let mut rng = TestRng::new();
        let sid = b"test-session";

        round_based::sim::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            |i, party, mut rng| async move { run_dkg(party, i, n, t, sid, &mut rng).await },
        )
        .unwrap()
        .expect_ok()
        .into_vec()
    }

    #[test]
    fn dkg_3_parties_threshold_2() {
        let outputs = run_dkg_sync(2, 3);
        let pk = outputs[0].public_key;
        for out in &outputs {
            assert_eq!(out.public_key, pk, "all parties must agree on public key");
        }
    }

    #[test]
    fn dkg_5_parties_threshold_3() {
        let outputs = run_dkg_sync(3, 5);
        let pk = outputs[0].public_key;
        for out in &outputs {
            assert_eq!(out.public_key, pk, "all parties must agree on public key");
        }
    }

    #[test]
    fn dkg_1_out_of_2() {
        let outputs = run_dkg_sync(1, 2);
        let pk = outputs[0].public_key;
        for out in &outputs {
            assert_eq!(out.public_key, pk, "all parties must agree on public key");
        }
    }

    #[test]
    fn refresh_preserves_public_key() {
        let (t, n) = (2, 3);

        let initial = run_dkg_sync(t, n);
        let pk_initial = initial[0].public_key;
        let initial_ref = &initial;

        let mut rng = TestRng::new();
        let sid = b"test-refresh";

        let result = round_based::sim::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            |i, party, _rng| async move {
                run_refresh(
                    party,
                    i,
                    n,
                    t,
                    sid,
                    &initial_ref[usize::from(i)].secret_share,
                    pk_initial,
                )
                .await
            },
        )
        .unwrap()
        .expect_ok()
        .into_vec();

        for out in &result {
            assert_eq!(
                out.public_key, pk_initial,
                "public key must stay same after refresh"
            );
        }
    }

    #[test]
    fn refresh_via_hex_roundtrip() {
        let (t, n) = (2, 3);

        let initial = run_dkg_sync(t, n);
        let pk_initial = initial[0].public_key;

        let old_share_hex = hex::encode(initial[0].secret_share.as_ref().to_be_bytes());
        let master_pk_hex = hex::encode(pk_initial.to_bytes(true));

        let old_share_bytes = hex::decode(&old_share_hex).unwrap();
        let old_share = SecretScalar::<Secp256k1>::new(
            &mut Scalar::<Secp256k1>::from_be_bytes_mod_order(&old_share_bytes),
        );
        let master_pk_bytes = hex::decode(&master_pk_hex).unwrap();
        let master_pk = Point::<Secp256k1>::from_bytes(&master_pk_bytes).unwrap();

        assert_eq!(master_pk, pk_initial, "master pk roundtrip");
        assert_eq!(
            *old_share.as_ref(),
            *initial[0].secret_share.as_ref(),
            "old share roundtrip"
        );

        let sid = b"test-refresh-hex";
        let old_shares = vec![old_share; n as usize];

        let result = round_based::sim::run_with_setup(old_shares, |i, party, share| async move {
            run_refresh(party, i, n, t, sid, &share, master_pk).await
        })
        .unwrap()
        .expect_ok()
        .into_vec();

        for out in &result {
            assert_eq!(
                out.public_key, pk_initial,
                "public key must stay same after hex roundtrip refresh"
            );
        }
    }

    #[test]
    fn sign_works_1_of_2() {
        let mut rng = TestRng::new();
        let msg = b"hello world";
        let digest = sha2::Sha256::digest(msg);
        let msg_digest: [u8; 32] = digest.into();

        let outputs = run_dkg_sync(1, 2);
        let signers = [0u16, 1u16];

        let shares: Vec<SecretScalar<Secp256k1>> = outputs
            .iter()
            .map(|o| {
                let encoded = o.secret_share.as_ref().to_be_bytes();
                let bytes: [u8; 32] = encoded.as_ref().try_into().unwrap();
                SecretScalar::<Secp256k1>::from_be_bytes(&bytes).unwrap()
            })
            .collect();
        let pub_key =
            Point::<Secp256k1>::from_bytes(outputs[0].public_key.to_bytes(false)).unwrap();

        let result =
            round_based::sim::run_with_setup(core::iter::repeat_with(|| rng.fork()).take(2), {
                let shares = shares.clone();
                let pk = pub_key;
                let md = msg_digest;
                move |i, party, mut rng| {
                    let share = shares[usize::from(i)].clone();
                    async move {
                        run_sign(party, i, 2, &signers, &share, &pk, &md, &mut rng)
                            .await
                            .unwrap()
                    }
                }
            })
            .unwrap()
            .expect_eq();

        assert!(verify_signature(
            &pub_key,
            &msg_digest,
            &result.0,
            &result.1
        ));
    }

    #[test]
    fn signature_fails_wrong_message() {
        let mut rng = TestRng::new();
        let msg = b"hello world";
        let digest = sha2::Sha256::digest(msg);
        let msg_digest: [u8; 32] = digest.into();
        let wrong_digest: [u8; 32] = sha2::Sha256::digest(b"wrong message").into();

        let outputs = run_dkg_sync(1, 2);

        let shares: Vec<SecretScalar<Secp256k1>> = outputs
            .iter()
            .map(|o| {
                let encoded = o.secret_share.as_ref().to_be_bytes();
                let bytes: [u8; 32] = encoded.as_ref().try_into().unwrap();
                SecretScalar::<Secp256k1>::from_be_bytes(&bytes).unwrap()
            })
            .collect();
        let pub_key =
            Point::<Secp256k1>::from_bytes(outputs[0].public_key.to_bytes(false)).unwrap();
        let signers = [0u16, 1u16];

        let result =
            round_based::sim::run_with_setup(core::iter::repeat_with(|| rng.fork()).take(2), {
                let shares = shares.clone();
                let pk = pub_key;
                let md = msg_digest;
                move |i, party, mut rng| {
                    let share = shares[usize::from(i)].clone();
                    async move {
                        run_sign(party, i, 2, &signers, &share, &pk, &md, &mut rng)
                            .await
                            .unwrap()
                    }
                }
            })
            .unwrap()
            .expect_eq();

        assert!(!verify_signature(
            &pub_key,
            &wrong_digest,
            &result.0,
            &result.1
        ));
    }

    #[test]
    fn dkg_then_2_of_3_signing() {
        let outputs = run_dkg_sync(2, 3);
        let signers = [0u16, 1u16];
        let msg = b"threshold test";
        let digest = sha2::Sha256::digest(msg);
        let msg_digest: [u8; 32] = digest.into();

        let shares: Vec<SecretScalar<Secp256k1>> = outputs
            .iter()
            .map(|o| {
                let encoded = o.secret_share.as_ref().to_be_bytes();
                let bytes: [u8; 32] = encoded.as_ref().try_into().unwrap();
                SecretScalar::<Secp256k1>::from_be_bytes(&bytes).unwrap()
            })
            .collect();
        let pub_key =
            Point::<Secp256k1>::from_bytes(outputs[0].public_key.to_bytes(false)).unwrap();

        let mut rng = TestRng::new();

        let result =
            round_based::sim::run_with_setup(core::iter::repeat_with(|| rng.fork()).take(3), {
                let shares = shares.clone();
                let pk = pub_key;
                let md = msg_digest;
                move |i, party, mut rng| {
                    let share = shares[usize::from(i)].clone();
                    async move {
                        run_sign(party, i, 3, &signers, &share, &pk, &md, &mut rng)
                            .await
                            .unwrap()
                    }
                }
            })
            .unwrap()
            .expect_eq();

        assert!(verify_signature(
            &pub_key,
            &msg_digest,
            &result.0,
            &result.1
        ));
    }
}
