pub mod keygen;
pub mod presign;
pub mod sign;

// Common types for CGGMP21
#[derive(Clone)]
pub struct Cggmp21KeygenOutput {
    pub ec_share: generic_ec::SecretScalar<generic_ec::curves::Secp256k1>,
    pub public_key: generic_ec::Point<generic_ec::curves::Secp256k1>,
    pub paillier_sk: crate::paillier::PaillierPrivateKey,
    pub paillier_pk: crate::paillier::PaillierPublicKey,
    pub peer_paillier_pks: Vec<Option<crate::paillier::PaillierPublicKey>>,
}

impl Cggmp21KeygenOutput {
    pub fn to_key_data(&self) -> crate::types::Cggmp21KeyData {
        crate::types::Cggmp21KeyData {
            protocol: "cggmp21".into(),
            ec_share: self.ec_share.as_ref().to_be_bytes().to_vec(),
            public_key: self.public_key.to_bytes(true).to_vec(),
        }
    }

    pub fn from_key_data(data: &crate::types::Cggmp21KeyData) -> Self {
        assert_eq!(data.protocol, "cggmp21", "key file protocol mismatch");
        use generic_ec::{Point, Scalar, SecretScalar, curves::Secp256k1};
        let mut s = Scalar::<Secp256k1>::from_be_bytes_mod_order(&data.ec_share);
        // Paillier keys not persisted — generated per presign session
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
            public_key: Point::<Secp256k1>::from_bytes(&data.public_key).expect("invalid public key in key data"),
            paillier_sk,
            paillier_pk,
            peer_paillier_pks: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::TestRng;

    use super::*;
    use crate::lindell::sign::verify_signature;

    #[test]
    fn cggmp21_2of2_keygen_presign_sign() {
        let n = 2;
        let signers = [0u16, 1u16];
        let sid = b"test-cggmp21-e2e";
        let msg_digest = [0xabu8; 32];
        let mut rng = TestRng::new();

        let t = n - 1;
        let keygen_outputs: Vec<Cggmp21KeygenOutput> = round_based::sim::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            |i, party, mut rng| async move {
                keygen::run_keygen(party, i, n, t, sid, &mut rng)
                    .await
                    .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let pub_key = keygen_outputs[0].public_key;
        for (idx, out) in keygen_outputs.iter().enumerate() {
            assert_eq!(out.public_key, pub_key, "pub_key mismatch at {}", idx);
        }

        let presign_outputs: Vec<presign::Presignature> = round_based::sim::run_with_setup(
            keygen_outputs.clone(),
            |i, party, kgen_out| async move {
                presign::run_presign(
                    party,
                    i,
                    &signers,
                    &kgen_out.ec_share,

                    TestRng::new(),
                )
                .await
                .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let r_point = presign_outputs[0].r_point;
        let r = presign_outputs[0].r;
        let k_inv_0 = presign_outputs[0].k_inv;
        for (idx, p) in presign_outputs.iter().enumerate() {
            assert_eq!(p.r, r, "r mismatch at party {}", idx);
            assert_eq!(p.r_point, r_point, "r_point mismatch at party {}", idx);
            assert_eq!(p.k_inv, k_inv_0, "k_inv mismatch at party {}", idx);
        }

        let zip_iter = keygen_outputs.into_iter().zip(presign_outputs);
        let sign_outputs: Vec<sign::Signature> =
            round_based::sim::run_with_setup(zip_iter, |i, party, (kgen_out, presig)| async move {
                sign::run_online_sign(
                    party,
                    i,
                    &signers,
                    &kgen_out.ec_share,
                    &pub_key,
                    &msg_digest,
                    &presig,
                )
                .await
                .unwrap()
            })
            .unwrap()
            .into_vec();

        let sig = &sign_outputs[0];
        for (idx, s) in sign_outputs.iter().enumerate() {
            assert_eq!(s.r_bytes, sig.r_bytes, "r_bytes mismatch at party {}", idx);
            assert_eq!(s.s_bytes, sig.s_bytes, "s_bytes mismatch at party {}", idx);
        }

        let verified = verify_signature(&pub_key, &msg_digest, &sig.r_bytes, &sig.s_bytes);
        assert!(verified);
    }

    #[test]
    fn cggmp21_3of3_keygen_presign_sign() {
        let n = 3;
        let t = 3;
        let signers = [0u16, 1u16, 2u16];
        let sid = b"test-cggmp21-3of3";
        let msg_digest = [0xabu8; 32];
        let mut rng = TestRng::new();

        let keygen_outputs: Vec<Cggmp21KeygenOutput> = round_based::sim::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            |i, party, mut rng| async move {
                keygen::run_keygen(party, i, n, t, sid, &mut rng)
                    .await
                    .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let pub_key = keygen_outputs[0].public_key;
        for (idx, out) in keygen_outputs.iter().enumerate() {
            assert_eq!(out.public_key, pub_key, "pub_key mismatch at {}", idx);
        }

        let presign_outputs: Vec<presign::Presignature> = round_based::sim::run_with_setup(
            keygen_outputs.clone(),
            |i, party, kgen_out| async move {
                presign::run_presign(
                    party,
                    i,
                    &signers,
                    &kgen_out.ec_share,

                    TestRng::new(),
                )
                .await
                .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let r_point = presign_outputs[0].r_point;
        let r = presign_outputs[0].r;
        let k_inv_0 = presign_outputs[0].k_inv;
        for (idx, p) in presign_outputs.iter().enumerate() {
            assert_eq!(p.r, r, "r mismatch at party {}", idx);
            assert_eq!(p.r_point, r_point, "r_point mismatch at party {}", idx);
            assert_eq!(p.k_inv, k_inv_0, "k_inv mismatch at party {}", idx);
        }

        let zip_iter = keygen_outputs.into_iter().zip(presign_outputs);
        let sign_outputs: Vec<sign::Signature> =
            round_based::sim::run_with_setup(zip_iter, |i, party, (kgen_out, presig)| async move {
                sign::run_online_sign(
                    party,
                    i,
                    &signers,
                    &kgen_out.ec_share,
                    &pub_key,
                    &msg_digest,
                    &presig,
                )
                .await
                .unwrap()
            })
            .unwrap()
            .into_vec();

        let sig = &sign_outputs[0];
        for (idx, s) in sign_outputs.iter().enumerate() {
            assert_eq!(s.r_bytes, sig.r_bytes, "r_bytes mismatch at party {}", idx);
            assert_eq!(s.s_bytes, sig.s_bytes, "s_bytes mismatch at party {}", idx);
        }

        let verified = verify_signature(&pub_key, &msg_digest, &sig.r_bytes, &sig.s_bytes);
        assert!(verified);
    }

    #[test]
    fn cggmp21_3of5_keygen_presign_sign() {
        let n = 5;
        let t = 3;
        let signers = [1u16, 2u16, 4u16];
        let sid = b"test-cggmp21-3of5";
        let msg_digest = [0xabu8; 32];
        let mut rng = TestRng::new();

        let keygen_outputs: Vec<Cggmp21KeygenOutput> = round_based::sim::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            |i, party, mut rng| async move {
                keygen::run_keygen(party, i, n, t, sid, &mut rng)
                    .await
                    .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let pub_key = keygen_outputs[0].public_key;
        for (idx, out) in keygen_outputs.iter().enumerate() {
            assert_eq!(out.public_key, pub_key, "pub_key mismatch at {}", idx);
        }

        let signer_kgen: Vec<Cggmp21KeygenOutput> = signers
            .iter()
            .map(|&s| keygen_outputs[s as usize].clone())
            .collect();

        let presign_outputs: Vec<presign::Presignature> = round_based::sim::run_with_setup(
            signer_kgen.clone(),
            |i, party, kgen_out| async move {
                presign::run_presign(
                    party,
                    signers[usize::from(i)],
                    &signers,
                    &kgen_out.ec_share,

                    TestRng::new(),
                )
                .await
                .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let r_point = presign_outputs[0].r_point;
        let r = presign_outputs[0].r;
        let k_inv_0 = presign_outputs[0].k_inv;
        for (idx, p) in presign_outputs.iter().enumerate() {
            assert_eq!(p.r, r, "r mismatch at party {}", idx);
            assert_eq!(p.r_point, r_point, "r_point mismatch at party {}", idx);
            assert_eq!(p.k_inv, k_inv_0, "k_inv mismatch at party {}", idx);
        }

        let zip_iter = signer_kgen.into_iter().zip(presign_outputs);
        let sign_outputs: Vec<sign::Signature> =
            round_based::sim::run_with_setup(zip_iter, |i, party, (kgen_out, presig)| async move {
                sign::run_online_sign(
                    party,
                    signers[usize::from(i)],
                    &signers,
                    &kgen_out.ec_share,
                    &pub_key,
                    &msg_digest,
                    &presig,
                )
                .await
                .unwrap()
            })
            .unwrap()
            .into_vec();

        let sig = &sign_outputs[0];
        for (idx, s) in sign_outputs.iter().enumerate() {
            assert_eq!(s.r_bytes, sig.r_bytes, "r_bytes mismatch at party {}", idx);
            assert_eq!(s.s_bytes, sig.s_bytes, "s_bytes mismatch at party {}", idx);
        }

        let verified = verify_signature(&pub_key, &msg_digest, &sig.r_bytes, &sig.s_bytes);
        assert!(verified);
    }

    #[test]
    fn cggmp21_7of5_keygen_presign_sign() {
        let n = 7;
        let t = 5;
        let signers = [0u16, 2u16, 3u16, 5u16, 6u16];
        let sid = b"test-cggmp21-7of5";
        let msg_digest = [0xabu8; 32];
        let mut rng = TestRng::new();

        let keygen_outputs: Vec<Cggmp21KeygenOutput> = round_based::sim::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            |i, party, mut rng| async move {
                keygen::run_keygen(party, i, n, t, sid, &mut rng)
                    .await
                    .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let pub_key = keygen_outputs[0].public_key;
        for (idx, out) in keygen_outputs.iter().enumerate() {
            assert_eq!(out.public_key, pub_key, "pub_key mismatch at {}", idx);
        }

        let signer_kgen: Vec<Cggmp21KeygenOutput> = signers
            .iter()
            .map(|&s| keygen_outputs[s as usize].clone())
            .collect();

        let presign_outputs: Vec<presign::Presignature> = round_based::sim::run_with_setup(
            signer_kgen.clone(),
            |i, party, kgen_out| async move {
                presign::run_presign(
                    party,
                    signers[usize::from(i)],
                    &signers,
                    &kgen_out.ec_share,

                    TestRng::new(),
                )
                .await
                .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let r_point = presign_outputs[0].r_point;
        let r = presign_outputs[0].r;
        let k_inv_0 = presign_outputs[0].k_inv;
        for (idx, p) in presign_outputs.iter().enumerate() {
            assert_eq!(p.r, r, "r mismatch at party {}", idx);
            assert_eq!(p.r_point, r_point, "r_point mismatch at party {}", idx);
            assert_eq!(p.k_inv, k_inv_0, "k_inv mismatch at party {}", idx);
        }

        let zip_iter = signer_kgen.into_iter().zip(presign_outputs);
        let sign_outputs: Vec<sign::Signature> =
            round_based::sim::run_with_setup(zip_iter, |i, party, (kgen_out, presig)| async move {
                sign::run_online_sign(
                    party,
                    signers[usize::from(i)],
                    &signers,
                    &kgen_out.ec_share,
                    &pub_key,
                    &msg_digest,
                    &presig,
                )
                .await
                .unwrap()
            })
            .unwrap()
            .into_vec();

        let sig = &sign_outputs[0];
        for (idx, s) in sign_outputs.iter().enumerate() {
            assert_eq!(s.r_bytes, sig.r_bytes, "r_bytes mismatch at party {}", idx);
            assert_eq!(s.s_bytes, sig.s_bytes, "s_bytes mismatch at party {}", idx);
        }

        let verified = verify_signature(&pub_key, &msg_digest, &sig.r_bytes, &sig.s_bytes);
        assert!(verified);
    }

    #[test]
    fn cggmp21_7of3_keygen_presign_sign() {
        let n = 7;
        let t = 3;
        let signers = [1u16, 3u16, 6u16];
        let sid = b"test-cggmp21-7of3";
        let msg_digest = [0xabu8; 32];
        let mut rng = TestRng::new();

        let keygen_outputs: Vec<Cggmp21KeygenOutput> = round_based::sim::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            |i, party, mut rng| async move {
                keygen::run_keygen(party, i, n, t, sid, &mut rng)
                    .await
                    .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let pub_key = keygen_outputs[0].public_key;
        for (idx, out) in keygen_outputs.iter().enumerate() {
            assert_eq!(out.public_key, pub_key, "pub_key mismatch at {}", idx);
        }

        let signer_kgen: Vec<Cggmp21KeygenOutput> = signers
            .iter()
            .map(|&s| keygen_outputs[s as usize].clone())
            .collect();

        let presign_outputs: Vec<presign::Presignature> = round_based::sim::run_with_setup(
            signer_kgen.clone(),
            |i, party, kgen_out| async move {
                presign::run_presign(
                    party,
                    signers[usize::from(i)],
                    &signers,
                    &kgen_out.ec_share,

                    TestRng::new(),
                )
                .await
                .unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let r_point = presign_outputs[0].r_point;
        let r = presign_outputs[0].r;
        let k_inv_0 = presign_outputs[0].k_inv;
        for (idx, p) in presign_outputs.iter().enumerate() {
            assert_eq!(p.r, r, "r mismatch at party {}", idx);
            assert_eq!(p.r_point, r_point, "r_point mismatch at party {}", idx);
            assert_eq!(p.k_inv, k_inv_0, "k_inv mismatch at party {}", idx);
        }

        let zip_iter = signer_kgen.into_iter().zip(presign_outputs);
        let sign_outputs: Vec<sign::Signature> =
            round_based::sim::run_with_setup(zip_iter, |i, party, (kgen_out, presig)| async move {
                sign::run_online_sign(
                    party,
                    signers[usize::from(i)],
                    &signers,
                    &kgen_out.ec_share,
                    &pub_key,
                    &msg_digest,
                    &presig,
                )
                .await
                .unwrap()
            })
            .unwrap()
            .into_vec();

        let sig = &sign_outputs[0];
        for (idx, s) in sign_outputs.iter().enumerate() {
            assert_eq!(s.r_bytes, sig.r_bytes, "r_bytes mismatch at party {}", idx);
            assert_eq!(s.s_bytes, sig.s_bytes, "s_bytes mismatch at party {}", idx);
        }

        let verified = verify_signature(&pub_key, &msg_digest, &sig.r_bytes, &sig.s_bytes);
        assert!(verified);
    }
}
