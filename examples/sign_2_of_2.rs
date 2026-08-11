use govis::lindell::sign::{run_sign, verify_signature};
use govis::run_dkg;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::Digest;

#[tokio::main]
async fn main() {
    let (n, t) = (2u16, 1u16);
    let sid = b"example-session";
    let msg_digest: [u8; 32] = sha2::Sha256::digest(b"hello world").into();

    let outputs = round_based::sim::run_with_setup(
        (0..n).map(|i| StdRng::seed_from_u64(i.into())),
        |i, party, mut rng| async move {
            run_dkg(party, i, n, t, sid, &mut rng).await.unwrap()
        },
    )
    .unwrap()
    .into_vec();

    let public_key = outputs[0].public_key;
    println!("public key: {}", hex::encode(public_key.to_bytes(true)));

    let signers = [0u16, 1u16];
    let signatures = round_based::sim::run_with_setup(
        (0..n).map(|i| StdRng::seed_from_u64(i.into())),
        |i, party, mut rng| {
            let share = outputs[usize::from(i)].secret_share.clone();
            async move {
                run_sign(party, i, n, &signers, &share, &public_key, &msg_digest, &mut rng)
                    .await
                    .unwrap()
            }
        },
    )
    .unwrap()
    .expect_eq();

    let (r, s, rec_id) = signatures;
    println!("r: {}", hex::encode(&r));
    println!("s: {}", hex::encode(&s));
    println!("recovery id: {rec_id}");
    println!(
        "signature valid: {}",
        verify_signature(&public_key, &msg_digest, &r, &s)
    );
}
