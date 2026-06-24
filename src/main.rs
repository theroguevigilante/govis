use std::net::SocketAddr;

use govis::cggmp21;
use govis::lindell::sign;
use round_based::mpc;
use sha2::{Digest, Sha256};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let my_index: u16 = match get_arg(&args, "--index") {
        Some(s) => s.parse().expect("invalid --index"),
        None => {
            eprintln!(
                "Usage: {} --index <i> --addrs <host:port,...> [--protocol <lindell|cggmp21>] [--threshold <t>] [--signers <i,j,...>] [--sid <id>] [--sign <hex> | --file <path>]",
                args[0]
            );
            std::process::exit(1);
        }
    };

    let addrs_str = get_arg(&args, "--addrs").expect("missing --addrs <host:port,host:port,...>");

    let addrs: Vec<SocketAddr> = addrs_str
        .split(',')
        .map(|s| s.parse().unwrap_or_else(|_| panic!("invalid address: {s}")))
        .collect();

    let n = addrs.len() as u16;

    let threshold: u16 = match get_arg(&args, "--threshold") {
        Some(s) => s.parse().expect("invalid --threshold"),
        None => {
            let f = (n - 1) / 3;
            2 * f + 1
        }
    };

    let protocol = get_arg(&args, "--protocol").unwrap_or("lindell");

    let signers: Vec<u16> = match get_arg(&args, "--signers") {
        Some(s) => s
            .split(',')
            .map(|x| x.parse().expect("invalid signer index"))
            .collect(),
        None => vec![0u16, 1u16],
    };

    let sid = get_arg(&args, "--sid").unwrap_or("dkg-session");

    eprintln!("Party {my_index}/{n}: connecting (protocol={protocol}, threshold={threshold})...");

    match protocol {
        "cggmp21" => run_cggmp21(my_index, n, threshold, &signers, &addrs, sid, &args).await,
        _ => run_lindell(my_index, n, threshold, &addrs, sid, &args).await,
    }
}

async fn run_lindell(
    my_index: u16,
    n: u16,
    threshold: u16,
    addrs: &[SocketAddr],
    sid: &str,
    args: &[String],
) {
    let delivery = govis::tcp_delivery::connect_tcp(my_index, addrs)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Connection failed: {e}");
            std::process::exit(1);
        });

    eprintln!("Party {my_index}: connected, running DKG...");

    let party = mpc::connected(delivery);
    let output = govis::run_dkg(
        party,
        my_index,
        n,
        threshold,
        sid.as_bytes(),
        &mut rand_core::OsRng,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("DKG failed: {e:?}");
        std::process::exit(1);
    });

    print_keygen_output(my_index, &output.public_key);

    if let Some(msg_digest) = resolve_digest(args) {
        eprintln!("Party {my_index}: running signing...");

        let delivery2 = govis::tcp_delivery::connect_tcp(my_index, addrs)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Reconnect failed: {e}");
                std::process::exit(1);
            });

        let party2 = mpc::connected(delivery2);
        let signers = [0, 1];
        let (r_bytes, s_bytes, rec_id) = match sign::run_sign(
            party2,
            my_index,
            n,
            &signers,
            &output.secret_share,
            &output.public_key,
            &msg_digest,
            &mut rand_core::OsRng,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Signing failed: {e:?}");
                std::process::exit(1);
            }
        };

        print_signature(
            my_index,
            &output.public_key,
            &msg_digest,
            &r_bytes,
            &s_bytes,
            rec_id,
        );
    }
}

async fn run_cggmp21(
    my_index: u16,
    n: u16,
    threshold: u16,
    signers: &[u16],
    addrs: &[SocketAddr],
    sid: &str,
    args: &[String],
) {
    // Phase 1: Keygen
    let delivery = govis::tcp_delivery::connect_tcp(my_index, addrs)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Connection failed: {e}");
            std::process::exit(1);
        });

    eprintln!("Party {my_index}: connected, running CGGMP21 keygen...");

    let party = mpc::connected(delivery);
    let output = cggmp21::keygen::run_keygen(
        party,
        my_index,
        n,
        threshold,
        sid.as_bytes(),
        &mut rand_core::OsRng,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("CGGMP21 keygen failed: {e:?}");
        std::process::exit(1);
    });

    print_keygen_output(my_index, &output.public_key);

    // Phase 2: Presign (if --sign or --file is provided)
    if let Some(msg_digest) = resolve_digest(args) {
        eprintln!("Party {my_index}: running presign...");

        let delivery2 = govis::tcp_delivery::connect_tcp(my_index, addrs)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Presign reconnect failed: {e}");
                std::process::exit(1);
            });

        let party2 = mpc::connected(delivery2);
        let presig = cggmp21::presign::run_presign(
            party2,
            my_index,
            signers,
            &output.ec_share,
            &output.peer_paillier_pks,
            &output.paillier_sk,
            &output.paillier_pk,
            rand_core::OsRng,
        )
        .await
        .unwrap_or_else(|e| {
            eprintln!("Presign failed: {e:?}");
            std::process::exit(1);
        });

        // Phase 3: Online sign
        eprintln!("Party {my_index}: running online sign...");
        let delivery3 = govis::tcp_delivery::connect_tcp(my_index, addrs)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Sign reconnect failed: {e}");
                std::process::exit(1);
            });

        let party3 = mpc::connected(delivery3);
        let sig = cggmp21::sign::run_online_sign(
            party3,
            my_index,
            signers,
            &output.ec_share,
            &output.public_key,
            &msg_digest,
            &presig,
        )
        .await
        .unwrap_or_else(|e| {
            eprintln!("Online sign failed: {e:?}");
            std::process::exit(1);
        });

        print_signature(
            my_index,
            &output.public_key,
            &msg_digest,
            &sig.r_bytes,
            &sig.s_bytes,
            sig.rec_id,
        );
    }
}

fn print_keygen_output(
    my_index: u16,
    public_key: &generic_ec::Point<generic_ec::curves::Secp256k1>,
) {
    println!("=== Party {my_index} Keygen Result ===");
    println!("Public key: {:?}", public_key);
}

fn print_signature(
    my_index: u16,
    public_key: &generic_ec::Point<generic_ec::curves::Secp256k1>,
    msg_digest: &[u8; 32],
    r_bytes: &[u8],
    s_bytes: &[u8],
    rec_id: u8,
) {
    println!("=== Party {my_index} Signature ===");
    println!("r: {}", hex::encode(r_bytes));
    println!("s: {}", hex::encode(s_bytes));
    println!("rec_id: {rec_id}");
    println!(
        "Verify: {}",
        sign::verify_signature(public_key, msg_digest, r_bytes, s_bytes)
    );

    // Ethereum 65-byte format
    let eth_sig = sign::ethereum_signature(r_bytes, s_bytes, rec_id, None);
    println!("Ethereum: 0x{}", hex::encode(&eth_sig));
    let eth_sig_eip155 = sign::ethereum_signature(r_bytes, s_bytes, rec_id, Some(1));
    println!(
        "Ethereum (EIP-155 chain 1): 0x{}",
        hex::encode(&eth_sig_eip155)
    );

    // Bitcoin DER format
    let btc_sig = sign::bitcoin_der_signature(r_bytes, s_bytes);
    println!("Bitcoin DER: {}", hex::encode(&btc_sig));
}

fn resolve_digest(args: &[String]) -> Option<[u8; 32]> {
    if let Some(hex_str) = get_arg(args, "--sign") {
        let bytes = hex::decode(hex_str).expect("invalid hex in --sign");
        if bytes.len() != 32 {
            eprintln!("--sign value must be 32 bytes (64 hex chars)");
            std::process::exit(1);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Some(arr);
    }

    if let Some(path) = get_arg(args, "--file") {
        let data = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("failed to read --file {path}: {e}");
            std::process::exit(1);
        });
        let hash = Sha256::digest(&data);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        eprintln!(
            "Hashed file ({}, {} bytes): 0x{}",
            path,
            data.len(),
            hex::encode(arr)
        );
        return Some(arr);
    }

    None
}

fn get_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}
