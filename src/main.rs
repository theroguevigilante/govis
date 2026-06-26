use std::net::SocketAddr;

use govis::cggmp21;
use govis::lindell::sign;
use round_based::mpc;
use sha2::{Digest, Sha256};

use govis::types::{Cggmp21KeyData, DkgOutput, LindellKeyData};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let my_index: u16 = match get_arg(&args, "--index") {
        Some(s) => s.parse().expect("invalid --index"),
        None => {
            eprintln!(
                "Usage: {} --index <i> --addrs <host:port,...> [--protocol <lindell|cggmp21>] [--threshold <t>] [--signers <i,j,...>] [--sid <id>] [--sign <hex> | --file <path>] [--refresh --old-share <hex> --master-pk <hex>] [--save-key <file>] [--load-key <file>] [--paillier-bits <bits>]",
                args[0]
            );
            std::process::exit(1);
        }
    };

    let do_refresh = get_arg(&args, "--refresh").is_some();

    let addrs_pos = args.iter().position(|a| a == "--addrs")
        .expect("missing --addrs <host:port,...>");

    let addrs: Vec<SocketAddr> = args[addrs_pos + 1..]
        .iter()
        .take_while(|a| !a.starts_with("--"))
        .flat_map(|s| s.split(','))
        .map(|s| s.parse().unwrap_or_else(|_| panic!("invalid address: {s}")))
        .collect();

    if addrs.is_empty() {
        eprintln!("Error: --addrs requires at least one address");
        std::process::exit(1);
    }

    let n = addrs.len() as u16;

    let protocol = get_arg(&args, "--protocol").unwrap_or("lindell");

    let threshold: u16 = match get_arg(&args, "--threshold") {
        Some(s) => {
            let t: u16 = s.parse().expect("invalid --threshold");
            if protocol == "lindell" {
                if t != 2 {
                    eprintln!("Error: Lindell protocol requires threshold 2, got {t}");
                    std::process::exit(1);
                }
                eprintln!("Note: --threshold is ignored for Lindell (always 2)");
            }
            t
        }
        None => {
            if protocol == "lindell" {
                2
            } else {
                let f = (n - 1) / 3;
                2 * f + 1
            }
        }
    };

    if let Some(bits_str) = get_arg(&args, "--paillier-bits") {
        let bits: usize = bits_str.parse().expect("invalid --paillier-bits");
        sign::set_paillier_bits(bits);
        eprintln!("Using Paillier modulus size: {bits} bits");
    }

    let signers: Vec<u16> = match get_arg(&args, "--signers") {
        Some(s) => s
            .split(',')
            .map(|x| x.parse().expect("invalid signer index"))
            .collect(),
        None => {
            if protocol == "lindell" {
                vec![0u16, 1u16]
            } else {
                (0..threshold).collect()
            }
        }
    };

    if protocol == "cggmp21" && signers.len() < threshold as usize {
        eprintln!(
            "Error: CGGMP21 requires at least --threshold ({threshold}) signers, got {}",
            signers.len()
        );
        std::process::exit(1);
    }

    if threshold > n {
        eprintln!(
            "Error: --threshold ({threshold}) cannot exceed the number of parties ({n})"
        );
        std::process::exit(1);
    }

    if let Some(&s) = signers.iter().find(|&&s| s >= n) {
        eprintln!("Error: signer index {s} is out of range (max index is {})", n - 1);
        std::process::exit(1);
    }

    let sid = get_arg(&args, "--sid").unwrap_or("dkg-session");

    if do_refresh {
        if protocol == "cggmp21" {
            eprintln!(
                "Error: --refresh is not yet supported for CGGMP21. Use --protocol lindell or omit --refresh."
            );
            std::process::exit(1);
        }
        run_refresh_cli(my_index, n, threshold, &addrs, sid, &args).await;
        return;
    }

    eprintln!("Party {my_index}/{n}: connecting (protocol={protocol}, threshold={threshold})...");

    match protocol {
        "cggmp21" => run_cggmp21(my_index, n, threshold, &signers, &addrs, sid, &args).await,
        _ => run_lindell(my_index, n, threshold, &signers, &addrs, sid, &args).await,
    }
}

async fn run_lindell(
    my_index: u16,
    n: u16,
    threshold: u16,
    signers: &[u16],
    addrs: &[SocketAddr],
    sid: &str,
    args: &[String],
) {
    let load_key_path = get_arg(args, "--load-key");

    let output = if let Some(path) = load_key_path {
        let data = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Failed to read --load-key {path}: {e}");
            std::process::exit(1);
        });
        let key_data: LindellKeyData = bincode::deserialize(&data).unwrap_or_else(|_| {
            eprintln!("Error: {path} is not a valid Lindell key file.");
            std::process::exit(1);
        });
        eprintln!("Party {my_index}: loaded key from {path}");
        DkgOutput::from_key_data(&key_data)
    } else {
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

        print_keygen_output(my_index, &output.public_key, &output.secret_share);
        output
    };

    if let Some(path) = get_arg(args, "--save-key") {
        let key_data = output.to_key_data();
        let bytes = bincode::serialize(&key_data).expect("failed to serialize key data");
        std::fs::write(path, &bytes).unwrap_or_else(|e| {
            eprintln!("Failed to write --save-key: {e}");
            std::process::exit(1);
        });
        eprintln!("Party {my_index}: saved key to {path}");
    }

    if let Some(msg_digest) = resolve_digest(args) {
        eprintln!("Party {my_index}: running signing...");

        let delivery2 = govis::tcp_delivery::connect_tcp(my_index, addrs)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Reconnect failed: {e}");
                std::process::exit(1);
            });

        let party2 = mpc::connected(delivery2);
        if signers.len() != 2 {
            eprintln!("Error: Lindell signing requires exactly 2 signers (got {})", signers.len());
            std::process::exit(1);
        }
        let signer_pair: [u16; 2] = [signers[0], signers[1]];
        let (r_bytes, s_bytes, rec_id) = match sign::run_sign(
            party2,
            my_index,
            n,
            &signer_pair,
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
    let load_key_path = get_arg(args, "--load-key");

    let output = if let Some(path) = load_key_path {
        let data = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Failed to read --load-key {path}: {e}");
            std::process::exit(1);
        });
        let key_data: Cggmp21KeyData = bincode::deserialize(&data).unwrap_or_else(|_| {
            eprintln!("Error: {path} is not a valid CGGMP21 key file.");
            std::process::exit(1);
        });
        eprintln!("Party {my_index}: loaded key from {path}");
        cggmp21::Cggmp21KeygenOutput::from_key_data(&key_data)
    } else {
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

        print_keygen_output(my_index, &output.public_key, &output.ec_share);
        output
    };

    if let Some(path) = get_arg(args, "--save-key") {
        let key_data = output.to_key_data();
        let bytes = bincode::serialize(&key_data).expect("failed to serialize key data");
        std::fs::write(path, &bytes).unwrap_or_else(|e| {
            eprintln!("Failed to write --save-key: {e}");
            std::process::exit(1);
        });
        eprintln!("Party {my_index}: saved key to {path}");
    }

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
    secret_share: &generic_ec::SecretScalar<generic_ec::curves::Secp256k1>,
) {
    println!("=== Party {my_index} Keygen Result ===");
    println!("Public key: {:?}", public_key);
    println!("Secret share: {}", hex::encode(secret_share.as_ref().to_be_bytes()));
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

async fn run_refresh_cli(
    my_index: u16,
    n: u16,
    threshold: u16,
    addrs: &[SocketAddr],
    sid: &str,
    args: &[String],
) {
    let (old_share, master_pk) = if let Some(path) = get_arg(args, "--load-key") {
        let data = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Failed to read --load-key {path}: {e}");
            std::process::exit(1);
        });
        let key_data: LindellKeyData = bincode::deserialize(&data).unwrap_or_else(|_| {
            eprintln!("Error: {path} is not a valid Lindell key file.");
            std::process::exit(1);
        });
        let out = DkgOutput::from_key_data(&key_data);
        eprintln!("Party {my_index}: loaded key from {path}");
        (out.secret_share, out.public_key)
    } else {
        let old_share_hex = get_arg(args, "--old-share")
            .expect("--refresh requires either --load-key <file> or --old-share <hex> + --master-pk <hex>");
        let master_pk_hex = get_arg(args, "--master-pk")
            .expect("--refresh requires --master-pk <hex> with --old-share");

        let old_share_bytes = hex::decode(old_share_hex).expect("invalid hex in --old-share");
        let old_share = generic_ec::SecretScalar::<generic_ec::curves::Secp256k1>::new(
            &mut generic_ec::Scalar::<generic_ec::curves::Secp256k1>::from_be_bytes_mod_order(
                &old_share_bytes,
            ),
        );

        let master_pk_bytes = hex::decode(master_pk_hex).expect("invalid hex in --master-pk");
        let master_pk =
            generic_ec::Point::<generic_ec::curves::Secp256k1>::from_bytes(&master_pk_bytes)
                .expect("invalid point in --master-pk");
        (old_share, master_pk)
    };

    let delivery = govis::tcp_delivery::connect_tcp(my_index, addrs)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Connection failed: {e}");
            std::process::exit(1);
        });

    eprintln!("Party {my_index}: connected, running key refresh...");
    let party = round_based::mpc::connected(delivery);
    let output = govis::run_refresh(
        party,
        my_index,
        n,
        threshold,
        sid.as_bytes(),
        &old_share,
        master_pk,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("Key refresh failed: {e:?}");
        std::process::exit(1);
    });

    if let Some(path) = get_arg(args, "--save-key") {
        let key_data = DkgOutput {
            secret_share: output.secret_share.clone(),
            public_key: master_pk,
        }
        .to_key_data();
        let bytes = bincode::serialize(&key_data).expect("failed to serialize key data");
        std::fs::write(path, &bytes).unwrap_or_else(|e| {
            eprintln!("Failed to write --save-key: {e}");
            std::process::exit(1);
        });
        eprintln!("Party {my_index}: saved refreshed key to {path}");
    }

    println!("=== Party {my_index} Key Refresh Result ===");
    println!(
        "New secret share: {}",
        hex::encode(output.secret_share.as_ref().to_be_bytes())
    );
    println!(
        "Master public key: {}",
        hex::encode(master_pk.to_bytes(true))
    );
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
