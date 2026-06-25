# Govis

Threshold cryptography library in Rust implementing **CGGMP21** (t-of-n) and **Lindell** (2-party) ECDSA signing protocols over secp256k1, with a CLI for multi-party key generation and signing over TCP.

## Status

- [x] Lindell 2-party DKG + signing
- [x] CGGMP21 t-of-n keygen, presign, online sign
- [x] Paillier encryption & ZK proofs (range, consistency, log, Schnorr, Blum)
- [x] TCP multi-party networking (`tcp_delivery`)
- [x] CLI: `--index`, `--addrs`, `--protocol`, `--threshold`, `--signers`, `--sid`, `--sign`/`--file`, `--refresh`, `--save-key`, `--load-key`
- [x] 36 unit tests (simulated MPC, all thresholds)
- [x] Deterministic RNG via `TestRng` for reproducible tests
- [x] Ephemeral Paillier keys in CGGMP21 presign (not persisted)
- [x] Protocol-tagged key files (`"lindell"` or `"cggmp21"` in each `.bin`)
- [x] `keygen-sign.sh` — one-click keygen → refresh → sign workflow

## Modules

| Path | Description |
|------|-------------|
| `src/core.rs` | Feldman VSS DKG — polynomial evaluation, share generation, key refresh |
| `src/types.rs` | Common message types (`CommitMsg`, `RevealMsg`, `ShareMsg`, `DkgOutput`, `LindellKeyData`, `Cggmp21KeyData`) |
| `src/paillier.rs` | Paillier encryption & decryption |
| `src/paillier_zk.rs` | Zero-knowledge proofs for Paillier-based MTA |
| `src/mta.rs` | Multiplicative-to-additive (MtA) protocol |
| `src/tcp_delivery.rs` | Async TCP network layer via `tokio` |
| `src/lindell/` | Lindell 2-party (t=1, n=2) — DKG + sign |
| `src/cggmp21/` | CGGMP21 t-of-n — keygen, presign, online sign |
| `src/main.rs` | CLI entry point |

## CLI Usage

```bash
# 2-party keygen + sign (Lindell)
govis --index 0 --addrs 127.0.0.1:9000,127.0.0.1:9001 --sign <hex>

# Keygen, save keys for later reuse
govis --index 0 --addrs ... --save-key party0.bin

# Load saved keys and sign (skip keygen, any protocol)
govis --index 0 --addrs ... --load-key party0.bin --sign <hex>

# CGGMP21 3-of-5 keygen + sign
govis --index 0 --addrs 127.0.0.1:{9000..9004} --protocol cggmp21 --threshold 3 --signers 0,1,2 --sign <hex>

# Sign a file (SHA256 digest)
govis --index 0 --addrs ... --file <path>

# Key refresh (Lindell) via saved key
govis --index 0 --addrs ... --refresh --load-key party0.bin --save-key party0_refreshed.bin

# Key refresh (Lindell) via hex (legacy)
govis --index 0 --addrs ... --refresh --old-share <hex> --master-pk <hex>
```

### All flags

| Flag | Description |
|------|-------------|
| `--index <i>` | This party's index (required) |
| `--addrs <host:port,...>` | Comma-separated addresses of all parties (required) |
| `--protocol <lindell\|cggmp21>` | Protocol to use (default: lindell) |
| `--threshold <t>` | Signing threshold (default: 2f+1 for BFT) |
| `--signers <i,j,...>` | Signer indices (default: 0,1 for Lindell; all parties for CGGMP21) |
| `--sid <id>` | Session ID string (default: "dkg-session") |
| `--sign <hex>` | 32-byte hex digest to sign |
| `--file <path>` | Sign SHA256 hash of file |
| `--refresh` | Run key refresh instead of keygen (Lindell only) |
| `--old-share <hex>` | Current secret share hex (required with `--refresh` without `--load-key`) |
| `--master-pk <hex>` | Master public key hex (required with `--refresh` without `--load-key`) |
| `--save-key <file>` | Save key material to file after keygen or refresh |
| `--load-key <file>` | Load key material from file (skips keygen) |

### Key files

Both protocols produce 81-byte bincode files containing a protocol tag, 32-byte secret share, and 33-byte compressed public key:

```
Lindell:  "lindell"  [32 bytes secret_share] [33 bytes public_key]
CGGMP21:  "cggmp21" [32 bytes ec_share]      [33 bytes public_key]
```

Paillier keys are **not persisted** — CGGMP21 generates fresh Paillier keypairs during each presign session via a key-exchange round, keeping the key files small and stateless.

Loading a key with the wrong `--protocol` prints a clear error (`key file protocol mismatch`).

## Script: keygen-sign.sh

A convenience script for testing multi-party flows — keygen, optional refresh, and sign in one command:

```bash
# Keygen → sign (3 parties, signers 0,1)
./keygen-sign.sh --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002 --threshold 2

# Keygen → refresh → sign
./keygen-sign.sh --addrs ... --threshold 2 --refresh

# Keygen → sign (CGGMP21 3-of-3)
./keygen-sign.sh --addrs ... --protocol cggmp21 --threshold 2

See `./keygen-sign.sh --help` for all options.

## Tests

```bash
cargo test                    # all 36 tests
cargo test cggmp21            # 5 CGGMP21 tests (slow: ~60s for 7-of-5)
```

## Dependencies

`generic-ec` (secp256k1), `round-based` (0.5.0-alpha.1), `tokio`, `num-bigint`, `paillier` ZK proofs, `serde`, `sha2`.

## License

GNU General Public License v3.0 (GPL-3.0)
