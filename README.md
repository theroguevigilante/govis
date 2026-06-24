# Govis

Threshold cryptography library in Rust implementing **CGGMP21** (t-of-n) and **Lindell** (2-party) ECDSA signing protocols over secp256k1, with a CLI for multi-party key generation and signing over TCP.

## Status

- [x] Lindell 2-party DKG + signing
- [x] CGGMP21 t-of-n keygen, presign, online sign
- [x] Paillier encryption & ZK proofs (range, consistency, log, Schnorr, Blum)
- [x] TCP multi-party networking (`tcp_delivery`)
- [x] CLI: `--index`, `--addrs`, `--protocol`, `--threshold`, `--signers`, `--sid`, `--sign`/`--file`
- [x] 35 unit tests (simulated MPC, all thresholds)
- [x] Deterministic RNG via `TestRng` for reproducible tests

## Modules

| Path | Description |
|------|-------------|
| `src/core.rs` | Pedersen DKG — polynomial evaluation, share generation, key refresh |
| `src/types.rs` | Common message types (`CommitMsg`, `RevealMsg`, `ShareMsg`, `DkgOutput`) |
| `src/paillier.rs` | Paillier encryption & decryption |
| `src/paillier_zk.rs` | Zero-knowledge proofs for Paillier-based MTA |
| `src/mta.rs` | Multiplicative-to-additive (MtA) protocol |
| `src/tcp_delivery.rs` | Async TCP network layer via `tokio` |
| `src/lindell/` | Lindell 2-party (t=1, n=2) — DKG + sign |
| `src/cggmp21/` | CGGMP21 t-of-n — keygen, presign, online sign |
| `src/main.rs` | CLI entry point |

## CLI Usage

```bash
# Lindell 2-party keygen + sign (party 0)
govis --index 0 --addrs 127.0.0.1:9000,127.0.0.1:9001 --sign <hex>

# CGGMP21 3-of-5 signing
govis --index 0 --addrs 127.0.0.1:{9000..9004} --protocol cggmp21 --threshold 2 --signers 0,1,2 --sign <hex>

# Sign a file (SHA256 digest)
govis --index 0 --addrs ... --file <path>
```

## Tests

```bash
cargo test                    # all 35 tests
cargo test cggmp21            # 5 CGGMP21 tests (slow: ~60s for 7-of-5)
```

## Dependencies

`generic-ec` (secp256k1), `round-based` (0.5.0-alpha.1), `tokio`, `num-bigint`, `paillier` ZK proofs, `serde`, `sha2`.

## License

GNU General Public License v3.0 (GPL-3.0)
