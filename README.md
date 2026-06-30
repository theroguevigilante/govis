# govis

Rust implementation of threshold ECDSA over secp256k1 based on the Lindell and CGGMP21 protocols. 

## Status

**Experimental**

- Lindell protocol is feature complete, including key refresh.
- CGGMP21 supports key generation, presigning, and online signing.
- CGGMP21 key refresh is not yet implemented.
- The implementation has not been independently security audited.

## Motivation

A standard private key creates a single point of failure. Threshold signing splits the key into shares so that no one party can sign alone and the full key is never reconstructed. This is useful for multi-sig wallets, distributed custody, etc.

## Features

- Lindell 2-of-n threshold ECDSA
- CGGMP21 t-of-n threshold ECDSA
- Distributed key generation (DKG)
- Threshold signing
- Lindell key refresh
- Paillier-based secure multiparty computation
- TCP-based networking
- Key persistence
- CLI

## Installation

Requires Rust (edition 2024). Build with:

```bash
cargo build --release
```

No external system dependencies.

## Building

```bash
# Debug build
cargo build

# Release build (recommended for actual use)
cargo build --release
```

## Usage

All parties must be started within a few seconds of each other. Each party prints its public key and secret share after keygen, and the resulting signature after signing.

### Lindell 2-of-3 keygen + sign (3 terminals)

```bash
# Terminal 0
cargo run --release -- --index 0 --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002 --sign abababababababababababababababababababababababababababababababab

# Terminal 1
cargo run --release -- --index 1 --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002 --sign abababababababababababababababababababababababababababababababab

# Terminal 2
cargo run --release -- --index 2 --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002 --sign abababababababababababababababababababababababababababababababab
```

### CGGMP21 3-of-5 keygen + sign (5 terminals)

```bash
# Each terminal i (0..4)
cargo run --release -- --index <i> --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004 --protocol cggmp21 --threshold 3 --signers 0,1,2 --sign abababababababababababababababababababababababababababababababab
```

### Save and load keys

```bash
# Keygen + save
cargo run --release -- --index 0 --addrs ... --protocol lindell --save-key /tmp/party_0.bin

# Later: load + sign (skips keygen)
cargo run --release -- --index 0 --addrs ... --protocol lindell --load-key /tmp/party_0.bin --sign <hex>
```

### Key refresh (Lindell only)

```bash
cargo run --release -- --index 0 --addrs ... --protocol lindell --refresh --load-key /tmp/party_0.bin --save-key /tmp/party_0_refreshed.bin
```

### Sign a file (SHA256 hash)

```bash
cargo run --release -- --index 0 --addrs ... --file /path/to/document.pdf
```

### All CLI flags

| Flag | Description |
|------|-------------|
| `--index <i>` | This party's index (0..n-1) |
| `--addrs <host:port,...>` | Addresses of all n parties |
| `--protocol <lindell\|cggmp21>` | Protocol (default: lindell) |
| `--threshold <t>` | Minimum signers (Lindell: forced to 2; CGGMP21: default 2f+1) |
| `--signers <i,j,...>` | Which parties sign (Lindell default: 0,1; CGGMP21 default: 0..threshold) |
| `--sid <id>` | Session ID (default: "dkg-session") |
| `--sign <hex>` | 32-byte hex digest to sign |
| `--file <path>` | Sign SHA256 hash of file |
| `--refresh` | Run key refresh (Lindell only) |
| `--old-share <hex>` | Secret share hex (with --refresh, no --load-key) |
| `--master-pk <hex>` | Master public key hex (with --refresh, no --load-key) |
| `--save-key <file>` | Save key material after keygen or refresh |
| `--load-key <file>` | Load saved key material (skips keygen) |
| `--paillier-bits <bits>` | Paillier modulus size (default: 2048) |

### Key files

Both protocols produce 81-byte binary files in bincode format:

```
lindell:  "lindell"  [32 bytes secret_share] [33 bytes compressed public_key]
cggmp21:  "cggmp21" [32 bytes ec_share]      [33 bytes compressed public_key]
```

Paillier keys are not persisted. CGGMP21 generates fresh Paillier keypairs during each presign session via a key-exchange round.

### Convenience script

```bash
# keygen → sign (3 parties, threshold 2)
./keygen-sign.sh --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002 --threshold 2

# keygen → refresh → sign (Lindell)
./keygen-sign.sh --addrs ... --threshold 2 --refresh

# CGGMP21 3-of-3
./keygen-sign.sh --addrs ... --protocol cggmp21 --threshold 2
```

| Feature | Lindell | CGGMP21 |
|---------|---------|----------|
| Threshold | 2-of-n | t-of-n |
| Key refresh | ✅ | ❌ |
| Presigning | ❌ | ✅ |
| Paillier | During signing | During presign |
| Use case | Simpler deployments | General threshold signing |

## Architecture

The protocol execution follows a round-based pattern using the `round-based` crate:

1. **DKG (Feldman VSS)** — Each party generates a random polynomial, commits to its coefficients, reveals them, and distributes shares. Parties verify received shares against the committed coefficients. The sum of all parties' constant-term commitments is the joint public key; each party's share is the sum of received shares.

2. **Lindell signing** (3 rounds) — P1 generates a Paillier keypair and encrypts `k⁻¹` under it. Both parties compute their partial signature using Lagrange interpolation over their secret shares. P1 decrypts and combines the partial signatures into a standard ECDSA signature. ZK proofs prevent malicious behavior at each step.

3. **CGGMP21 signing** (3 phases) — Keygen produces EC secret shares and Paillier keypairs. Presign generates ephemeral Paillier keys and precomputes `k`, `R = k·G`, and additive shares of `k·σ` (where σ is the secret). Online sign uses the presignature to produce the final ECDSA signature in a single round.

4. **Networking** — `TcpDelivery` implements `futures::Stream` + `Sink` for the `round-based` MPC trait. Parties bind to their port, accept incoming connections from lower-index parties, and dial higher-index parties. Reconnecting for signing uses `SO_REUSEADDR` to avoid `TIME_WAIT` conflicts.

5. **Key refresh** — Each party runs DKG with a zero intercept, producing additive offsets. Parties apply received offsets to their existing secret share. The public key remains unchanged.

## Testing

```bash
# All 36 tests
cargo test

# CGGMP21 tests only (includes slow 7-of-5)
cargo test cggmp21

# Lindell tests only
cargo test lindell

# Core DKG math tests
cargo test core
```
Tests use `round_based::sim` for in-process multi-party simulation with deterministic `TestRng`. No network setup is needed.

## References

This implementation is based on the following works:

- Lindell, *Fast Secure Two-Party ECDSA Signing*
- Canetti et al., *UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts (CGGMP21)*
- Feldman, *A Practical Scheme for Non-Interactive Verifiable Secret Sharing*
- Paillier, *Public-Key Cryptosystems Based on Composite Degree Residuosity Classes*

## Security

- This project is highly experimental.
- The implementation tries to follow Lindell and CGGMP21 protocols but has not undergone an independent security audit.
- Use caution before deploying it in production.
- 🔒 [Security Policy](SECURITY.md)

## Contributing

- Contributions are welcome.
- Please open an issue for discussion before significant changes.

## License

GNU General Public License v3.0 (GPL-3.0). See [License](LICENSE).
