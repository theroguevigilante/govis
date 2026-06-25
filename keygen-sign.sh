#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 --addrs <host:port,...> [options]

Options:
  --addrs <host:port,...>   Comma-separated list of party addresses (required)
  --threshold <t>           Signing threshold (default: 2f+1 for BFT)
  --protocol <lindell|cggmp21>  Protocol to use (default: lindell)
  --sign <hex>              32-byte hex digest to sign (default: random)
  --signers <i,j,...>       Signer indices (default: 0,1 for Lindell; all parties for CGGMP21)
  --refresh                 Run key refresh after keygen before signing (Lindell only)
  --outdir <dir>            Directory for key files (default: tmp dir, deleted on exit)
  --keep-keys               Don't delete key files after signing
  --cargo-profile <profile>  Cargo profile (default: --release)
  --help                    Show this help

Examples:
  # 3-of-4 keygen then sign with Lindell (default signers 0,1)
  $0 --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 --threshold 2

  # 3-of-4 keygen, refresh, then sign with Lindell
  $0 --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 --threshold 2 --refresh

  # 3-of-5 keygen + sign with CGGMP21
  $0 --addrs 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004 --protocol cggmp21 --threshold 2
EOF
    exit 1
}

if [ $# -eq 0 ]; then usage; fi

# Parse args
ADDRS=""
THRESHOLD=""
PROTOCOL="lindell"
SIGN_HEX=""
SIGNERS=""
DO_REFRESH=false
OUTDIR=""
KEEP_KEYS=false
CARGO_PROFILE="--release"
POSITIONAL=()

while [ $# -gt 0 ]; do
    case "$1" in
        --addrs) ADDRS="$2"; shift 2 ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --protocol) PROTOCOL="$2"; shift 2 ;;
        --sign) SIGN_HEX="$2"; shift 2 ;;
        --signers) SIGNERS="$2"; shift 2 ;;
        --refresh) DO_REFRESH=true; shift ;;
        --outdir) OUTDIR="$2"; shift 2 ;;
        --keep-keys) KEEP_KEYS=true; shift ;;
        --cargo-profile) CARGO_PROFILE="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [ -z "$ADDRS" ]; then
    echo "Error: --addrs is required"
    usage
fi

# Parse addresses
IFS=',' read -ra ADDR_ARRAY <<< "$ADDRS"
N=${#ADDR_ARRAY[@]}

if [ -z "$THRESHOLD" ]; then
    F=$(( (N - 1) / 3 ))
    THRESHOLD=$(( 2 * F + 1 ))
fi

# Resolve signers
if [ -z "$SIGNERS" ]; then
    if [ "$PROTOCOL" = "cggmp21" ]; then
        # CGGMP21: all parties participate in signing
        SIGNERS=$(seq 0 $((N - 1)) | paste -sd,)
    else
        # Lindell: default to 2-party
        SIGNERS="0,1"
    fi
fi
if [ -z "$SIGN_HEX" ]; then
    SIGN_HEX=$(openssl rand -hex 32)
    echo "Using random digest: 0x$SIGN_HEX"
fi

# Create output directory
if [ -z "$OUTDIR" ]; then
    OUTDIR=$(mktemp -d)
    CLEANUP_DIR=true
else
    mkdir -p "$OUTDIR"
    CLEANUP_DIR=false
fi

echo "=============================="
echo " Parties:    $N"
echo " Threshold:  $THRESHOLD"
echo " Protocol:   $PROTOCOL"
echo " Addresses:  $ADDRS"
echo " Out dir:    $OUTDIR"
echo "=============================="

cleanup() {
    echo ""
    echo "Cleaning up..."
    # Kill any remaining background processes
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
    if [ "$CLEANUP_DIR" = true ] && [ "$KEEP_KEYS" = false ]; then
        rm -rf "$OUTDIR"
        echo "Removed temp dir $OUTDIR"
    fi
}
trap cleanup EXIT INT TERM

# Phase 1: keygen
echo ""
echo "=== Phase 1: Keygen ==="
echo ""

KEY_FILES=()
PID_LIST=()

for i in $(seq 0 $((N - 1))); do
    KEY_FILE="$OUTDIR/party_${i}.bin"
    KEY_FILES+=("$KEY_FILE")
    LOG_FILE="$OUTDIR/party_${i}_keygen.log"
    echo "Starting party $i (log: $LOG_FILE)..."

    cargo run $CARGO_PROFILE -- \
        --index "$i" \
        --addrs "$ADDRS" \
        --protocol "$PROTOCOL" \
        --threshold "$THRESHOLD" \
        --save-key "$KEY_FILE" \
        > "$LOG_FILE" 2>&1 &
    PID_LIST+=($!)
done

echo "Waiting for all parties to complete keygen..."
FAILED=false
for i in $(seq 0 $((N - 1))); do
    if wait "${PID_LIST[$i]}"; then
        echo "Party $i: keygen OK"
    else
        echo "Party $i: keygen FAILED (exit code $?)"
        FAILED=true
    fi
done

if [ "$FAILED" = true ]; then
    echo "Keygen failed. Check logs in $OUTDIR"
    exit 1
fi

# Display public keys
echo ""
echo "Public keys:"
for i in $(seq 0 $((N - 1))); do
    LOG_FILE="$OUTDIR/party_${i}_keygen.log"
    PUBKEY=$(grep "Public key:" "$LOG_FILE" | sed 's/.*Public key: //')
    echo "  Party $i: $PUBKEY"
done

# Display secret shares
echo ""
echo "Secret shares:"
for i in $(seq 0 $((N - 1))); do
    LOG_FILE="$OUTDIR/party_${i}_keygen.log"
    SHARE=$(grep "Secret share:" "$LOG_FILE" | sed 's/.*Secret share: //')
    echo "  Party $i: 0x$SHARE"
done

# Phase 2: key refresh (optional)
REFRESHED_FILES=()
if [ "$DO_REFRESH" = true ]; then
    echo ""
    echo "=== Phase 2: Key Refresh ==="
    echo ""

    PID_LIST=()
    for i in $(seq 0 $((N - 1))); do
        REFRESHED_FILE="$OUTDIR/party_${i}_refreshed.bin"
        REFRESHED_FILES+=("$REFRESHED_FILE")
        LOG_FILE="$OUTDIR/party_${i}_refresh.log"
        echo "Starting party $i refresh (log: $LOG_FILE)..."

        cargo run $CARGO_PROFILE -- \
            --index "$i" \
            --addrs "$ADDRS" \
            --protocol "$PROTOCOL" \
            --threshold "$THRESHOLD" \
            --refresh \
            --load-key "${KEY_FILES[$i]}" \
            --save-key "$REFRESHED_FILE" \
            > "$LOG_FILE" 2>&1 &
        PID_LIST+=($!)
    done

    echo "Waiting for all parties to complete refresh..."
    FAILED=false
    for i in $(seq 0 $((N - 1))); do
        if wait "${PID_LIST[$i]}"; then
            echo "Party $i: refresh OK"
        else
            echo "Party $i: refresh FAILED"
            FAILED=true
        fi
    done

    if [ "$FAILED" = true ]; then
        echo "Refresh failed. Check logs in $OUTDIR"
        exit 1
    fi

    # Display new shares
    echo ""
    echo "Refreshed secret shares:"
    for i in $(seq 0 $((N - 1))); do
        LOG_FILE="$OUTDIR/party_${i}_refresh.log"
        SHARE=$(grep "New secret share:" "$LOG_FILE" | sed 's/.*New secret share: //')
        echo "  Party $i: 0x$SHARE"
    done
fi

# Use refreshed keys for signing if available, else original keys
SIGN_KEY_FILES=("${KEY_FILES[@]}")
if [ "$DO_REFRESH" = true ]; then
    SIGN_KEY_FILES=("${REFRESHED_FILES[@]}")
fi

# Phase 3: sign
echo ""
echo "=== Phase 3: Sign (digest: 0x$SIGN_HEX) ==="
echo ""

PID_LIST=()

PID_LIST=()
for i in $(seq 0 $((N - 1))); do
    LOG_FILE="$OUTDIR/party_${i}_sign.log"
    echo "Starting party $i signing (log: $LOG_FILE)..."

    SIG_ARGS=()
    SIG_ARGS+=(--index "$i")
    SIG_ARGS+=(--addrs "$ADDRS")
    SIG_ARGS+=(--protocol "$PROTOCOL")
    SIG_ARGS+=(--threshold "$THRESHOLD")
    SIG_ARGS+=(--load-key "${SIGN_KEY_FILES[$i]}")
    if [ -n "$SIGNERS" ]; then
        SIG_ARGS+=(--signers "$SIGNERS")
    fi
    SIG_ARGS+=(--sign "$SIGN_HEX")

    cargo run $CARGO_PROFILE -- "${SIG_ARGS[@]}" > "$LOG_FILE" 2>&1 &
    PID_LIST+=($!)
done

echo "Waiting for all parties to complete signing..."
FAILED=false
for i in $(seq 0 $((N - 1))); do
    if wait "${PID_LIST[$i]}"; then
        echo "Party $i: sign OK"
    else
        echo "Party $i: sign FAILED"
        FAILED=true
    fi
done

if [ "$FAILED" = true ]; then
    echo "Signing failed. Check logs in $OUTDIR"
    exit 1
fi

# Display signature
echo ""
echo "=== Signature ==="
for i in $(seq 0 $((N - 1))); do
    LOG_FILE="$OUTDIR/party_${i}_sign.log"
    if [ -f "$LOG_FILE" ]; then
        echo "--- Party $i ---"
        grep -E "^(r:|s:|rec_id|Verify|Ethereum|Bitcoin)" "$LOG_FILE" || echo "  (no signature output found)"
    fi
done

echo ""
echo "Done. Logs and keys in: $OUTDIR"
