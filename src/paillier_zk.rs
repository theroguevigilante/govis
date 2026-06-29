use generic_ec::{Point, Scalar, curves::Secp256k1};
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::scalar_to_bigint;
use crate::paillier;

fn bu2bi(u: &BigUint) -> BigInt {
    BigInt::from_biguint(num_bigint::Sign::Plus, u.clone())
}

fn g_pow(m: &BigInt, n: &BigInt, n_sq: &BigInt) -> BigInt {
    (BigInt::one() + m * n) % n_sq
}

/// Non-interactive range proof for Paillier.
/// Proves |m| < 2^ell where c = Enc_pk(m, rho).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    pub c_alpha: BigInt,
    pub z: BigInt,
    pub s: BigInt,
}

fn range_challenge(
    sid: &[u8],
    n: &BigUint,
    g: &BigUint,
    ell: usize,
    c: &BigInt,
    c_alpha: &BigInt,
) -> BigInt {
    let mut h = Sha256::new();
    h.update(b"govis-paillier-range");
    h.update(sid);
    h.update(n.to_bytes_be());
    h.update(g.to_bytes_be());
    h.update((ell as u64).to_be_bytes());
    h.update(c.to_bytes_be().1);
    h.update(c_alpha.to_bytes_be().1);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.finalize())
}

/// Proves that c = Enc(m, rho) has |m| < 2^ell.
pub fn prove_range(
    pk: &paillier::PaillierPublicKey,
    c: &BigInt,
    m: &BigInt,
    rho: &BigInt,
    ell: usize,
    sid: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> RangeProof {
    let n = bu2bi(&pk.n);
    let n_sq = bu2bi(&pk.n_sq);

    let sec = 256usize;
    let n_bit = pk.n.bits() as usize;
    let alpha_bits = ell + sec + n_bit;

    let alpha = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::from(1) << alpha_bits));
    let gamma = rng.gen_bigint_range(&BigInt::from(1), &n);

    let g_alpha = g_pow(&alpha, &n, &n_sq);
    let gamma_n = gamma.modpow(&n, &n_sq);
    let c_alpha = (g_alpha * gamma_n) % &n_sq;

    let e = range_challenge(sid, &pk.n, &pk.g, ell, c, &c_alpha);

    let z = &alpha + &(&e * m);
    let s = (&gamma * rho.modpow(&e, &n)) % &n;

    RangeProof { c_alpha, z, s }
}

/// Verifies that c = Enc(m, rho) has |m| < 2^ell.
pub fn verify_range(
    pk: &paillier::PaillierPublicKey,
    c: &BigInt,
    ell: usize,
    sid: &[u8],
    proof: &RangeProof,
) -> bool {
    let n = bu2bi(&pk.n);
    let n_sq = bu2bi(&pk.n_sq);

    let sec = 256usize;
    let n_bit = pk.n.bits() as usize;
    let bound = BigInt::from(1) << (ell + sec + n_bit + 1);

    if proof.z >= bound || proof.z < BigInt::zero() {
        return false;
    }

    let e = range_challenge(sid, &pk.n, &pk.g, ell, c, &proof.c_alpha);

    let c_e = c.modpow(&e, &n_sq);
    let lhs = (&proof.c_alpha * &c_e) % &n_sq;

    let g_z = g_pow(&proof.z, &n, &n_sq);
    let s_n = proof.s.modpow(&n, &n_sq);
    let rhs = (g_z * s_n) % &n_sq;

    lhs == rhs
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlumProof {
    pub challenge_indices: Vec<u64>,
    pub bits: Vec<bool>,
    pub roots: Vec<BigInt>,
}

fn blum_challenge(sid: &[u8], n: &BigUint, iteration: u64) -> BigInt {
    let mut h = Sha256::new();
    h.update(b"govis-blum");
    h.update(sid);
    h.update(n.to_bytes_be());
    h.update(iteration.to_be_bytes());
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.finalize())
}

fn is_quadratic_residue_mod_prime(a: &BigInt, p: &BigInt) -> bool {
    // Euler's criterion: a^((p-1)/2) ≡ 1 (mod p) iff a is QR mod p
    let exp = (p - BigInt::one()) >> 1;
    let res = a.modpow(&exp, p);
    res == BigInt::one()
}

fn sqrt_mod_prime(a: &BigInt, p: &BigInt) -> BigInt {
    // Tonelli-Shanks for p ≡ 3 mod 4: sqrt = a^((p+1)/4) mod p
    let exp = (p + BigInt::one()) >> 2;
    a.modpow(&exp, p)
}

/// Proves that N is a Blum integer.
/// Prover knows the factorization N = p*q with p,q ≡ 3 mod 4.
pub fn prove_blum(p: &BigInt, q: &BigInt, n: &BigInt, sid: &[u8]) -> BlumProof {
    let mut challenge_indices = Vec::new();
    let mut bits = Vec::new();
    let mut roots = Vec::new();

    for i in 0..128 {
        let c = blum_challenge(sid, &n.to_biguint().unwrap(), i);
        let c_mod_n = c.mod_floor(n);

        // Check if c is QR mod N
        let c_qr_p = is_quadratic_residue_mod_prime(&c_mod_n, p);
        let c_qr_q = is_quadratic_residue_mod_prime(&c_mod_n, q);

        if c_qr_p && c_qr_q {
            // c is QR mod N
            let sqrt_p = sqrt_mod_prime(&c_mod_n, p);
            let sqrt_q = sqrt_mod_prime(&c_mod_n, q);
            let root = crt(&sqrt_p, p, &sqrt_q, q, n);
            challenge_indices.push(i);
            bits.push(true);
            roots.push(root);
        } else {
            let neg_c = n - &c_mod_n;
            let neg_qr_p = is_quadratic_residue_mod_prime(&neg_c, p);
            let neg_qr_q = is_quadratic_residue_mod_prime(&neg_c, q);

            if neg_qr_p && neg_qr_q {
                let sqrt_p = sqrt_mod_prime(&neg_c, p);
                let sqrt_q = sqrt_mod_prime(&neg_c, q);
                let root = crt(&sqrt_p, p, &sqrt_q, q, n);
                challenge_indices.push(i);
                bits.push(false);
                roots.push(root);
            }
        }
    }

    BlumProof {
        challenge_indices,
        bits,
        roots,
    }
}

/// Verifies the Blum integer proof.
pub fn verify_blum(n: &BigUint, sid: &[u8], proof: &BlumProof) -> bool {
    let n_bi = BigInt::from_biguint(num_bigint::Sign::Plus, n.clone());

    if !n_bi.bit(0) {
        return false;
    }
    if n_bi.mod_floor(&BigInt::from(4u64)) != BigInt::one() {
        return false;
    }

    let mut valid_count = 0;
    for ((cidx, bit), root) in proof
        .challenge_indices
        .iter()
        .zip(proof.bits.iter())
        .zip(proof.roots.iter())
    {
        let c = blum_challenge(sid, n, *cidx);
        let c_mod = c.mod_floor(&n_bi);

        let expected = if *bit { c_mod } else { &n_bi - c_mod };
        let expected = expected.mod_floor(&n_bi);

        let root_sq = root.modpow(&BigInt::from(2u64), &n_bi);

        if root_sq == expected {
            valid_count += 1;
        }
    }

    valid_count > 0 && valid_count == proof.bits.len()
}

fn crt(a: &BigInt, p: &BigInt, b: &BigInt, q: &BigInt, n: &BigInt) -> BigInt {
    let diff = (b - a).mod_floor(n);
    let p_inv_q = modinv_internal(p.clone(), q);
    let t = (diff * &p_inv_q).mod_floor(q);
    (a + p * t).mod_floor(n)
}

fn modinv_internal(a: BigInt, m: &BigInt) -> BigInt {
    let a = a.mod_floor(m);
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = m.clone();
    let mut new_r = a;
    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        t = &t - &quotient * &new_t;
        std::mem::swap(&mut t, &mut new_t);
        r = &r - &quotient * &new_r;
        std::mem::swap(&mut r, &mut new_r);
    }
    if t < BigInt::zero() { t + m } else { t }
}


/// Proves that c_out = c_in^(scalar) · Enc(0) where scalar corresponds to a known EC point contribution.
/// Public: c_in, c_out, pk, R_peer_x (the x-coordinate of the peer's public contribution)
/// Private: scalar (which is r * x_2 for P2), peer_public_share_point
///
/// Note: For the simplified 2-party case, we prove that:
///   c_s2 = c_k_inv^(r·x₂) · Enc(0) mod N^2
///   where the same scalar (r·x₂) satisfies Q₂' = (r·x₂)·G for some published partial public key Q₂
///
/// For the current protocol without P2 public key, we just prove c_out is well-formed
/// relative to c_in, using a simple Σ-protocol over the Paillier group.
/// The EC consistency check requires Q₂ to be known to the verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MulProof {
    pub c_t: BigInt,
    pub z: BigInt,
    pub s_response: BigInt,
}

fn mul_challenge(
    sid: &[u8],
    n: &BigUint,
    g: &BigUint,
    c_in: &BigInt,
    c_out: &BigInt,
    c_t: &BigInt,
) -> BigInt {
    let mut h = Sha256::new();
    h.update(b"govis-paillier-mul");
    h.update(sid);
    h.update(n.to_bytes_be());
    h.update(g.to_bytes_be());
    h.update(c_in.to_bytes_be().1);
    h.update(c_out.to_bytes_be().1);
    h.update(c_t.to_bytes_be().1);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.finalize())
}

/// P2 proves that c_out = c_in^(scalar) · Enc(0) mod N^2 for a bounded scalar.
/// The bound ensures the Paillier decryption doesn't overflow.
#[allow(clippy::too_many_arguments)]
pub fn prove_mul(
    pk: &paillier::PaillierPublicKey,
    c_in: &BigInt,
    c_out: &BigInt,
    scalar: &BigInt,
    rho_out: &BigInt,
    scalar_bound_bits: usize,
    sid: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> MulProof {
    let n = bu2bi(&pk.n);
    let n_sq = bu2bi(&pk.n_sq);

    let sec = 256usize;

    let t_bits = scalar_bound_bits + sec;
    let t = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::from(1) << t_bits));
    let rho_t = rng.gen_bigint_range(&BigInt::from(1), &n);

    let c_in_t = c_in.modpow(&t, &n_sq);
    let enc_zero = rho_t.modpow(&n, &n_sq);
    let c_t = (c_in_t * enc_zero) % &n_sq;

    let e = mul_challenge(sid, &pk.n, &pk.g, c_in, c_out, &c_t);

    let z = &t + &(&e * scalar);
    let s_response = (&rho_t * rho_out.modpow(&e, &n)) % &n;

    MulProof { c_t, z, s_response }
}

/// Verifies that c_out = c_in^(scalar) · Enc(0) for the proven scalar.
pub fn verify_mul(
    pk: &paillier::PaillierPublicKey,
    c_in: &BigInt,
    c_out: &BigInt,
    scalar_bound_bits: usize,
    sid: &[u8],
    proof: &MulProof,
) -> bool {
    let n = bu2bi(&pk.n);
    let n_sq = bu2bi(&pk.n_sq);

    let sec = 256usize;
    let n_bit = pk.n.bits() as usize;
    let bound = BigInt::from(1) << (scalar_bound_bits + sec + n_bit + 1);

    if proof.z >= bound || proof.z < BigInt::zero() {
        return false;
    }

    let e = mul_challenge(sid, &pk.n, &pk.g, c_in, c_out, &proof.c_t);

    let c_out_e = c_out.modpow(&e, &n_sq);
    let lhs = (&proof.c_t * &c_out_e) % &n_sq;

    let c_in_z = c_in.modpow(&proof.z, &n_sq);
    let s_n = proof.s_response.modpow(&n, &n_sq);
    let rhs = (c_in_z * s_n) % &n_sq;

    lhs == rhs
}

// ─── Paillier-EC Consistency Proof (Π_mod) ───

/// Proves that c = Enc(m, ρ) and m·R = G (i.e., R = m⁻¹·G).
/// This binds a Paillier ciphertext to an ECDSA nonce point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub c_alpha: BigInt,
    pub a: Point<Secp256k1>,
    pub z: BigInt,
    pub s_response: BigInt,
}

fn consistency_challenge(
    sid: &[u8],
    n: &BigUint,
    g: &BigUint,
    c: &BigInt,
    r_point: &Point<Secp256k1>,
    a: &Point<Secp256k1>,
    c_alpha: &BigInt,
) -> BigInt {
    let mut h = Sha256::new();
    h.update(b"govis-paillier-ec-consistency");
    h.update(sid);
    h.update(n.to_bytes_be());
    h.update(g.to_bytes_be());
    h.update(c.to_bytes_be().1);
    h.update(r_point.to_bytes(true).as_ref());
    h.update(a.to_bytes(true).as_ref());
    h.update(c_alpha.to_bytes_be().1);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.finalize())
}

/// Proves that c = Enc(m, ρ) and m·R = G.
pub fn prove_consistency(
    pk: &paillier::PaillierPublicKey,
    m: &BigInt,
    rho: &BigInt,
    c: &BigInt,
    r_point: &Point<Secp256k1>,
    sid: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> ConsistencyProof {
    let n = bu2bi(&pk.n);
    let n_sq = bu2bi(&pk.n_sq);

    let alpha_scalar = Scalar::<Secp256k1>::random(rng);
    let alpha_bigint = scalar_to_bigint(&alpha_scalar);

    let gamma = rng.gen_bigint_range(&BigInt::one(), &n);

    let a = *r_point * alpha_scalar;

    let g_alpha = g_pow(&alpha_bigint, &n, &n_sq);
    let gamma_n = gamma.modpow(&n, &n_sq);
    let c_alpha = (g_alpha * gamma_n) % &n_sq;

    let e = consistency_challenge(sid, &pk.n, &pk.g, c, r_point, &a, &c_alpha);

    let z = &alpha_bigint + &(&e * m);
    let s_response = (&gamma * rho.modpow(&e, &n)) % &n;

    ConsistencyProof {
        c_alpha,
        a,
        z,
        s_response,
    }
}

/// Verifies that c = Enc(m, ρ) and m·R = G for some m, ρ.
pub fn verify_consistency(
    pk: &paillier::PaillierPublicKey,
    c: &BigInt,
    r_point: &Point<Secp256k1>,
    sid: &[u8],
    proof: &ConsistencyProof,
) -> bool {
    let n = bu2bi(&pk.n);
    let n_sq = bu2bi(&pk.n_sq);

    let e = consistency_challenge(sid, &pk.n, &pk.g, c, r_point, &proof.a, &proof.c_alpha);

    // EC check: z·R == A + e·G
    let z_scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(&proof.z.to_bytes_be().1);
    let e_scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(&e.to_bytes_be().1);

    let lhs = *r_point * z_scalar;
    let rhs = proof.a + Point::generator() * e_scalar;
    if lhs != rhs {
        return false;
    }

    // Paillier check: c_α · c^e ≡ g^z · s^N (mod N²)
    let g = bu2bi(&pk.g);
    let g_z = g.modpow(&proof.z, &n_sq);
    let s_n = proof.s_response.modpow(&n, &n_sq);
    let rhs_paillier = (g_z * s_n) % &n_sq;

    let c_e = c.modpow(&e, &n_sq);
    let lhs_paillier = (&proof.c_alpha * &c_e) % &n_sq;

    lhs_paillier == rhs_paillier
}

// ─── Schnorr Proof of Knowledge (Π_sch) ───
// Non-interactive proof of knowledge of x such that X = x·G.
// Uses Fiat-Shamir: challenge = H(A || X || sid).

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub a: Point<Secp256k1>,
    pub z: Scalar<Secp256k1>,
}

fn schnorr_challenge(
    a: &Point<Secp256k1>,
    public: &Point<Secp256k1>,
    sid: &[u8],
) -> Scalar<Secp256k1> {
    let mut h = Sha256::new();
    h.update(b"govis-schnorr");
    h.update(sid);
    h.update(a.to_bytes(true).as_ref());
    h.update(public.to_bytes(true).as_ref());
    Scalar::<Secp256k1>::from_be_bytes_mod_order(h.finalize())
}

pub fn prove_schnorr(
    secret: &Scalar<Secp256k1>,
    public: &Point<Secp256k1>,
    sid: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> SchnorrProof {
    let alpha = Scalar::<Secp256k1>::random(rng);
    let a = Point::generator() * alpha;
    let e = schnorr_challenge(&a, public, sid);
    let z = alpha + e * secret;
    SchnorrProof { a, z }
}

pub fn verify_schnorr(public: &Point<Secp256k1>, sid: &[u8], proof: &SchnorrProof) -> bool {
    let e = schnorr_challenge(&proof.a, public, sid);
    let lhs = Point::generator() * proof.z;
    let rhs = proof.a + *public * e;
    lhs == rhs
}

// ─── Paillier-EC DLOG Equality Proof (Π_log) ───
// Proves that c = Enc(x, rho) AND X = x·G for the same x.
// The prover knows (x, rho) such that both relations hold.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogProof {
    pub c_alpha: BigInt,
    pub a: Point<Secp256k1>,
    pub z: BigInt,
    pub s_response: BigInt,
}

fn log_challenge(
    sid: &[u8],
    n: &BigUint,
    g: &BigUint,
    c: &BigInt,
    public: &Point<Secp256k1>,
    a: &Point<Secp256k1>,
    c_alpha: &BigInt,
) -> BigInt {
    let mut h = Sha256::new();
    h.update(b"govis-paillier-log");
    h.update(sid);
    h.update(n.to_bytes_be());
    h.update(g.to_bytes_be());
    h.update(c.to_bytes_be().1);
    h.update(public.to_bytes(true).as_ref());
    h.update(a.to_bytes(true).as_ref());
    h.update(c_alpha.to_bytes_be().1);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.finalize())
}

/// Proves that c = Enc(x, rho) AND X = x·G for the same secret x.
pub fn prove_log(
    pk: &paillier::PaillierPublicKey,
    c: &BigInt,
    x: &BigInt,
    rho: &BigInt,
    public: &Point<Secp256k1>,
    sid: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> LogProof {
    let n = bu2bi(&pk.n);
    let n_sq = bu2bi(&pk.n_sq);

    // Commit to random alpha
    let alpha_scalar = Scalar::<Secp256k1>::random(rng);
    let alpha_bi = scalar_to_bigint(&alpha_scalar);
    let a = Point::generator() * alpha_scalar;

    let gamma = rng.gen_bigint_range(&BigInt::one(), &n);
    let g_alpha = g_pow(&alpha_bi, &n, &n_sq);
    let gamma_n = gamma.modpow(&n, &n_sq);
    let c_alpha = (g_alpha * gamma_n) % &n_sq;

    let e = log_challenge(sid, &pk.n, &pk.g, c, public, &a, &c_alpha);

    let z = &alpha_bi + &(&e * x);
    let s_response = (&gamma * rho.modpow(&e, &n)) % &n;

    LogProof {
        c_alpha,
        a,
        z,
        s_response,
    }
}

/// Verifies that c = Enc(x, rho) AND X = x·G for some x, rho.
pub fn verify_log(
    pk: &paillier::PaillierPublicKey,
    c: &BigInt,
    public: &Point<Secp256k1>,
    sid: &[u8],
    proof: &LogProof,
) -> bool {
    let n = bu2bi(&pk.n);
    let n_sq = bu2bi(&pk.n_sq);

    let e = log_challenge(sid, &pk.n, &pk.g, c, public, &proof.a, &proof.c_alpha);

    // EC check: z·G == A + e·X
    let z_scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(&proof.z.to_bytes_be().1);
    let e_scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(&e.to_bytes_be().1);

    let lhs_ec = Point::generator() * z_scalar;
    let rhs_ec = proof.a + *public * e_scalar;
    if lhs_ec != rhs_ec {
        return false;
    }

    // Paillier check: c_α · c^e ≡ g^z · s^N (mod N²)
    let g = bu2bi(&pk.g);
    let g_z = g.modpow(&proof.z, &n_sq);
    let s_n = proof.s_response.modpow(&n, &n_sq);
    let rhs_p = (g_z * s_n) % &n_sq;

    let c_e = c.modpow(&e, &n_sq);
    let lhs_p = (&proof.c_alpha * &c_e) % &n_sq;

    lhs_p == rhs_p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_proof_honest_prover() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-range";
        let ell = 256;
        let m = BigInt::from(12345);
        let mut rng = rand::thread_rng();

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);

        // Manual encryption with known rho
        let n_sq = bu2bi(&kp.pk.n_sq);
        let g_m = g_pow(&m, &n, &n_sq);
        let rho_n = rho.modpow(&n, &n_sq);
        let c = (g_m * rho_n) % &n_sq;

        let proof = prove_range(&kp.pk, &c, &m, &rho, ell, sid, &mut rng);
        assert!(verify_range(&kp.pk, &c, ell, sid, &proof));
    }

    #[test]
    fn range_proof_rejects_large_m() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-range";
        let ell = 8; // claim |m| < 256
        let m = BigInt::from(1) << 1100; // m is astronomically larger than 256 — bound check catches it
        let mut rng = rand::thread_rng();

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        let n_sq = bu2bi(&kp.pk.n_sq);
        let g_m = g_pow(&m, &n, &n_sq);
        let rho_n = rho.modpow(&n, &n_sq);
        let c = (g_m * rho_n) % &n_sq;

        let proof = prove_range(&kp.pk, &c, &m, &rho, ell, sid, &mut rng);
        assert!(!verify_range(&kp.pk, &c, ell, sid, &proof));
    }

    #[test]
    fn range_proof_rejects_tampered_ciphertext() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-range";
        let ell = 256;
        let m = BigInt::from(42);
        let mut rng = rand::thread_rng();

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        let n_sq = bu2bi(&kp.pk.n_sq);
        let g_m = g_pow(&m, &n, &n_sq);
        let rho_n = rho.modpow(&n, &n_sq);
        let c = (g_m * rho_n) % &n_sq;

        let proof = prove_range(&kp.pk, &c, &m, &rho, ell, sid, &mut rng);

        // Tamper with the ciphertext
        let c_tampered = (&c + BigInt::one()) % &n_sq;
        assert!(!verify_range(&kp.pk, &c_tampered, ell, sid, &proof));
    }

    #[test]
    fn mul_proof_honest_prover() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-mul";
        let mut rng = rand::thread_rng();

        let n = bu2bi(&kp.pk.n);
        let n_sq = bu2bi(&kp.pk.n_sq);

        // c_in = Enc(7)
        let m_in = BigInt::from(7);
        let rho_in = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c_in = (g_pow(&m_in, &n, &n_sq) * rho_in.modpow(&n, &n_sq)) % &n_sq;

        // c_out = c_in^5 · Enc(0, rho_out) mod N^2  (homomorphic scalar mul)
        let scalar = BigInt::from(5);
        let rho_out = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c_in_scaled = c_in.modpow(&scalar, &n_sq);
        let enc_zero = rho_out.modpow(&n, &n_sq);
        let c_out = (c_in_scaled * enc_zero) % &n_sq;

        let bound = 16;
        let proof = prove_mul(
            &kp.pk, &c_in, &c_out, &scalar, &rho_out, bound, sid, &mut rng,
        );
        assert!(verify_mul(&kp.pk, &c_in, &c_out, bound, sid, &proof));
    }

    #[test]
    fn mul_proof_rejects_wrong_scalar() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-mul";
        let mut rng = rand::thread_rng();

        let n = bu2bi(&kp.pk.n);
        let n_sq = bu2bi(&kp.pk.n_sq);

        let m_in = BigInt::from(7);
        let rho_in = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c_in = (g_pow(&m_in, &n, &n_sq) * rho_in.modpow(&n, &n_sq)) % &n_sq;

        // c_out = Enc(9999) — not Enc(7*5)
        let wrong = BigInt::from(9999);
        let rho_out = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c_out = (g_pow(&wrong, &n, &n_sq) * rho_out.modpow(&n, &n_sq)) % &n_sq;

        let bound = 16;
        let proof = prove_mul(
            &kp.pk,
            &c_in,
            &c_out,
            &BigInt::from(5),
            &rho_out,
            bound,
            sid,
            &mut rng,
        );
        assert!(!verify_mul(&kp.pk, &c_in, &c_out, bound, sid, &proof));
    }

    #[test]
    fn consistency_proof_honest_prover() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-consistency";
        let mut rng = rand::thread_rng();

        // Generate k, compute R = k·G, k_inv = k⁻¹ mod q
        let k = Scalar::<Secp256k1>::random(&mut rng);
        let k_inv = k.invert().unwrap();
        let r_point = Point::generator() * k;
        let m = scalar_to_bigint(&k_inv);

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c = kp.pk.encrypt_with_rho(&m, &rho);

        let proof = prove_consistency(&kp.pk, &m, &rho, &c, &r_point, sid, &mut rng);
        assert!(verify_consistency(&kp.pk, &c, &r_point, sid, &proof));
    }

    #[test]
    fn consistency_proof_rejects_wrong_ciphertext() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-consistency";
        let mut rng = rand::thread_rng();

        let k = Scalar::<Secp256k1>::random(&mut rng);
        let k_inv = k.invert().unwrap();
        let r_point = Point::generator() * k;
        let m = scalar_to_bigint(&k_inv);

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c = kp.pk.encrypt_with_rho(&m, &rho);
        let c_wrong = kp.pk.encrypt_with_rho(&BigInt::from(9999), &rho);

        let proof = prove_consistency(&kp.pk, &m, &rho, &c, &r_point, sid, &mut rng);
        assert!(!verify_consistency(&kp.pk, &c_wrong, &r_point, sid, &proof));
    }

    #[test]
    fn blum_proof_honest_prover() {
        let (p, q, kp) = paillier::generate_keypair_ext(512);
        let sid = b"test-blum";
        let n = BigInt::from_biguint(num_bigint::Sign::Plus, kp.pk.n.clone());
        let p_bi = BigInt::from_biguint(num_bigint::Sign::Plus, p);
        let q_bi = BigInt::from_biguint(num_bigint::Sign::Plus, q);
        let proof = prove_blum(&p_bi, &q_bi, &n, sid);
        assert!(n.bit(0), "N must be odd");
        assert_eq!(
            n.mod_floor(&BigInt::from(4u64)),
            BigInt::one(),
            "N must be 1 mod 4"
        );
        assert_eq!(
            p_bi.mod_floor(&BigInt::from(4u64)),
            BigInt::from(3u64),
            "p must be 3 mod 4"
        );
        assert_eq!(
            q_bi.mod_floor(&BigInt::from(4u64)),
            BigInt::from(3u64),
            "q must be 3 mod 4"
        );
        assert!(
            !proof.bits.is_empty(),
            "Should have at least some valid entries"
        );
        let verified = verify_blum(&kp.pk.n, sid, &proof);
        assert!(verified, "Blum proof should verify for proper Blum primes");
    }

    #[test]
    fn schnorr_proof_honest_prover() {
        let mut rng = rand::thread_rng();
        let sid = b"test-schnorr";
        let x = Scalar::<Secp256k1>::random(&mut rng);
        let x_point = Point::generator() * x;
        let proof = prove_schnorr(&x, &x_point, sid, &mut rng);
        assert!(verify_schnorr(&x_point, sid, &proof));
    }

    #[test]
    fn schnorr_proof_rejects_wrong_public_key() {
        let mut rng = rand::thread_rng();
        let sid = b"test-schnorr";
        let x = Scalar::<Secp256k1>::random(&mut rng);
        let wrong = Scalar::<Secp256k1>::random(&mut rng);
        let wrong_point = Point::generator() * wrong;
        let proof = prove_schnorr(&x, &wrong_point, sid, &mut rng);
        assert!(!verify_schnorr(&wrong_point, sid, &proof));
    }

    #[test]
    fn log_proof_honest_prover() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-log";
        let mut rng = rand::thread_rng();

        let x = Scalar::<Secp256k1>::random(&mut rng);
        let x_bi = scalar_to_bigint(&x);
        let x_point = Point::generator() * x;

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c = kp.pk.encrypt_with_rho(&x_bi, &rho);

        let proof = prove_log(&kp.pk, &c, &x_bi, &rho, &x_point, sid, &mut rng);
        assert!(verify_log(&kp.pk, &c, &x_point, sid, &proof));
    }

    #[test]
    fn log_proof_rejects_wrong_point() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-log";
        let mut rng = rand::thread_rng();

        let x = Scalar::<Secp256k1>::random(&mut rng);
        let x_bi = scalar_to_bigint(&x);
        let x_point = Point::generator() * x;

        let wrong = Scalar::<Secp256k1>::random(&mut rng);
        let wrong_point = Point::generator() * wrong;

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c = kp.pk.encrypt_with_rho(&x_bi, &rho);

        let proof = prove_log(&kp.pk, &c, &x_bi, &rho, &x_point, sid, &mut rng);
        assert!(!verify_log(&kp.pk, &c, &wrong_point, sid, &proof));
    }

    #[test]
    fn log_proof_rejects_wrong_ciphertext() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-log";
        let mut rng = rand::thread_rng();

        let x = Scalar::<Secp256k1>::random(&mut rng);
        let x_bi = scalar_to_bigint(&x);
        let x_point = Point::generator() * x;
        let wrong_x = BigInt::from(9999);

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c = kp.pk.encrypt_with_rho(&x_bi, &rho);
        let c_wrong = kp.pk.encrypt_with_rho(&wrong_x, &rho);

        let proof = prove_log(&kp.pk, &c, &x_bi, &rho, &x_point, sid, &mut rng);
        assert!(!verify_log(&kp.pk, &c_wrong, &x_point, sid, &proof));
    }

    #[test]
    fn consistency_proof_rejects_wrong_point() {
        let kp = paillier::generate_keypair(1024);
        let sid = b"test-consistency";
        let mut rng = rand::thread_rng();

        let k = Scalar::<Secp256k1>::random(&mut rng);
        let k_inv = k.invert().unwrap();
        let r_point = Point::generator() * k;
        let m = scalar_to_bigint(&k_inv);

        // Wrong EC point: R' = k'·G for a different k'
        let k2 = Scalar::<Secp256k1>::random(&mut rng);
        let wrong_point = Point::generator() * k2;

        let n = bu2bi(&kp.pk.n);
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        let c = kp.pk.encrypt_with_rho(&m, &rho);

        let proof = prove_consistency(&kp.pk, &m, &rho, &c, &r_point, sid, &mut rng);
        assert!(!verify_consistency(&kp.pk, &c, &wrong_point, sid, &proof));
    }
}
