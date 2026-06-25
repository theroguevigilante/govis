use num_bigint::{BigInt, BigUint, RandBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

/// Paillier public key
#[derive(Clone, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    pub n: BigUint,
    pub n_sq: BigUint,
    pub g: BigUint,
}

/// Paillier private key
#[derive(Clone, Serialize, Deserialize)]
pub struct PaillierPrivateKey {
    pub lambda: BigUint,
    pub mu: BigUint,
}

/// Paillier keypair
pub struct PaillierKeypair {
    pub pk: PaillierPublicKey,
    pub sk: PaillierPrivateKey,
}

impl PaillierPublicKey {
    pub fn encrypt(&self, m: &BigInt) -> BigInt {
        let n = BigInt::from_biguint(num_bigint::Sign::Plus, self.n.clone());
        let mut rng = rand::thread_rng();
        let rho = rng.gen_bigint_range(&BigInt::from(1), &n);
        self.encrypt_with_rho(m, &rho)
    }

    /// Encrypt with a caller-provided randomness (needed for ZK proofs).
    pub fn encrypt_with_rho(&self, m: &BigInt, rho: &BigInt) -> BigInt {
        let n = BigInt::from_biguint(num_bigint::Sign::Plus, self.n.clone());
        let n_sq = BigInt::from_biguint(num_bigint::Sign::Plus, self.n_sq.clone());
        let g = BigInt::from_biguint(num_bigint::Sign::Plus, self.g.clone());
        let gm = g.modpow(m, &n_sq);
        let rn = rho.modpow(&n, &n_sq);
        (gm * rn) % n_sq
    }

    pub fn add(&self, c1: &BigInt, c2: &BigInt) -> BigInt {
        let n_sq = BigInt::from_biguint(num_bigint::Sign::Plus, self.n_sq.clone());
        (c1 * c2) % n_sq
    }

    pub fn scalar_mul(&self, c: &BigInt, k: &BigInt) -> BigInt {
        let n_sq = BigInt::from_biguint(num_bigint::Sign::Plus, self.n_sq.clone());
        c.modpow(k, &n_sq)
    }
}

impl PaillierPrivateKey {
    pub fn decrypt(&self, pk: &PaillierPublicKey, c: &BigInt) -> BigInt {
        let n = BigInt::from_biguint(num_bigint::Sign::Plus, pk.n.clone());
        let n_sq = BigInt::from_biguint(num_bigint::Sign::Plus, pk.n_sq.clone());
        let lambda = BigInt::from_biguint(num_bigint::Sign::Plus, self.lambda.clone());
        let mu = BigInt::from_biguint(num_bigint::Sign::Plus, self.mu.clone());
        let c_lambda = c.modpow(&lambda, &n_sq);
        let l = l_function(&c_lambda, &n);
        (l * mu) % n
    }
}

fn l_function(x: &BigInt, n: &BigInt) -> BigInt {
    (x - BigInt::one()) / n
}

fn modinv(a: &BigInt, n: &BigInt) -> BigInt {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = n.clone();
    let mut new_r = a.mod_floor(n);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        t = &t - &quotient * &new_t;
        std::mem::swap(&mut t, &mut new_t);
        r = &r - &quotient * &new_r;
        std::mem::swap(&mut r, &mut new_r);
    }

    if r > BigInt::one() {
        return BigInt::zero();
    }
    if t < BigInt::zero() { t + n } else { t }
}

/// Generates a Paillier keypair with modulus of `bits` size (e.g., 2048).
pub fn generate_keypair(bits: usize) -> PaillierKeypair {
    generate_keypair_ext(bits).2
}

/// Same as `generate_keypair` but also returns the primes p and q.
pub fn generate_keypair_ext(bits: usize) -> (BigUint, BigUint, PaillierKeypair) {
    let half = bits / 2;
    let three = BigUint::from(3u64);
    let four = BigUint::from(4u64);
    loop {
        let p = BigUint::from_bytes_be(&Generator::new_prime(half).to_bytes_be());
        if &p % &four != three {
            continue;
        }
        let q = BigUint::from_bytes_be(&Generator::new_prime(half).to_bytes_be());
        if &q % &four != three {
            continue;
        }
        if p == q {
            continue;
        }
        let n = &p * &q;
        let n_sq = &n * &n;
        let g = &n + BigUint::one();

        let p1 = &p - BigUint::one();
        let q1 = &q - BigUint::one();
        let lambda = lcm(&p1, &q1);

        let n_bigint = BigInt::from_biguint(num_bigint::Sign::Plus, n.clone());
        let n_sq_bigint = BigInt::from_biguint(num_bigint::Sign::Plus, n_sq.clone());
        let lambda_bigint = BigInt::from_biguint(num_bigint::Sign::Plus, lambda.clone());
        let g_bigint = BigInt::from_biguint(num_bigint::Sign::Plus, g.clone());

        let g_lambda = g_bigint.modpow(&lambda_bigint, &n_sq_bigint);
        let l = l_function(&g_lambda, &n_bigint);

        let mu = modinv(&l, &n_bigint);
        if mu == BigInt::zero() {
            continue;
        }

        return (
            p.clone(),
            q.clone(),
            PaillierKeypair {
                pk: PaillierPublicKey { n, n_sq, g },
                sk: PaillierPrivateKey {
                    lambda,
                    mu: mu.to_biguint().unwrap(),
                },
            },
        );
    }
}

fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    let gcd = biguint_gcd(a, b);
    (a * b) / gcd
}

fn biguint_gcd(a: &BigUint, b: &BigUint) -> BigUint {
    if b.is_zero() {
        return a.clone();
    }
    biguint_gcd(b, &(a % b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let kp = generate_keypair(512);
        let m = BigInt::from(42);
        let c = kp.pk.encrypt(&m);
        let d = kp.sk.decrypt(&kp.pk, &c);
        assert_eq!(m, d);
    }

    #[test]
    fn test_homomorphic_add() {
        let kp = generate_keypair(512);
        let m1 = BigInt::from(10);
        let m2 = BigInt::from(20);
        let c1 = kp.pk.encrypt(&m1);
        let c2 = kp.pk.encrypt(&m2);
        let c_sum = kp.pk.add(&c1, &c2);
        let d = kp.sk.decrypt(&kp.pk, &c_sum);
        assert_eq!(d, BigInt::from(30));
    }

    #[test]
    fn test_scalar_mul() {
        let kp = generate_keypair(512);
        let m = BigInt::from(7);
        let s = BigInt::from(5);
        let c = kp.pk.encrypt(&m);
        let c_mul = kp.pk.scalar_mul(&c, &s);
        let d = kp.sk.decrypt(&kp.pk, &c_mul);
        assert_eq!(d, BigInt::from(35));
    }

    #[test]
    fn test_homomorphic_chain() {
        let kp = generate_keypair(512);
        let a = BigInt::from(3);
        let b = BigInt::from(5);
        let c = BigInt::from(7);
        let ca = kp.pk.encrypt(&a);
        let cb = kp.pk.encrypt(&b);
        let cab = kp.pk.add(&ca, &cb);
        let cabc = kp.pk.scalar_mul(&cab, &c);
        let d = kp.sk.decrypt(&kp.pk, &cabc);
        assert_eq!(d, (a + b) * &c);
    }
}
