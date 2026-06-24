//! # Govis Library
//! This crate handles threshold cryptography and key refreshes.
//! It is built for speed and security.

pub mod cggmp21;
pub mod core;
pub mod lindell;
pub mod mta;
pub mod paillier;
pub mod paillier_zk;
pub mod tcp_delivery;
pub mod types;

pub use crate::core::*;
pub use crate::lindell::*;
pub use crate::types::*;

#[cfg(test)]
pub(crate) mod test_helpers {
    use rand::rngs::StdRng;
    use rand::{CryptoRng, RngCore, SeedableRng};

    pub struct TestRng(StdRng);

    impl TestRng {
        pub fn new() -> Self {
            Self(StdRng::seed_from_u64(0))
        }

        pub fn fork(&mut self) -> Self {
            Self(StdRng::seed_from_u64(self.0.next_u64()))
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    impl CryptoRng for TestRng {}
}
