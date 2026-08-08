//! Shared data types used by both protocols.

use generic_ec::{Point, SecretScalar, curves::Secp256k1};

/// Feldman VSS output: polynomial commitments and one secret share per party.
pub struct DkgShares {
    pub commitments: Vec<Point<Secp256k1>>,
    pub secret_shares: Vec<SecretScalar<Secp256k1>>,
}

/// Alias for [`DkgShares`]; used for key refresh offsets.
pub type RefreshShares = DkgShares;
