//! # Shamir's Secret Sharing (SSS) Module
//!
//! This module implements Shamir's Secret Sharing, a cryptographic algorithm to distribute
//! a secret amongst a group of participants, each of whom is allocated a share of the secret.
//! The unique property of SSS is that the secret can only be reconstructed when a sufficient
//! number of shares (threshold) are combined together; individually, shares do not reveal
//! any information about the secret.
//!
//! The scheme is based on polynomial interpolation over a finite field, ensuring security
//! and mathematical robustness. It has applications in secure key storage, distributed systems,
//! and wherever secret management is critical.
//!
//! ## Key Functionalities
//! - **Share Generation**: Divides a secret into multiple shares, ensuring that only a
//!   specified number of shares can reconstruct the secret.
//! - **Secret Reconstruction**: Combines a sufficient number of shares to reconstruct
//!   the original secret using Lagrange interpolation.
//!
//! ## Usage
//! This module is designed to be used where secure and distributed control over a secret
//! is necessary. It leverages the `Polynomial` and `lagrange_interpolation_zero` functions
//! from the `utils` module for its core operations, aligning with cryptographic best practices.
//!

use num_bigint::{BigUint, ToBigUint};
use crate::utils::Polynomial;
use crate::utils::lagrange_interpolation_zero;

/// Generates shares for Shamir's Secret Sharing scheme.
///
/// # Arguments
///
/// * `secret` - The secret value to be shared.
/// * `threshold` - The threshold value for reconstructing the secret.
/// * `num_shares` - The number of shares to generate.
/// * `modulus` - The modulus for the polynomial operations.
///
/// # Returns
///
/// A vector of tuples representing the generated shares. Each tuple contains the x-coordinate
/// (share index) and the corresponding y-coordinate (share value).
pub fn generate_shares(
    secret: &BigUint,
    threshold: usize,
    num_shares: usize,
    modulus: &BigUint,
) -> Vec<(BigUint, BigUint)> {
    let poly = Polynomial::new_for_shamir(threshold - 1, secret.bits() as usize, secret);
    let mut shares = Vec::with_capacity(num_shares);

    for i in 1..=num_shares {
        let x = i.to_biguint().unwrap();
        let y = poly.evaluate(&x) % modulus;
        shares.push((x, y));
    }

    shares
}

/// Reconstructs the secret from shares using Lagrange interpolation.
///
/// # Arguments
///
/// * `shares` - A slice of tuples representing the shares. Each tuple contains the x-coordinate
///   (share index) and the corresponding y-coordinate (share value).
/// * `modulus` - The modulus used for the finite field operations.
///
/// # Returns
///
/// The reconstructed secret if successful, otherwise None.
pub fn reconstruct_secret(shares: &[(BigUint, BigUint)], modulus: &BigUint) -> Option<BigUint> {
    lagrange_interpolation_zero(shares, modulus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;

    // Test for generating and reconstructing shares
    #[test]
    fn test_generate_and_reconstruct_shares() {
        let secret = 87985.to_biguint().unwrap();
        let threshold = 3;
        let num_shares = 5;
        let modulus = 678879987.to_biguint().unwrap();

        // Generate shares
        let shares = generate_shares(&secret, threshold, num_shares, &modulus);

        // Reconstruct secret
        let reconstructed_secret = reconstruct_secret(&shares[..threshold], &modulus).unwrap();

        // Assert equality
        assert_eq!(secret, reconstructed_secret);
    }
}