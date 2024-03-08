//! # Feldman's Verifiable Secret Sharing (VSS) Module
//!
//! This module implements Feldman's Verifiable Secret Sharing scheme, an extension
//! of Shamir's Secret Sharing (SSS) that adds a layer of verifiability to the shared
//! secrets. In Feldman's VSS, commitments to the coefficients of the polynomial used
//! in Shamir's scheme are publicly shared. These commitments enable any party to verify
//! their shares without revealing the secret or the coefficients of the polynomial.
//!
//! The key functionalities include:
//! - Generation of shares based on a secret.
//! - Creation of public commitments to the polynomial's coefficients.
//! - Verification of shares against the public commitments.
//! - Reconstruction of the secret from a subset of shares using Lagrange interpolation.
//!
//! This module requires `Polynomial`, `mod_exp`, `lagrange_interpolation_zero` and potentially other utility functions
//! from the `utils` module for its operations.


use crate::utils::{Polynomial, mod_exp,lagrange_interpolation_zero};
use num_bigint::{BigUint, ToBigUint};
use num_traits::One;

/// Represents the public parameters for the Feldman VSS scheme.
pub struct FeldmanVSSParams {
    pub g: BigUint, // Generator of the group G
    pub q: BigUint, // Prime order of the group G
}

impl FeldmanVSSParams {

    /// Initializes Feldman VSS parameters with a generator and prime order.
    pub fn new(g: BigUint, q: BigUint) -> Self {
        FeldmanVSSParams { g, q }
    }


    /// Generates shares for Shamir's Secret Sharing (SSS) scheme and creates commitments for 
    /// Feldman's Verifiable Secret Sharing (VSS) based on a provided secret, a threshold, 
    /// and the total number of shares. It combines the secret sharing mechanism with a 
    /// verifiable component by publishing commitments to the coefficients of the polynomial
    /// used to generate the shares.
    ///
    /// # Arguments
    ///
    /// * `secret` - A `BigUint` representing the secret to be shared.
    /// * `threshold` - The minimum number of shares required to reconstruct the secret.
    /// * `num_shares` - The total number of shares to be generated.
    ///
    /// # Returns
    ///
    /// A tuple containing two vectors:
    /// - The first vector contains tuples of `BigUint`, each representing a share with an
    ///   index (x-value) and the corresponding share value (y-value).
    /// - The second vector contains `BigUint` commitments to the coefficients of the polynomial,
    ///   enabling the verification of shares without revealing the coefficients themselves.

    pub fn generate_shares(&self, secret: &BigUint, threshold: usize, num_shares: usize) -> (Vec<(BigUint, BigUint)>, Vec<BigUint>) {
        let poly = Polynomial::new_for_shamir(threshold - 1, secret.bits() as usize, secret);
        let mut shares = Vec::with_capacity(num_shares);

        // Generate shares using the polynomial, similar to Shamir's scheme
        for i in 1..=num_shares {
            let x = i.to_biguint().unwrap();
            let y = poly.evaluate(&x) % &self.q; // Ensure the evaluation is done modulo q
            shares.push((x, y));
        }

        // Generate commitments for the polynomial's coefficients for verifiability
        let commitments = self.generate_commitments(&poly);

        (shares, commitments)
    }
    
    /// Generates verifiable commitments to the coefficients of the polynomial used in the secret sharing.
    ///
    /// In Feldman's Verifiable Secret Sharing scheme, these commitments are made public and allow any party
    /// to verify their shares without compromising the security of the secret or needing access to the polynomial's
    /// coefficients directly. Each commitment is calculated using the group's generator `g` raised to the power
    /// of the coefficient, all operations performed modulo `q`, the prime order of the group.
    ///
    /// # Arguments
    ///
    /// * `polynomial` - A reference to the `Polynomial` instance that represents the polynomial used
    ///   to generate shares in the secret sharing scheme. The polynomial's coefficients are used to
    ///   create the commitments.
    ///
    /// # Returns
    ///
    /// A vector of `BigUint` representing the commitments to each coefficient of the polynomial.
    /// These commitments can be publicly shared to enable verification of shares by participants
    /// without revealing the polynomial's coefficients or the shared secret itself.
    ///
    /// Each commitment is of the form `g^coef mod q`, where `g` is the generator of the group,
    /// `coef` is a coefficient of the polynomial, and `q` is the prime order of the group.
    fn generate_commitments(&self, polynomial: &Polynomial) -> Vec<BigUint> {
        polynomial.coefficients.iter().map(|coef| {
            mod_exp(&self.g, coef, &self.q) // Compute g^coef mod q for each coefficient
        }).collect()
    }

}


/// Verifies a share against the public commitments using the Feldman Verifiable Secret Sharing scheme.
/// This function checks if a share is valid by verifying that g^share equals the product of the commitments
/// raised to the power of their respective indices, all operations performed modulo q.
///
/// # Arguments
///
/// * `i` - A `BigUint` representing the index of the share being verified.
/// * `share` - A `BigUint` representing the share value associated with the index `i`.
/// * `commitments` - A slice of `BigUint` representing the public commitments to the polynomial coefficients.
/// * `params` - A reference to the `FeldmanVSSParams` containing the public parameters (g and q) of the scheme.
///
/// # Returns
///
/// `true` if the share is valid according to the verification equation, otherwise `false`.

pub fn verify_share(
    i: &BigUint, // Share index
    share: &BigUint, // Share value
    commitments: &[BigUint], // Public commitments
    params: &FeldmanVSSParams, // VSS parameters
) -> bool {
    // Calculate the left-hand side (LHS) as g^share mod q
    let lhs = mod_exp(&params.g, share, &params.q);

    // Calculate the right-hand side (RHS) as the product of commitments raised to the power of the share index
    let rhs = commitments.iter().enumerate().fold(BigUint::one(), |acc, (j, commitment)| {
        let exponent = i.modpow(&BigUint::from(j), &params.q);
        (acc * mod_exp(commitment, &exponent, &params.q)) % &params.q
    });

    lhs == rhs
}

/// Reconstructs the secret from a set of shares using Lagrange interpolation at zero.
/// This function is a critical part of Shamir's Secret Sharing, enabling the recovery
/// of the secret from a minimum number of shares without revealing the shares themselves.
///
/// # Arguments
///
/// * `shares` - A slice of tuples containing shares, where each tuple consists of an
///   index (x-value) and the corresponding share value (y-value).
/// * `modulus` - A `BigUint` representing the modulus used for the finite field operations,
///   which should be the same as used in share generation.
///
/// # Returns
///
/// An `Option<BigUint>` containing the reconstructed secret if successful, otherwise `None`.

pub fn reconstruct_secret(shares: &[(BigUint, BigUint)], modulus: &BigUint) -> Option<BigUint> {
    lagrange_interpolation_zero(shares, modulus)
}


#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;
    use crate::utils::generate_prime;

    #[test]
    fn test_share_generation_and_verification() {
        let secret = 1234.to_biguint().unwrap();
        let threshold = 3;
        let num_shares = 5;

        let g = 2.to_biguint().unwrap();
        let q = generate_prime(256);

        let params = FeldmanVSSParams::new(g, q);

        let (shares, commitments) = params.generate_shares(&secret, threshold, num_shares);

        for (i, &(ref x, ref y)) in shares.iter().enumerate() {
            assert!(verify_share(x, y, &commitments, &params), "Share {} failed verification", i + 1);
        }

        let reconstructed_secret = reconstruct_secret(&shares[..threshold], &params.q).unwrap();
        assert_eq!(secret, reconstructed_secret, "Reconstructed secret does not match the original secret.");
    }
}
