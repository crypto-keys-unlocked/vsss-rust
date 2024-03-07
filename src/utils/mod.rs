//! The module for cryptographic operations, including polynomial generation, evaluation,
//! prime number generation, hashing, modular arithmetic, and Lagrange interpolation.
extern crate num_bigint;
extern crate num_traits;
extern crate rand;

use num_bigint::{BigUint, BigInt, RandBigInt, ToBigInt};
use num_traits::{One,Zero};
use rand::thread_rng;
use num_prime::RandPrime;
use num_prime::PrimalityTestConfig;
use sha2::{Sha256, Digest};


/// Represents a polynomial with coefficients in `BigUint`.
/// This struct is used for operations such as Shamir's Secret Sharing.
pub struct Polynomial {
    /// The coefficients of the polynomial.
    pub coefficients: Vec<BigUint>,
}

impl Polynomial {
    /// Creates a new polynomial with random coefficients.
    /// 
    /// # Arguments
    ///
    /// * `degree` - The degree of the polynomial.
    /// * `max_bit_size` - The maximum bit size for the random coefficients.
    ///
    /// # Returns
    ///
    /// A `Polynomial` instance with randomly generated coefficients.

    pub fn new(degree: usize, max_bit_size: usize) -> Self {
        let mut rng = thread_rng();
        let mut coefficients = Vec::with_capacity(degree + 1);

        let n = BigUint::one() << max_bit_size;

        for _ in 0..=degree {
            let coef = rng.gen_biguint_range(&BigUint::one(), &n);
            coefficients.push(coef);
        }

        Polynomial { coefficients }
    }
    /// Evaluates the polynomial at a given point `x`.
    ///
    /// # Arguments
    ///
    /// * `x` - The point at which to evaluate the polynomial.
    ///
    /// # Returns
    ///
    /// The value of the polynomial at point `x`.
    pub fn evaluate(&self, x: &BigUint) -> BigUint {
        let mut result = BigUint::zero();
        let mut x_pow = BigUint::one();

        for coef in &self.coefficients {
            result += coef * &x_pow;
            x_pow *= x;
        }

        result
    }

    /// Returns a string representation of the polynomial.
    pub fn to_string(&self) -> String {
        self.coefficients.iter().enumerate().map(|(index, coef)| {
            match index {
                0 => format!("{}", coef),
                1 => format!("{}x", coef),
                _ => format!("{}x^{}", coef, index),
            }
        }).collect::<Vec<String>>().join(" + ")
    }
}

/// Generates a random `BigUint` number within the range `[1, modulus)`.
///
/// This function creates a random number that is greater than or equal to `1` and less than
/// the specified `modulus`. It uses the thread-local random number generator to ensure unpredictability
/// and suitability for cryptographic applications where secure random number generation is crucial.
///
/// # Parameters
///
/// * `modulus`: A reference to a `BigUint` that specifies the upper bound of the random number generation.
///   The generated number will be in the range `[1, modulus)`, meaning it includes `1` but excludes `modulus`.
///
/// # Returns
///
/// Returns a `BigUint` representing the randomly generated number within the specified range.
///

pub fn gen_rand(modulus: &BigUint) -> BigUint{
    let mut rng = thread_rng();
    rng.gen_biguint_range(&BigUint::one(), modulus)
}


/// Generates a prime number of a specified bit size.
///
/// # Arguments
///
/// * `bit_size` - The bit size of the prime number to generate.
///
/// # Returns
///
/// A `BigUint` representing the generated prime number.
pub fn generate_prime(bit_size: usize) -> BigUint {
    let mut rng = thread_rng();
    let config = PrimalityTestConfig::default();
    rng.gen_prime(bit_size, Some(config))
}
/// Hashes input data using SHA-256.
///
/// # Arguments
///
/// * `data` - The data to hash.
///
/// # Returns
///
/// A vector of bytes representing the SHA-256 hash of the input data.
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculates the modular exponentiation of a base raised to an exponent modulo a modulus.
///
/// # Arguments
///
/// * `base` - The base of the exponentiation.
/// * `exponent` - The exponent.
/// * `modulus` - The modulus.
///
/// # Returns
///
/// The result of the modular exponentiation as a `BigUint`.
pub fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exponent, modulus)
}

/// Extended Euclidean algorithm for computing the greatest common divisor (gcd) and Bezout coefficients.
/// 
/// # Arguments
/// 
/// * `a` - The first integer.
/// * `b` - The second integer.
/// 
/// # Returns
/// 
/// A tuple `(g, x, y)` representing the gcd of `a` and `b` (`g`), and the Bezout coefficients `x` and `y`.
pub fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b, Zero::zero(), One::one())
    } else {
        let (g, x, y) = egcd(b.clone() % a.clone(), a.clone());
        (g, y - (b / a.clone()) * x.clone(), x)
    }
}

/// Computes the modular multiplicative inverse of `a` modulo `m`.
/// 
/// # Arguments
/// 
/// * `a` - The number to find the inverse for, as a `BigUint`.
/// * `m` - The modulus, as a `BigUint`.
/// 
/// # Returns
/// 
/// An `Option<BigUint>` representing the modular multiplicative inverse of `a` modulo `m` if it exists.
pub fn mod_inv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (g, x, _) = egcd(a.to_bigint().unwrap(), m.to_bigint().unwrap());
    if g == One::one() {
        let x_mod_m = ((x % m.to_bigint().unwrap()) + m.to_bigint().unwrap()) % m.to_bigint().unwrap();
        
        Some(x_mod_m.to_biguint().unwrap())
    } else {
        None
    }
}

/// Performs Lagrange interpolation at zero for a given set of points modulo a given modulus.
///
/// This function calculates the Lagrange polynomial that passes through a given set of points
/// and evaluates it at zero. This is particularly useful in secret sharing schemes,
/// such as Shamir's Secret Sharing, where the secret is reconstructed from shares without revealing
/// the shares themselves.
///
/// # Parameters
///
/// * `points`: A slice of tuples where each tuple contains two `BigUint` values. The first element of each tuple
/// represents the x-coordinate, and the second element represents the y-coordinate of a point on the polynomial.
/// * `modulus`: A reference to a `BigUint` value representing the modulus for the finite field operations.
///
/// # Returns
///
/// Returns `Some(BigUint)` representing the secret (the polynomial evaluated at zero) if the inverse of the
/// denominator exists for all terms in the interpolation formula. Otherwise, returns `None`.
///

pub fn lagrange_interpolation_zero(points: &[(BigUint, BigUint)], modulus: &BigUint) -> Option<BigUint> {
    let mut secret = BigUint::zero();

    for (i, (x_i, y_i)) in points.iter().enumerate() {
        let mut numerator = BigUint::one();
        let mut denominator = BigUint::one();

        for (j, (x_j, _)) in points.iter().enumerate() {
            if i != j {
                let x_diff = (modulus - x_j) % modulus;
                numerator = (numerator * x_diff) % modulus;
                denominator = (denominator * (x_i + modulus - x_j) % modulus) % modulus;
            }
        }
        let inv_denominator = mod_inv(&denominator, modulus)?;
        let term = (y_i * &numerator * inv_denominator) % modulus;        
        secret = (secret + term) % modulus;
    }
    Some(secret)
}


#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;

    // Test for converting polynomial to string representation
    #[test]
    fn test_polynomial_to_string() {
        let poly = Polynomial {
            coefficients: vec![1.to_biguint().unwrap(), 2.to_biguint().unwrap(), 3.to_biguint().unwrap()],
        };

        let expected = "1 + 2x + 3x^2".to_string();
        assert_eq!(poly.to_string(), expected);
    }

    // Test for prime generation
    #[test]
    fn test_prime_generation() {
        let prime = generate_prime(128);
        println!("Prime:{}", prime);
    }

    // Test for hashing data
    #[test]
    fn test_hash_data() {
        let data = b"hello, world";
        let hash = hash_data(data);
        assert_eq!(hash.len(), 32); // SHA-256 produces a 32-byte (256-bit) hash
    }

    // Test for modular exponentiation
    #[test]
    fn test_mod_exp() {
        let base = 2.to_biguint().unwrap();
        let exponent = 10.to_biguint().unwrap();
        let modulus = 1000.to_biguint().unwrap();
        let result = mod_exp(&base, &exponent, &modulus);
        assert_eq!(result, 24.to_biguint().unwrap());
    }

    // Test for modular inverse
    #[test]
    fn test_mod_inv() {
        let a = 3.to_biguint().unwrap();
        let m = 11.to_biguint().unwrap();
        let inv = mod_inv(&a, &m).unwrap();
        assert_eq!(inv, 4.to_biguint().unwrap());
    }

    // Test for Lagrange interpolation at zero
    #[test]
    fn test_lagrange_interpolation_zero() {
        let points = vec![
            (1.to_biguint().unwrap(), 4.to_biguint().unwrap()),
            (2.to_biguint().unwrap(), 7.to_biguint().unwrap()),
            (3.to_biguint().unwrap(), 2.to_biguint().unwrap())
        ];
        let modulus = 11.to_biguint().unwrap();
        let secret = lagrange_interpolation_zero(&points, &modulus).unwrap();
        assert_eq!(secret, 4.to_biguint().unwrap());
    }
}
