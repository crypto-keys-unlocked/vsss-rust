extern crate vsss_rust;
use vsss_rust::shamirs_secret_sharing::{generate_shares as sss_generate_shares, reconstruct_secret as sss_reconstruct_secret};
use vsss_rust::feldman_verifiability::{FeldmanVSSParams, verify_share, reconstruct_secret};
use num_bigint::ToBigUint;
use vsss_rust::utils::generate_prime;

fn main() {
    // Shamir's Secret Sharing (SSS)
    // Secret to be shared
    let secret_sss = 12345.to_biguint().unwrap();
    // Threshold for secret reconstruction
    let threshold_sss = 3;
    // Total number of shares to generate
    let num_shares_sss = 5;
    // Prime modulus for finite field operations
    let modulus_sss = 7919.to_biguint().unwrap();

    // Generate shares for SSS
    let shares_sss = sss_generate_shares(&secret_sss, threshold_sss, num_shares_sss, &modulus_sss);

    // Reconstruct secret for SSS
    let reconstructed_secret_sss = sss_reconstruct_secret(&shares_sss[..threshold_sss], &modulus_sss).unwrap();

    println!("Shamir's Secret Sharing:");
    println!("Original Secret: {}", secret_sss);
    println!("Reconstructed Secret: {}", reconstructed_secret_sss);

    // Feldman's Verifiable Secret Sharing (VSS)
    // Secret to be shared
    let secret = 986743267.to_biguint().unwrap();
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
    println!("Feldman's Verifiable Secret Sharing (VSS):");
    println!("Original Secret: {}", secret);
    println!("Reconstructed Secret: {}", reconstructed_secret);
}
