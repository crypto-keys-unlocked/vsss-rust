use criterion::{criterion_group, criterion_main, Criterion};
use vsss_rust::shamirs_secret_sharing::{generate_shares as sss_generate_shares, reconstruct_secret as sss_reconstruct_secret};
use vsss_rust::feldman_verifiability::{FeldmanVSSParams, verify_share, reconstruct_secret};
use num_bigint::ToBigUint;
use vsss_rust::utils::generate_prime;

fn sss_generation_benchmark(c: &mut Criterion) {
    let secret = 12345.to_biguint().unwrap();
    let threshold = 3;
    let num_shares = 5;
    let modulus = 7919.to_biguint().unwrap();

    c.bench_function("SSS Share Generation", |b| {
        b.iter(|| sss_generate_shares(&secret, threshold, num_shares, &modulus))
    });
}

fn sss_reconstruction_benchmark(c: &mut Criterion) {
    let secret = 12345.to_biguint().unwrap();
    let threshold = 3;
    let num_shares = 5;
    let modulus = 7919.to_biguint().unwrap();
    let shares = sss_generate_shares(&secret, threshold, num_shares, &modulus);

    c.bench_function("SSS Secret Reconstruction", |b| {
        b.iter(|| sss_reconstruct_secret(&shares[..threshold], &modulus))
    });
}

fn vss_generation_benchmark(c: &mut Criterion) {
    let secret = 986743267.to_biguint().unwrap();
    let threshold = 3;
    let num_shares = 5;
    let g = 2.to_biguint().unwrap();
    let q = generate_prime(256);
    let params = FeldmanVSSParams::new(g, q);

    c.bench_function("VSS Share Generation", |b| {
        b.iter(|| params.generate_shares(&secret, threshold, num_shares))
    });
}

fn vss_verification_benchmark(c: &mut Criterion) {
    let secret = 986743267.to_biguint().unwrap();
    let threshold = 3;
    let num_shares = 5;
    let g = 2.to_biguint().unwrap();
    let q = generate_prime(256);
    let params = FeldmanVSSParams::new(g, q);
    let (shares, commitments) = params.generate_shares(&secret, threshold, num_shares);

    c.bench_function("VSS Share Verification", |b| {
        b.iter(|| {
            for (i, &(ref x, ref y)) in shares.iter().enumerate() {
                assert!(verify_share(x, y, &commitments, &params), "Share {} failed verification", i + 1);
            }
        })
    });
}

fn vss_reconstruction_benchmark(c: &mut Criterion) {
    let secret = 986743267.to_biguint().unwrap();
    let threshold = 3;
    let num_shares = 5;
    let g = 2.to_biguint().unwrap();
    let q = generate_prime(256);
    let params = FeldmanVSSParams::new(g, q);
    let (shares, _) = params.generate_shares(&secret, threshold, num_shares);

    c.bench_function("VSS Secret Reconstruction", |b| {
        b.iter(|| reconstruct_secret(&shares[..threshold], &params.q))
    });
}

criterion_group!(
    vss_benches,
    sss_generation_benchmark,
    sss_reconstruction_benchmark,
    vss_generation_benchmark,
    vss_verification_benchmark,
    vss_reconstruction_benchmark
);

criterion_main!(vss_benches);
