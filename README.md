# VSSS-Rust

![Rust](https://img.shields.io/badge/language-Rust-orange)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/crypto-keys-unlocked/vsss-rust/blob/main/LICENSE)

VSSS-Rust is a Rust library providing implementations of Verifiable Secret Sharing (VSS) schemes. Verifiable Secret Sharing is a cryptographic technique that enables a secret to be divided into shares and distributed among a group of participants in such a way that only specific combinations of shares can reconstruct the secret, while also allowing any participant to verify the validity of their own share.

## Features

- Implementation of various Verifiable Secret Sharing (VSS) schemes in Rust.
- Support for Shamir's Secret Sharing (SSS) and Feldman's Verifiable Secret Sharing (VSS) schemes.
- Generation of secret shares based on user-defined thresholds and total shares.
- Public commitment generation for the verifiability of shares.
- Share verification against public commitments.
- Secret reconstruction from valid shares using Lagrange interpolation.

## Installation

Add the following dependency to your `Cargo.toml` file:

```toml
[dependencies]
vsss-rust = "0.1.0"
```

## Usage

Add `vsss-rust` to your project's dependencies in the `Cargo.toml` file, and then import the necessary modules into your Rust code.

```rust
extern crate vsss_rust;

use vsss_rust::shamirs_secret_sharing::{generate_shares as sss_generate_shares, reconstruct_secret as sss_reconstruct_secret};
use vsss_rust::feldman_verifiability::{FeldmanVSSParams, verify_share, reconstruct_secret};
use num_bigint::ToBigUint;

fn main() {
    // Your code here
}
```

## Example

Check out the `example.rs` file in the repository for a basic example of how to use this library.

## Benchmarks

This library includes benchmarks for performance testing. You can run the benchmarks using Criterion by executing the following command:

```bash
cargo bench
```
The following is a brief summary for one run:

| Benchmark                   | Time (ns) Range                          | Outliers Found (%)       |
|-----------------------------|------------------------------------------|--------------------------|
| SSS Share Generation        | [785.14 ns, 788.13 ns]                   | 1 (1.00%) high mild     |
| SSS Secret Reconstruction   | [2.2811 µs, 2.2898 µs]                   | 1 (1.00%) high mild     |
| VSS Share Generation        | [14.999 µs, 15.004 µs]                   | 11 (11.00%) total        |
|                             |                                          |  - 5 (5.00%) low mild    |
|                             |                                          |  - 1 (1.00%) high mild   |
|                             |                                          |  - 5 (5.00%) high severe |
| VSS Share Verification      | [153.58 µs, 153.98 µs]                   | 20 (20.00%) total        |
|                             |                                          |  - 3 (3.00%) low mild    |
|                             |                                          |  - 11 (11.00%) high mild |
|                             |                                          |  - 6 (6.00%) high severe|
| VSS Secret Reconstruction   | [3.6152 µs, 3.6291 µs]                   | 12 (12.00%) total        |
|                             |                                          |  - 5 (5.00%) high mild   |
|                             |                                          |  - 7 (7.00%) high severe|

## Documentation

For detailed documentation and usage examples, refer to the [API documentation](https://docs.rs/vsss-rust).

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please feel free to open a pull request or submit an issue on the GitHub repository.

## License

This project is licensed under the terms of the MIT license.

## TODO

- Implement the perfectly-secure VSS scheme of Ben-Or, Goldwasser, and Wigderson.
- Implement the Benaloh zero-knowledge-based secure voting scheme.
- Implement a simplified 5-round version of 7BGW-VSS-Sh due to Genarro, Ishai, Kushilevitz, and Rabin.
- Implement a 4-round sharing phase protocol due to Genarro, Ishai, Kushilevitz, and Rabin.
- Implement the 3-round 3GIKR-VSS scheme due to Genarro, Ishai, Kushilevitz, and Rabin.
- Implement the 3-round 3FGGRS-WSS scheme due to Fitzi, Garay, Gollakota, Rangan, and Srinathan.
- Implement the 3-round 3KKK-WSS-Sh protocol due to Katz, Koo, and Kumaresan.