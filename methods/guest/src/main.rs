#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
// #![no_std]  // std support is experimental

use risc0_zkvm::guest::env;
use ttfhe::{
    ggsw::{cmux, GgswCiphertext},
    glwe::GlweCiphertext,
};
risc0_zkvm::guest::entry!(main);

pub fn main() {
    println!("cycle count: {}", env::get_cycle_count());
    // Reading the three components required to perform one step of the blind rotation (one CMUX)
    let (bsk_i, c_prime, c_prime_rotated): (GgswCiphertext, GlweCiphertext, GlweCiphertext) =
        env::read();

    let res = cmux(&bsk_i, &c_prime, &c_prime_rotated);

    env::commit(&res);
}
