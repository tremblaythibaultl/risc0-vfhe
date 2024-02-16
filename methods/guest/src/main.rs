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
    let start = env::cycle_count();
    // Reading the three components required to perform one step of the blind rotation (one CMUX)
    let (bsk_i, c_prime, c_prime_rotated): (GgswCiphertext, GlweCiphertext, GlweCiphertext) =
        env::read();

    let after_load = env::cycle_count();

    let res = cmux(&bsk_i, &c_prime, &c_prime_rotated);

    let after_cmux = env::cycle_count();

    env::commit(&res);
    let end = env::cycle_count();

    eprintln!(
        "start: {}\nafter load (before cmux): {}\nafter cmux: {}\nend: {}",
        start, after_load, after_cmux, end
    );
}
