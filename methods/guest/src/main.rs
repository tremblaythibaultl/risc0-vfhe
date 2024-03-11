#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
// #![no_std]  // std support is experimental

use risc0_zkvm::guest::env;
use ttfhe::{ggsw::BootstrappingKey, glwe::GlweCiphertext, lwe::LweCiphertext};
risc0_zkvm::guest::entry!(main);

pub fn main() {
    let start = env::cycle_count();
    // bincode can serialize `bsk` into a blob that weighs 39.9MB on disk.
    // This `env::read()` call doesn't seem to stop - memory is allocated until the process goes OOM with risc0 v0.17.0.
    let (c, bsk): (LweCiphertext, BootstrappingKey) = env::read();
    
    let after_load = env::cycle_count();

    let lut = GlweCiphertext::trivial_encrypt_lut_poly();

    // `blind_rotate` is a quite heavy computation that takes ~2s to perform on a M2 MBP.
    // Maybe this is why the process is running OOM?
    let blind_rotated_lut = lut.blind_rotate(c, &bsk);

    let after_br = env::cycle_count();

    let res_ct = blind_rotated_lut.sample_extract();

    let after_se = env::cycle_count();

    env::commit(&res_ct);

    let end = env::cycle_count();

    eprintln!(
        "start: {}\nafter load (before br): {}\nafter br: {}\nafter se: {}\nend: {}",
        start, after_load, after_br, after_se, end
    );
}
