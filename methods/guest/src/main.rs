#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
// #![no_std]  // std support is experimental

use include_bytes_aligned::include_bytes_aligned;
use risc0_zkvm::guest::env;
use ttfhe::{
    ggsw::{BootstrappingKey, GgswCiphertext},
    glwe::GlweCiphertext,
    lwe::LweCiphertext,
    LWE_DIM,
};
risc0_zkvm::guest::entry!(main);

pub fn main() {
    let start = env::get_cycle_count();
    // bincode can serialize `bsk` into a blob that weighs 39.9MB on disk.
    // This `env::read()` call doesn't seem to stop - memory is allocated until the process goes OOM with risc0 v0.17.0.
    // let (c, bsk): (LweCiphertext, BootstrappingKey) = env::read();

    static BSK_BYTES: &[u8] = include_bytes_aligned!(8, "../../../data/bsk");
    // static CT_BYTES: &[u8] = include_bytes_aligned!(8, "../../../data/ct");

    let bsk = unsafe { std::mem::transmute::<&u8, &[GgswCiphertext; LWE_DIM]>(&BSK_BYTES[0]) };

    // let ct: LweCiphertext = unsafe { std::mem::transmute::<&u8, LweCiphertext>(&CT_BYTES[0]) };

    let lut = GlweCiphertext::trivial_encrypt_lut_poly();

    // `blind_rotate` is a quite heavy computation that takes ~2s to perform on a M2 MBP.
    // Maybe this is why the process is running OOM?
    let blind_rotated_lut = lut.blind_rotate(c, &bsk.to_vec());

    // let res_ct = blind_rotated_lut.sample_extract();

    // env::commit(&res_ct);

    let end = env::get_cycle_count();
    eprintln!("start: {}, end: {}", start, end);
}
