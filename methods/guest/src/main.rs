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
    let start = env::cycle_count();
    
    let c: LweCiphertext = env::read();

    let after_read = env::cycle_count();

    static BSK_BYTES: &[u8] = include_bytes_aligned!(8, "../../../data/bsk");
    
    let after_include_bytes = env::cycle_count();

    let bsk = unsafe { std::mem::transmute::<&u8, &[GgswCiphertext; LWE_DIM]>(&BSK_BYTES[0]) };

    let after_transmute = env::cycle_count();

    // let ct: LweCiphertext = unsafe { std::mem::transmute::<&u8, LweCiphertext>(&CT_BYTES[0]) };

    let lut = GlweCiphertext::trivial_encrypt_lut_poly();

    let blind_rotated_lut = lut.blind_rotate(c, &bsk.to_vec());

    let res_ct = blind_rotated_lut.sample_extract();

    let after_br = env::cycle_count();


    env::commit(&res_ct);

    let end = env::cycle_count();
    eprintln!("start: {}, after_read: {}, after_include_bytes {}, after_transmute: {}, after_br: {}, end: {}", start, after_read, after_include_bytes, after_transmute, after_br, end);
}
