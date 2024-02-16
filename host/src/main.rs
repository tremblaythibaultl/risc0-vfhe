use std::time::Instant;

use methods::{BLIND_ROTATE_ELF, BLIND_ROTATE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use ttfhe::{
    ggsw::{compute_bsk, BootstrappingKey},
    glwe::{keygen, GlweCiphertext},
    lwe::{lwe_keygen, LweCiphertext},
    utils::encode,
};

fn main() {
    let sk1 = lwe_keygen();
    let sk2 = keygen();
    let bsk = compute_bsk(&sk1, &sk2); // list of encryptions under `sk2` of the bits of `sk1`.

    let c = LweCiphertext::encrypt(encode(2), &sk1).modswitch(); // "noisy" ciphertext that will be bootstrapped

    step_by_step_blind_rotation(&c, &bsk)
}

fn step_by_step_blind_rotation(c: &LweCiphertext, bsk: &BootstrappingKey) {
    let mut c_prime = GlweCiphertext::trivial_encrypt_lut_poly();

    c_prime.body = c_prime.body.multiply_by_monomial((2048 - c.body) as usize);

    for i in 0..bsk.len() {
        let now = Instant::now();

        let env = ExecutorEnv::builder()
            .write(&bsk[i])
            .unwrap()
            .write(&c_prime)
            .unwrap()
            .write(&c_prime.rotate(c.mask[i]))
            .unwrap()
            .build()
            .unwrap();

        let prover = default_prover();

        let receipt = prover.prove(env, BLIND_ROTATE_ELF).unwrap();

        receipt.verify(BLIND_ROTATE_ID).unwrap();
        c_prime = receipt.journal.decode().unwrap();
        println!(
            "Computed blind rotation step number {i} in {}",
            now.elapsed().as_secs()
        );
    }
}
