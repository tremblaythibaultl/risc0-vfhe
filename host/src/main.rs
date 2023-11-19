use methods::{BLIND_ROTATE_ELF, BLIND_ROTATE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use ttfhe::{
    ggsw::compute_bsk,
    glwe::keygen,
    lwe::{lwe_keygen, LweCiphertext},
    utils::{decode_bootstrapped, encode},
};

fn main() {
    let sk1 = lwe_keygen();
    let sk2 = keygen();
    let bsk = compute_bsk(&sk1, &sk2); // list of encryptions under `sk2` of the bits of `sk1`.

    // let ksk = compute_ksk(&sk2.recode(), &sk1); // list of encryptions under `sk1` of the bits of `sk2`.

    let c = LweCiphertext::encrypt(encode(2), &sk1).modswitch(); // "noisy" ciphertext that will be bootstrapped

    let env = ExecutorEnv::builder()
        .write(&c)
        .unwrap()
        .write(&bsk)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    let receipt = prover.prove_elf(env, BLIND_ROTATE_ELF).unwrap();

    receipt.verify(BLIND_ROTATE_ID).unwrap();
    let res_ct: LweCiphertext = receipt.journal.decode().unwrap();
    let res_pt = decode_bootstrapped(res_ct.decrypt(&sk1));
    println!("Computed bootstrapping and got plaintext {}", res_pt);
}
