// TODO: Update the name of the method loaded by the prover. E.g., if the method
// is `multiply`, replace `METHOD_NAME_ELF` with `MULTIPLY_ELF` and replace
// `METHOD_NAME_ID` with `MULTIPLY_ID`
use methods::{METHOD_NAME_ELF, METHOD_NAME_ID};
use risc0_zkvm::{
    default_prover,
    serde::{from_slice, to_vec},
    ExecutorEnv,
};
use ttfhe::{
    ggsw::compute_bsk,
    glwe::keygen,
    lwe::{compute_ksk, lwe_keygen, LweCiphertext},
    utils::{decode_bootstrapped, encode},
};

fn main() {
    let sk1 = lwe_keygen();
    let sk2 = keygen();
    let bsk = compute_bsk(&sk1, &sk2); // list of encryptions under `sk2` of the bits of `sk1`.
    let ksk = compute_ksk(&sk2.recode(), &sk1); // list of encryptions under `sk1` of the bits of `sk2`.

    let c = LweCiphertext::encrypt(encode(2), &sk1).modswitch(); // "noisy" ciphertext that will be bootstrapped

    let env = ExecutorEnv::builder()
        .add_input(&to_vec(&(c, bsk, ksk)).unwrap())
        .build()
        .unwrap();

    let prover = default_prover();

    let receipt = prover.prove_elf(env, METHOD_NAME_ELF).unwrap();

    receipt.verify(METHOD_NAME_ID).unwrap();
    let res_ct = from_slice::<LweCiphertext, _>(&receipt.journal).unwrap();
    let res_pt = decode_bootstrapped(res_ct.decrypt(&sk1));
    println!("Computed bootstrapping and got plaintext {}", res_pt);
}
