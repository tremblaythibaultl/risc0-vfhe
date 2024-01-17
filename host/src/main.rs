use methods::{BLIND_ROTATE_ELF, BLIND_ROTATE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use ttfhe::{
    ggsw::{compute_bsk, BootstrappingKey},
    glwe::{keygen, SecretKey},
    lwe::{lwe_keygen, LweCiphertext, LweSecretKey},
    utils::{decode_bootstrapped, encode},
};

fn main() {
    // let sk1 = lwe_keygen();
    let sk1: LweSecretKey = bincode::deserialize(&std::fs::read("../data/sk1").unwrap()).unwrap();
    // let sk2 = keygen();
    let sk2: SecretKey = bincode::deserialize(&std::fs::read("../data/sk2").unwrap()).unwrap();
    // let bsk = compute_bsk(&sk1, &sk2); // list of encryptions under `sk2` of the bits of `sk1`.
    let bsk: BootstrappingKey =
        bincode::deserialize(&std::fs::read("../data/bsk").unwrap()).unwrap();

    // let ksk = compute_ksk(&sk2.recode(), &sk1); // list of encryptions under `sk1` of the bits of `sk2`.

    // let c = LweCiphertext::encrypt(encode(2), &sk1).modswitch(); // "noisy" ciphertext that will be bootstrapped
    let c: LweCiphertext = bincode::deserialize(&std::fs::read("../data/ct").unwrap()).unwrap();

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

#[test]
fn generate_bsk() {
    let sk1 = lwe_keygen();
    let sk2 = keygen();
    let bsk = compute_bsk(&sk1, &sk2); // list of encryptions under `sk2` of the bits of `sk1`.

    let ct = LweCiphertext::encrypt(encode(2), &sk1).modswitch();

    let sk1_ser = bincode::serialize(&sk1).unwrap();
    let sk2_ser = bincode::serialize(&sk2).unwrap();
    let bsk_ser = bincode::serialize(&bsk).unwrap();
    let ct_ser = bincode::serialize(&ct).unwrap();

    std::fs::write("../data/sk1", sk1_ser).unwrap();
    std::fs::write("../data/sk2", sk2_ser).unwrap();
    std::fs::write("../data/bsk", bsk_ser).unwrap();
    std::fs::write("../data/ct", ct_ser).unwrap();
}
