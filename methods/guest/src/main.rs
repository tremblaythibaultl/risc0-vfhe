use risc0_zkvm::guest::env;
use ttfhe::{
    ggsw::{cmux, GgswCiphertext},
    glwe::GlweCiphertext,
};

fn main() {
    // read the input
    let (bsk_i, c_prime, c_prime_rotated): (GgswCiphertext, GlweCiphertext, GlweCiphertext) =
        env::read();

    // compute a cmux operation (one step of the blind rotation)
    let res = cmux(&bsk_i, &c_prime, &c_prime_rotated);

    // commit to the result
    env::commit(&res);
}
