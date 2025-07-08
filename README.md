# Verifiable fully homomorphic encryption with Risc0

This repository hosts a proof of concept for verifiable fully homomorphic encryption.

The aim of this project is to prove and verify the correct execution of a single TFHE bootstrapping.

## Instructions

### Requirements
Risc0 zkVM: see installation procedure [here](https://dev.risczero.com/api/zkvm/install).

### Code structure
The project is divided in a guest (code to be executed in the zkVM) and a host (orchestrator for proving and verifying the guest code).
This follows paradigms introduced by Risc0. See [Risc0](https://dev.risczero.com/api/zkvm/) for more information on the project structure enforced by the zkVM.

The code relies on the [ttfhe](https://github.com/tremblaythibaultl/ttfhe) library, a simple (and thus zkVM-compatible) Rust implementation of the [TFHE](https://eprint.iacr.org/2018/421) cryptosystem. 

### Usage
- To test the program and make sure it compiles, use the "dev mode" provided by the Risc0 API:
```bash
RISC0_DEV_MODE=1 RUST_LOG=info RISC0_INFO=1 cargo run --release
```
- To generate proofs, execute
```bash
RISC0_DEV_MODE=0 RUST_LOG=info RISC0_INFO=1 cargo run --release
```

#### WARNING
The results presented in the paper were obtained by running the zkVM on a `hpc7a.96xlarge` AWS EC2 instance with 192 CPU cores and 768 GB memory. 

zkVMs are notoriously resource-hungry. As such, we do not guarantee the reproducibility of our results on less powerful machines. In fact, trying to execute this prototype on a machine with insufficient resources will likely result in a "killed" process.
