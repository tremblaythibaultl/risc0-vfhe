# Verifiable fully homomorphic encryption with Risc0

This repository hosts a proof of concept for verifiable fully homomorphic encryption.

The aim of this project is to prove and verify the correct execution of a single TFHE bootstrapping.

## Instructions

### Requirements
Risc0 zkVM (and all of its subdependencies): see installation procedure [here](https://dev.risczero.com/api/zkvm/install).

### Code structure
The project is divided in a guest (code to be executed in the zkVM) and a host (orchestrator for proving and verifying the guest code).
This follows paradigms introduced by Risc0. See [Risc0](https://dev.risczero.com/api/zkvm/) for more information on the project structure enforced by the zkVM.

The code relies on the [ttfhe](https://github.com/tremblaythibaultl/ttfhe) library, a simple (and thus zkVM-compatible) Rust implementation of the [TFHE](https://eprint.iacr.org/2018/421) cryptosystem. 

### Usage
1. Build the program:
```bash
$ cd program 
$ cargo prove build
```
2. Execute the program:
```bash
$ cd ../script 
$ RUST_LOG=info cargo run --release -- --execute
```