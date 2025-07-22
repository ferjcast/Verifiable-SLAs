

use k256_methods::{K256_VERIFY_ELF, K256_VERIFY_ID};
//use rand_core::OsRng;
use risc0_zkvm::{default_prover, ExecutorEnv};



fn main() {
    let data = include_str!("../res/mock-verification-minimal-1024.json");
    search_json(data);
}

fn search_json(data: &str) {
    let env = ExecutorEnv::builder()
        .write(&data)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove(env, K256_VERIFY_ELF).unwrap().receipt;

    let (_receipt_verifying_key, _receipt_message): (u32, u32) = receipt.journal.decode().unwrap();

    receipt.verify(K256_VERIFY_ID).unwrap();
}

