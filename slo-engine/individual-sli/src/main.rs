
use k256_methods::{K256_VERIFY_ELF, K256_VERIFY_ID};
//use rand_core::OsRng;
use risc0_zkvm::{default_prover, ExecutorEnv};



fn main() {
    let data = include_str!("../res/measurement-proof-0-1024.json");
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

    // Decode the committed values from the journal
    let (
        _is_valid,            // bool: Is the proof valid?
        _sla_violated,        // bool: Does it violate SLA?
        _measurement_latency, // i32: What was the latency?
        _measurement_success, // bool: Was it successful?
        _batch_sequence,      // u64: Which batch?
        _measurement_index,   // usize: Which measurement in the batch?
    ): (bool, bool, i32, bool, u64, usize) = receipt.journal.decode().unwrap();
    receipt.verify(K256_VERIFY_ID).unwrap();
}

