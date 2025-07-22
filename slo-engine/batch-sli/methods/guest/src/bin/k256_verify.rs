
use risc0_zkvm::guest::env;

// verify_minimal.rs - Standalone verification function

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    EncodedPoint,
};
use sha2::{Digest, Sha256};

use anyhow::{bail, Context, Result};
use json::{parse, JsonValue};
use json_core::Outputs;

pub struct VerificationResult {
    pub valid: bool,
    pub merkle_root_valid: bool,
    pub signature_valid: bool,
    pub calculated_merkle_root: String,
    pub expected_merkle_root: String,
    pub signer_address: String,
    pub error: Option<String>,
}

pub struct BatchStatistics {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub success_rate: f64,
    pub timestamp: String,
}

// Merkle tree helper functions
fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hex::encode(hasher.finalize())
}

fn build_merkle_tree(leaf_hashes: Vec<String>) -> String {
    if leaf_hashes.is_empty() {
        return String::new();
    }

    let mut current_level = leaf_hashes;

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for i in (0..current_level.len()).step_by(2) {
            if i + 1 < current_level.len() {
                // Hash pair of nodes
                let hash = hash_pair(&current_level[i], &current_level[i + 1]);
                next_level.push(hash);
            } else {
                // Odd number of nodes, promote the last one
                next_level.push(current_level[i].clone());
            }
        }

        current_level = next_level;
    }

    current_level[0].clone()
}

fn verify_signature(data: &[u8], signature: &str, verifying_key: &VerifyingKey) -> bool {
    let sig_bytes = match hex::decode(signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    if sig_bytes.len() != 64 {
        return false;
    }

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    verifying_key.verify(&hash, &signature).is_ok()
}

/// Create a canonical JSON string for a measurement (matching the original serialization)
fn measurement_to_canonical_json(measurement: &JsonValue) -> Result<String> {
    // Build the JSON in the exact order expected
    let canonical = json::object! {
        "endpoint" => measurement["endpoint"].as_str().unwrap_or(""),
        "method" => measurement["method"].as_str().unwrap_or(""),
        "path" => measurement["path"].as_str().unwrap_or(""),
        "statusCode" => measurement["statusCode"].as_u16().unwrap_or(0),
        "latency" => measurement["latency"].as_i32().unwrap_or(0),
        "timestamp" => measurement["timestamp"].as_i64().unwrap_or(0),
        "success" => measurement["success"].as_bool().unwrap_or(false),
        "monitorId" => measurement["monitorId"].as_str().unwrap_or(""),
        "error" => if measurement["error"].is_null() {
            JsonValue::Null
        } else {
            measurement["error"].clone()
        }
    };

    Ok(canonical.dump())
}

/// Verify a specific batch from the parsed JSON data
///
/// # Arguments
/// * `data` - The parsed JsonValue from json::parse
/// * `batch_index` - The index of the batch to verify
///
/// # Returns
/// * `Result<VerificationResult>` - The verification result with details
pub fn verify_minimal_batch(data: &JsonValue, batch_index: usize) -> Result<VerificationResult> {
    // Extract needed fields
    let public_key = data["public_key"]
        .as_str()
        .context("Missing public_key field")?;

    let wallet_address = data["wallet_address"]
        .as_str()
        .context("Missing wallet_address field")?;

    let batches = &data["batches"];
    if !batches.is_array() {
        bail!("batches field is not an array");
    }

    let batch = &batches[batch_index];
    if batch.is_null() {
        bail!("Batch {} not found", batch_index);
    }

    let merkle_root = batch["merkle_root"]
        .as_str()
        .context("Missing merkle_root in batch")?;

    let merkle_root_signature = batch["merkle_root_signature"]
        .as_str()
        .context("Missing merkle_root_signature in batch")?;

    let measurements = &batch["measurements"];
    if !measurements.is_array() {
        bail!("measurements field is not an array");
    }

    // Step 1: Build merkle tree from measurements
    let mut leaf_hashes = Vec::new();

    for i in 0..measurements.len() {
        let measurement = &measurements[i];

        // Create canonical JSON representation
        let canonical = measurement_to_canonical_json(measurement)?;

        // Hash the measurement
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let measurement_hash = hex::encode(hasher.finalize());
        leaf_hashes.push(measurement_hash);
    }

    let calculated_root = build_merkle_tree(leaf_hashes);

    // Step 2: Check if calculated root matches claimed root
    let merkle_root_valid = calculated_root == merkle_root;

    // Step 3: Verify merkle root signature
    let public_key_bytes = hex::decode(public_key).context("Failed to decode public key")?;
    let point =
        EncodedPoint::from_bytes(&public_key_bytes).context("Failed to parse public key point")?;
    let verifying_key =
        VerifyingKey::from_encoded_point(&point).context("Failed to create verifying key")?;

    let signature_valid = verify_signature(
        merkle_root.as_bytes(),
        merkle_root_signature,
        &verifying_key,
    );

    // Build result
    let result = VerificationResult {
        valid: merkle_root_valid && signature_valid,
        merkle_root_valid,
        signature_valid,
        calculated_merkle_root: calculated_root,
        expected_merkle_root: merkle_root.to_string(),
        signer_address: wallet_address.to_string(),
        error: if !merkle_root_valid {
            Some("Merkle root mismatch".to_string())
        } else if !signature_valid {
            Some("Invalid signature".to_string())
        } else {
            None
        },
    };

    Ok(result)
}

/// Get batch statistics from the parsed JSON data
pub fn get_batch_statistics(data: &JsonValue, batch_index: usize) -> Result<BatchStatistics> {
    let batches = &data["batches"];
    if !batches.is_array() {
        bail!("batches field is not an array");
    }

    let batch = &batches[batch_index];
    if batch.is_null() {
        bail!("Batch {} not found", batch_index);
    }

    let measurements = &batch["measurements"];
    if !measurements.is_array() {
        bail!("measurements field is not an array");
    }

    let total = measurements.len();
    let mut successful = 0;

    for i in 0..measurements.len() {
        if measurements[i]["success"].as_bool().unwrap_or(false) {
            successful += 1;
        }
    }

    let failed = total - successful;
    let success_rate = (successful as f64 / total as f64) * 100.0;

    let timestamp = batch["timestamp"].as_str().unwrap_or("unknown").to_string();

    Ok(BatchStatistics {
        total,
        successful,
        failed,
        success_rate,
        timestamp,
    })
}
/*
fn main() {
    // Decode the verifying key, message, and signature from the inputs.
    let (encoded_verifying_key, message, signature): (EncodedPoint, Vec<u8>, Signature) =
        env::read();
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();

    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&message, &signature)
        .expect("ECDSA signature verification failed");

    // Commit to the journal the verifying key and message that was signed.
    env::commit(&(encoded_verifying_key, message));
} */
fn main() {
    let data: String = env::read();

    let data = parse(&data).unwrap();
    let result = verify_minimal_batch(&data, 0).unwrap();

    println!("Verification Result:");
    println!("  Valid: {}", result.valid);
    println!("  Merkle Root Valid: {}", result.merkle_root_valid);
    println!("  Signature Valid: {}", result.signature_valid);
    println!(
        "  Calculated Root: {}...",
        &result.calculated_merkle_root[..16]
    );
    println!("  Expected Root: {}...", &result.expected_merkle_root[..16]);
    println!("  Signer Address: {}", result.signer_address);

    // Get statistics
    let stats = get_batch_statistics(&data, 0).unwrap();
    println!("\nBatch Statistics:");
    println!("  Total: {}", stats.total);
    println!("  Successful: {}", stats.successful);
    println!("  Failed: {}", stats.failed);
    println!("  Success Rate: {:.2}%", stats.success_rate);
    println!("  Timestamp: {}", stats.timestamp);

    //let proven_val = data["critical_data"].as_u32().unwrap();

    env::commit(&(stats.total, result.valid));
}
