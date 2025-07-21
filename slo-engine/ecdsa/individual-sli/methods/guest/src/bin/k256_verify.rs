// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use risc0_zkvm::guest::env;

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    EncodedPoint,
};
use sha2::{Digest, Sha256};

use anyhow::{bail, Context, Result};
use json::{parse, JsonValue};

pub struct MeasurementVerificationResult {
    pub valid: bool,
    pub measurement_signature_valid: bool,
    pub merkle_proof_valid: bool,
    pub sla_violated: bool,
    pub violation_type: Option<String>,
    pub error: Option<String>,
}

pub struct SlaEvaluation {
    pub latency_threshold: i32,
    pub violated: bool,
    pub measurement_latency: i32,
    pub measurement_success: bool,
    pub endpoint: String,
}

// Merkle proof verification helpers
fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hex::encode(hasher.finalize())
}

fn verify_merkle_proof(
    leaf_hash: &str,
    leaf_index: usize,
    merkle_proof: &[String],
    merkle_root: &str,
) -> bool {
    let mut current_hash = leaf_hash.to_string();
    let mut current_index = leaf_index;

    for sibling_hash in merkle_proof {
        if current_index % 2 == 0 {
            // Current node is left child
            current_hash = hash_pair(&current_hash, sibling_hash);
        } else {
            // Current node is right child
            current_hash = hash_pair(sibling_hash, &current_hash);
        }
        current_index /= 2;
    }

    current_hash == merkle_root
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

/// Create a canonical JSON string for a measurement
fn measurement_to_canonical_json(measurement: &JsonValue) -> Result<String> {
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

/// Evaluate if a measurement violates SLA
fn evaluate_sla(measurement: &JsonValue, latency_threshold: i32) -> SlaEvaluation {
    let latency = measurement["latency"].as_i32().unwrap_or(0);
    let success = measurement["success"].as_bool().unwrap_or(false);
    let endpoint = measurement["endpoint"].as_str().unwrap_or("").to_string();

    let violated = !success || latency > latency_threshold;

    SlaEvaluation {
        latency_threshold,
        violated,
        measurement_latency: latency,
        measurement_success: success,
        endpoint,
    }
}

/// Verify a measurement proof
pub fn verify_measurement_proof(
    data: &JsonValue,
    latency_threshold: i32,
) -> Result<(MeasurementVerificationResult, SlaEvaluation)> {
    // Extract fields from the proof
    let measurement = &data["measurement"];
    let measurement_signature = data["measurement_signature"]
        .as_str()
        .context("Missing measurement_signature")?;

    let merkle_proof_array = data["merkle_proof"]
        .members()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect::<Vec<String>>();

    let merkle_root = data["merkle_root"]
        .as_str()
        .context("Missing merkle_root")?;

    let merkle_root_signature = data["merkle_root_signature"]
        .as_str()
        .context("Missing merkle_root_signature")?;

    let public_key = data["public_key"].as_str().context("Missing public_key")?;

    let batch_info = &data["batch_info"];
    let measurement_index = batch_info["measurement_index"].as_usize().unwrap_or(0);

    // Step 1: Evaluate SLA
    let sla_eval = evaluate_sla(measurement, latency_threshold);

    // Step 2: Verify measurement signature
    let canonical = measurement_to_canonical_json(measurement)?;

    let public_key_bytes = hex::decode(public_key).context("Failed to decode public key")?;
    let point =
        EncodedPoint::from_bytes(&public_key_bytes).context("Failed to parse public key point")?;
    let verifying_key =
        VerifyingKey::from_encoded_point(&point).context("Failed to create verifying key")?;

    let measurement_signature_valid =
        verify_signature(canonical.as_bytes(), measurement_signature, &verifying_key);

    // Step 3: Hash the measurement to get leaf hash
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let leaf_hash = hex::encode(hasher.finalize());

    // Step 4: Verify merkle proof
    let merkle_proof_valid = verify_merkle_proof(
        &leaf_hash,
        measurement_index,
        &merkle_proof_array,
        merkle_root,
    );

    // Step 5: Verify merkle root signature
    let root_signature_valid = verify_signature(
        merkle_root.as_bytes(),
        merkle_root_signature,
        &verifying_key,
    );

    let all_valid = measurement_signature_valid && merkle_proof_valid && root_signature_valid;

    let result = MeasurementVerificationResult {
        valid: all_valid,
        measurement_signature_valid,
        merkle_proof_valid: merkle_proof_valid && root_signature_valid,
        sla_violated: sla_eval.violated,
        violation_type: if sla_eval.violated {
            if !sla_eval.measurement_success {
                Some("error".to_string())
            } else {
                Some("latency".to_string())
            }
        } else {
            None
        },
        error: if !measurement_signature_valid {
            Some("Invalid measurement signature".to_string())
        } else if !merkle_proof_valid {
            Some("Invalid merkle proof".to_string())
        } else if !root_signature_valid {
            Some("Invalid merkle root signature".to_string())
        } else {
            None
        },
    };

    Ok((result, sla_eval))
}

fn main() {
    // Read the measurement proof JSON
    let data: String = env::read();
    let proof_data = parse(&data).unwrap();

    // SLA threshold (could also be passed as input)
    let latency_threshold = 100; // 100ms

    // Verify the measurement proof
    let (result, sla_eval) = verify_measurement_proof(&proof_data, latency_threshold).unwrap();

    println!("=== Measurement Proof Verification ===");
    println!("Valid: {}", result.valid);
    println!(
        "Measurement Signature: {}",
        result.measurement_signature_valid
    );
    println!("Merkle Proof: {}", result.merkle_proof_valid);

    println!("\n=== SLA Evaluation ===");
    println!("Endpoint: {}", sla_eval.endpoint);
    println!("Success: {}", sla_eval.measurement_success);
    println!(
        "Latency: {} ms (threshold: {} ms)",
        sla_eval.measurement_latency, sla_eval.latency_threshold
    );
    println!("SLA Violated: {}", sla_eval.violated);

    if let Some(violation_type) = &result.violation_type {
        println!("Violation Type: {}", violation_type);
    }

    // Extract batch info for the commit
    let batch_sequence = proof_data["batch_info"]["batch_sequence"]
        .as_u64()
        .unwrap_or(0);
    let measurement_index = proof_data["batch_info"]["measurement_index"]
        .as_usize()
        .unwrap_or(0);

    // Commit the verification results to the journal
    // This proves:
    // 1. The measurement is valid (properly signed and included in batch)
    // 2. Whether it violates SLA
    // 3. Which batch and measurement index it came from
    env::commit(&(
        result.valid,                 // Is the proof valid?
        sla_eval.violated,            // Does it violate SLA?
        sla_eval.measurement_latency, // What was the latency?
        sla_eval.measurement_success, // Was it successful?
        batch_sequence,               // Which batch?
        measurement_index,            // Which measurement in the batch?
    ));
}
