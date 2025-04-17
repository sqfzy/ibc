use crate::{AAKAError, G1Point, GtPoint, ScalarField}; // Import types from lib.rs
use ark_ec::CurveGroup; // Need this trait for point coordinates/serialization
use ark_ff::PrimeField; // For field operations
use ark_serialize::CanonicalSerialize; // For serializing points/field elements
use ark_std::vec::Vec; // Use ark_std's Vec

use digest::Digest; // Import Digest trait
use sha3::Sha3_256; // Use SHA3-256 as the base hash function

// --- Domain Separation Constants ---
// Using unique prefixes for each hash function to ensure domain separation
const H0_DOMAIN_SEP: &[u8] = b"IBC_AAKA_H0";
const H1_DOMAIN_SEP: &[u8] = b"IBC_AAKA_H1";
const H2_DOMAIN_SEP: &[u8] = b"IBC_AAKA_H2";
const H3_DOMAIN_SEP: &[u8] = b"IBC_AAKA_H3";
const H4_DOMAIN_SEP: &[u8] = b"IBC_AAKA_H4";
const H5_DOMAIN_SEP: &[u8] = b"IBC_AAKA_H5";

// Helper function to serialize G1 points safely
fn serialize_g1(point: &G1Point) -> Result<Vec<u8>, AAKAError> {
    let mut buffer = Vec::new();
    point
        .into_affine() // Convert to affine for canonical serialization
        .serialize_compressed(&mut buffer)?; // Use compressed serialization for efficiency
    Ok(buffer)
}

// Helper function to serialize Gt points safely
fn serialize_gt(point: &GtPoint) -> Result<Vec<u8>, AAKAError> {
    let mut buffer = Vec::new();
    point.serialize_compressed(&mut buffer)?;
    Ok(buffer)
}

// --- Hash Function Implementations ---

/// h0: {0,1}^* × G → Z_q^*
/// Input: IDu || Ru
pub fn h0(id_u: &[u8], r_u: &G1Point) -> Result<ScalarField, AAKAError> {
    let r_u_bytes = serialize_g1(r_u)?;

    let mut hasher = Sha3_256::new();
    hasher.update(H0_DOMAIN_SEP);
    hasher.update(id_u);
    hasher.update(&r_u_bytes);
    let hash_output = hasher.finalize();

    // Convert hash output bytes to a ScalarField element (mod q)
    // Using from_be_bytes_mod_order ensures the result is in the field
    Ok(ScalarField::from_be_bytes_mod_order(hash_output.as_slice()))
}

/// h1: {0,1}^* → Z_q^*
/// Input: IDms
pub fn h1(id_ms: &[u8]) -> Result<ScalarField, AAKAError> {
    let mut hasher = Sha3_256::new();
    hasher.update(H1_DOMAIN_SEP);
    hasher.update(id_ms);
    let hash_output = hasher.finalize();

    Ok(ScalarField::from_be_bytes_mod_order(hash_output.as_slice()))
}

/// h2: GT → {0,1}^* × G × G (Output is raw bytes for XOR)
/// Input: gx = g^x = e(P, P)^x
/// Output length must match |IDu| + |Ru| + |X|
pub fn h2(g_x: &GtPoint, output_len: usize) -> Result<Vec<u8>, AAKAError> {
    let gx_bytes = serialize_gt(g_x)?;

    let mut hasher = Sha3_256::new();
    hasher.update(H2_DOMAIN_SEP);
    hasher.update(&gx_bytes);
    let hash_output = hasher.finalize(); // SHA3-256 outputs 32 bytes

    // If required output length is different from hash output length,
    // we might need a KDF or extend the hash. For simplicity,
    // we'll require the hash output length to be sufficient or use a KDF-like approach.
    // A simple (but not ideal) approach if len > 32: re-hash iteratively.
    // A better approach: Use a KDF like HKDF or Blake2X.
    // Let's use a simple iterative hashing if needed (demonstration purpose).
    let mut result_bytes = Vec::with_capacity(output_len);
    result_bytes.extend_from_slice(hash_output.as_slice());

    let mut counter: u32 = 0;
    while result_bytes.len() < output_len {
        let mut hasher_ext = Sha3_256::new();
        hasher_ext.update(H2_DOMAIN_SEP); // Keep domain separation consistent
        hasher_ext.update(&gx_bytes);
        hasher_ext.update(counter.to_be_bytes()); // Add counter to vary input
        let next_hash = hasher_ext.finalize();
        result_bytes.extend_from_slice(next_hash.as_slice());
        counter += 1;
        if counter > 100 {
            // Safety break to prevent infinite loops
            return Err(AAKAError::HashError(
                "H2 output generation loop limit reached".to_string(),
            ));
        }
    }

    // Truncate to the exact required length
    result_bytes.truncate(output_len);
    Ok(result_bytes)

    // Note: For production, consider using a dedicated XOF (e.g., SHAKE) or KDF (e.g., HKDF-Expand with SHA3-256).
    // This iterative approach is less standard but works for demonstration.
}

/// h3: {0,1}^* × G × G × {0,1}^* → Z_q^*
/// Input: IDu || Ru || X || Tu
pub fn h3(
    id_u: &[u8],
    r_u: &G1Point,
    x_pub: &G1Point, // X = xP
    timestamp: u64,
) -> Result<ScalarField, AAKAError> {
    let r_u_bytes = serialize_g1(r_u)?;
    let x_pub_bytes = serialize_g1(x_pub)?;
    let ts_bytes = timestamp.to_be_bytes();

    let mut hasher = Sha3_256::new();
    hasher.update(H3_DOMAIN_SEP);
    hasher.update(id_u);
    hasher.update(&r_u_bytes);
    hasher.update(&x_pub_bytes);
    hasher.update(ts_bytes);
    let hash_output = hasher.finalize();

    Ok(ScalarField::from_be_bytes_mod_order(hash_output.as_slice()))
}

/// h4: {0,1}^* × {0,1}^* × G × G × {0,1}^* → Z_q^*
/// Input: IDu || IDms || X || Y || Tms
pub fn h4(
    id_u: &[u8],
    id_ms: &[u8],
    x_pub: &G1Point, // X = xP
    y_pub: &G1Point, // Y = yP
    timestamp: u64,
) -> Result<ScalarField, AAKAError> {
    let x_pub_bytes = serialize_g1(x_pub)?;
    let y_pub_bytes = serialize_g1(y_pub)?;
    let ts_bytes = timestamp.to_be_bytes();

    let mut hasher = Sha3_256::new();
    hasher.update(H4_DOMAIN_SEP);
    hasher.update(id_u);
    hasher.update(id_ms);
    hasher.update(&x_pub_bytes);
    hasher.update(&y_pub_bytes);
    hasher.update(ts_bytes);
    let hash_output = hasher.finalize();

    Ok(ScalarField::from_be_bytes_mod_order(hash_output.as_slice()))
}

/// h5: GT × {0,1}^* × {0,1}^* × G × G → {0,1}^k (Output is Session Key)
/// Input: K = Kms-u = Ku-ms || IDu || IDms || X || Y
/// k is the desired key length in bytes (e.g., 16 for AES-128, 32 for AES-256)
pub fn h5(
    k_intermediate_g1: &G1Point, // <-- **Changed type to G1Point**
    id_u: &[u8],
    id_ms: &[u8],
    x_pub: &G1Point, // X = xP
    y_pub: &G1Point, // Y = yP
    key_len_bytes: usize,
) -> Result<Vec<u8>, AAKAError> {
    let k_bytes = serialize_g1(k_intermediate_g1)?; // <-- **Use serialize_g1**
    let x_pub_bytes = serialize_g1(x_pub)?;
    let y_pub_bytes = serialize_g1(y_pub)?;

    let mut hasher = Sha3_256::new();
    hasher.update(H5_DOMAIN_SEP);
    hasher.update(&k_bytes); // Hash the G1 point bytes
    hasher.update(id_u);
    hasher.update(id_ms);
    hasher.update(&x_pub_bytes);
    hasher.update(&y_pub_bytes);
    let hash_output = hasher.finalize(); // 32 bytes

    // KDF logic (iterative hash) remains the same for generating desired length
    let mut result_bytes = Vec::with_capacity(key_len_bytes);
    result_bytes.extend_from_slice(hash_output.as_slice());

    let mut counter: u32 = 0;
    while result_bytes.len() < key_len_bytes {
        let mut hasher_ext = Sha3_256::new();
        hasher_ext.update(H5_DOMAIN_SEP);
        hasher_ext.update(&k_bytes); // Re-use same base input
        hasher_ext.update(id_u);
        hasher_ext.update(id_ms);
        hasher_ext.update(&x_pub_bytes);
        hasher_ext.update(&y_pub_bytes);
        hasher_ext.update(counter.to_be_bytes()); // Vary input
        let next_hash = hasher_ext.finalize();
        result_bytes.extend_from_slice(next_hash.as_slice());
        counter += 1;
        if counter > 100 {
            return Err(AAKAError::HashError(
                "H5 output generation loop limit reached".to_string(),
            ));
        }
    }
    result_bytes.truncate(key_len_bytes);
    Ok(result_bytes)
}
