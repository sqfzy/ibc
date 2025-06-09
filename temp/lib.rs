pub mod hash_utils;
pub mod rc; // Make the rc module public
pub mod server;
pub mod user;

use ark_bls12_381::{Bls12_381, Fr as BlsScalarField, G1Affine, G1Projective, G2Projective};
use ark_ec::pairing::PairingOutput;
use ark_ec::{Group, pairing::Pairing}; // Need CurveGroup for zero(), Group for identity
use ark_ff::{BigInt, Field, UniformRand}; // Need Field for inverse, UniformRand for random generation
use ark_std::Zero;
use ark_std::ops::Add;
use ark_std::rand::prelude::*; // For random number generation (e.g., thread_rng) // Need Add trait
// Add UniformRand for random generation
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use blahaj::{Share, Sharks};
use bytemuck::try_from_bytes;
use rand::{SeedableRng, rngs::StdRng};
use std::time::{SystemTime, UNIX_EPOCH}; // Add SystemTime imports here

// Define type aliases for clarity
pub type Curve = Bls12_381; // Our chosen curve
pub type G1Point = G1Projective; // Points in G1 (projective coordinates are usually better for computations)
pub type G2Point = G2Projective;
pub type G1AffinePoint = G1Affine; // Affine representation of G1 points (often needed for serialization/hashing)
pub type GtPoint = PairingOutput<Curve>; // Points in the target group GT
pub type ScalarField = BlsScalarField; // Elements in the scalar field Z_q

use serde::{Deserialize, Serialize};

// --- Error Handling ---
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AAKAError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Server response verification failed")]
    ServerResponseVerificationFailed,
    #[error("Input data invalid: {0}")]
    InvalidInput(String),
    #[error("Hash function error: {0}")]
    HashError(String),
    #[error("other error: {0}")]
    Other(String),
}

// Helper to convert ark_serialize errors
impl From<ark_serialize::SerializationError> for AAKAError {
    fn from(err: ark_serialize::SerializationError) -> Self {
        AAKAError::Serialization(err.to_string())
    }
}

// --- Data Structures ---

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct SystemParameters {
    // We don't explicitly store curve info, it's implied by the types
    pub p: G1Point,         // Generator P
    pub p_pub: G1Point,     // sP
    pub p_pub_hat: G1Point, // ŝP
    pub g: GtPoint,         // e(P, P)
                            // Hash function identifiers/configs could be added here if needed
}

// Note: MasterSecretKey should be handled with extreme care and NOT be easily serialized/passed around.
// We define it for completeness but won't derive Serialize/Deserialize directly.
#[derive(Debug, Clone, PartialEq)]
pub struct MasterSecretKey {
    pub s: ScalarField,
    pub s_hat: ScalarField,
}

impl MasterSecretKey {
    pub fn into_shares(self, n: usize) -> Vec<Share> {
        let sharks = Sharks(n as u8);
        let msk_bytes: [u8; 64] = bytemuck::cast([self.s.0.0, self.s_hat.0.0]);
        let dealer = sharks.dealer(&msk_bytes);
        dealer.take(n).collect::<Vec<_>>()
    }

    pub fn from_shares(shares: Vec<Share>, n: usize) -> Result<Self, AAKAError> {
        let sharks = Sharks(n as u8);
        let bytes: [u8; 64] = sharks
            .recover(&shares)
            .map_err(|e| AAKAError::Other(e.to_string()))?
            .try_into()
            .map_err(|_| AAKAError::Other("MasterSecretKey should be [u8; 64]".to_string()))?;

        let two_parts: [[u64; 4]; 2] = bytemuck::cast(bytes);
        let s = ScalarField::from(BigInt::<4>(two_parts[0]));
        let s_hat = ScalarField::from(BigInt::<4>(two_parts[1]));

        Ok(Self { s, s_hat })
    }
}

#[test]
fn test_shares() {
    let mut rng = StdRng::from_entropy();
    let s = ScalarField::rand(&mut rng);
    let s_hat = ScalarField::rand(&mut rng); // Use ŝ notation internally as s_hat
    let msk = MasterSecretKey { s, s_hat };

    let shares = msk.clone().into_shares(3);
    let msk2 = MasterSecretKey::from_shares(shares, 3).unwrap();
    assert_eq!(msk, msk2);
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct UserSecretKey {
    pub r_u: G1Point,       // Ru = ru * P
    pub sid_u: ScalarField, // SIDu = ru + s * h0(IDu || Ru)
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct ServerSecretKey {
    // SIDms = (1 / (ŝ + h1(IDms))) * P
    // We store the point directly
    pub sid_ms: G2Point,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserAuthRequest {
    pub m: G1Point,
    pub n: Vec<u8>, // Encrypted/XORed data (IDu || Ru || X)
    pub sigma: ScalarField,
    pub timestamp: u64, // T_u
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerAuthResponse {
    pub t: ScalarField,
    pub y: G1Point,
    pub timestamp: u64, // T_ms
}

// Wrapper type for the final session key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey(pub Vec<u8>); // Store as bytes

// Temporary state kept by the user between sending request and receiving response
// We might need this later when implementing the user logic
#[derive(Debug, Clone)]
pub struct UserState {
    pub x: ScalarField,      // The chosen random x
    pub temp_x_pub: G1Point, // X = xP
    pub user_id: Vec<u8>,    // User's ID
    pub r_u: G1Point,        // User's Ru
                             // Store other relevant info if needed, e.g., target server_id
}
/// Gets the current Unix timestamp in seconds.
// Marked pub(crate) so it's accessible within the crate (e.g., from user.rs and server.rs)
pub(crate) fn get_current_timestamp() -> Result<u64, AAKAError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| AAKAError::CryptoError(format!("System time error: {}", e)))
}

/// Checks if a given timestamp is fresh within an allowed skew.
pub(crate) fn is_timestamp_fresh(timestamp: u64) -> Result<bool, AAKAError> {
    const ALLOWED_SKEW_SECONDS: u64 = 300; // Allow 5 minutes skew
    let current_ts = get_current_timestamp()?;
    let diff = if current_ts >= timestamp {
        current_ts - timestamp
    } else {
        timestamp - current_ts // Handle potential clock skew in both directions
    };
    Ok(diff <= ALLOWED_SKEW_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (lib.rs)
    use crate::{
        SessionKey, // Import our modules
        rc,
        server,
        user,
    };
    use ark_std::rand::{SeedableRng, rngs::StdRng}; // For deterministic testing RNG

    use std::ops::Add; // Use vec macro

    // Helper to create a deterministic RNG for tests
    fn test_rng() -> StdRng {
        // Use a fixed seed for reproducible tests
        StdRng::seed_from_u64(0u64)
    }

    // Helper to compare SessionKeys (assumes content equality is needed)
    impl PartialEq for SessionKey {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0 // Compare the underlying byte vectors
        }
    }
    impl Eq for SessionKey {}

    #[test]
    fn test_full_protocol_flow_success() {
        let mut rng = test_rng();
        let key_len_bytes = 32; // e.g., AES-256 key length

        // --- Phase 1: Setup ---
        let (params, msk) = rc::setup(&mut rng).expect("Setup failed");

        // --- Phase 2: Registration ---
        let user_id = b"alice@example.com";
        let server_id = b"mec-server-1.edge";

        let usk = rc::register_user(&msk, user_id, &mut rng).expect("User registration failed");
        // **Apply the fix for SIDms being G2 point**
        let ssk = rc::register_server(&msk, server_id).expect("Server registration failed");

        // --- Phase 3: Authentication ---

        // 1. User initiates authentication
        let (request, user_state) =
            user::initiate_authentication(&usk, user_id, server_id, &params, &mut rng)
                .expect("User initiation failed");

        // 2. Server processes request
        let server_result = server::process_user_request(
            &ssk,
            &request,
            server_id,
            &params,
            &mut rng,
            key_len_bytes,
        );

        // Assert server processing was successful
        assert!(
            server_result.is_ok(),
            "Server processing failed: {:?}",
            server_result.err()
        );
        let (response, server_session_key) = server_result.unwrap();

        // 3. User processes response
        let user_result = user::process_server_response(
            &usk,
            &user_state,
            &response,
            server_id,
            &params, // Pass params here
            key_len_bytes,
        );

        // Assert user processing was successful
        assert!(
            user_result.is_ok(),
            "User processing failed: {:?}",
            user_result.err()
        );
        let user_session_key = user_result.unwrap();

        // --- Final Check ---
        // Verify that both parties derived the same session key
        assert_eq!(
            user_session_key, server_session_key,
            "Session keys do not match!"
        );

        // Optional: Print keys for debugging (consider hex encoding)
        // println!("User SK: {}", hex::encode(&user_session_key.0));
        // println!("Server SK: {}", hex::encode(&server_session_key.0));
        assert!(!user_session_key.0.is_empty()); // Ensure key is not empty
    }

    #[test]
    fn test_signature_verification_failure() {
        let mut rng = test_rng();
        let key_len_bytes = 32;

        // --- Setup & Registration ---
        let (params, msk) = rc::setup(&mut rng).unwrap();
        let user_id = b"alice@example.com";
        let server_id = b"mec-server-1.edge";
        let usk = rc::register_user(&msk, user_id, &mut rng).unwrap();
        let ssk = rc::register_server(&msk, server_id).unwrap(); // Corrected SIDms type assumed

        // --- User initiates ---
        let (mut request, _user_state) =
            user::initiate_authentication(&usk, user_id, server_id, &params, &mut rng).unwrap();

        // --- Tamper with the signature (sigma) ---
        // Add one to sigma (in the scalar field)
        use ark_ff::Field;
        request.sigma = request.sigma.add(&ScalarField::ONE); // Tamper sigma

        // --- Server processes tampered request ---
        let server_result = server::process_user_request(
            &ssk,
            &request,
            server_id,
            &params,
            &mut rng,
            key_len_bytes,
        );

        // --- Assert Failure ---
        assert!(server_result.is_err());
        match server_result.err().unwrap() {
            AAKAError::SignatureVerificationFailed => {} // Expected error
            e => panic!("Expected SignatureVerificationFailed, got {:?}", e),
        }
    }

    #[test]
    fn test_server_response_verification_failure() {
        let mut rng = test_rng();
        let key_len_bytes = 32;

        // --- Setup & Registration ---
        let (params, msk) = rc::setup(&mut rng).unwrap();
        let user_id = b"alice@example.com";
        let server_id = b"mec-server-1.edge";
        let usk = rc::register_user(&msk, user_id, &mut rng).unwrap();
        let ssk = rc::register_server(&msk, server_id).unwrap();

        // --- User initiates ---
        let (request, user_state) =
            user::initiate_authentication(&usk, user_id, server_id, &params, &mut rng).unwrap();

        // --- Server processes valid request ---
        let server_result = server::process_user_request(
            &ssk,
            &request,
            server_id,
            &params,
            &mut rng,
            key_len_bytes,
        );
        assert!(server_result.is_ok());
        let (mut response, _server_session_key) = server_result.unwrap();

        // --- Tamper with the response (t) ---
        use ark_ff::Field;
        response.t = response.t.add(&ScalarField::ONE); // Tamper t

        // --- User processes tampered response ---
        let user_result = user::process_server_response(
            &usk,
            &user_state,
            &response,
            server_id,
            &params,
            key_len_bytes,
        );

        // --- Assert Failure ---
        assert!(user_result.is_err());
        match user_result.err().unwrap() {
            AAKAError::ServerResponseVerificationFailed => {} // Expected error
            e => panic!("Expected ServerResponseVerificationFailed, got {:?}", e),
        }
    }

    #[test]
    fn test_replay_attack_failure_user_request() {
        let mut rng = test_rng();
        let key_len_bytes = 32;

        // --- Setup & Registration ---
        let (params, msk) = rc::setup(&mut rng).unwrap();
        let user_id = b"alice@example.com";
        let server_id = b"mec-server-1.edge";
        let usk = rc::register_user(&msk, user_id, &mut rng).unwrap();
        let ssk = rc::register_server(&msk, server_id).unwrap();

        // --- User initiates ---
        let (request, _user_state) =
            user::initiate_authentication(&usk, user_id, server_id, &params, &mut rng).unwrap();

        // --- Server processes first time (should succeed) ---
        let server_result1 = server::process_user_request(
            &ssk,
            &request,
            server_id,
            &params,
            &mut rng,
            key_len_bytes,
        );
        assert!(server_result1.is_ok());

        // --- Simulate time passing beyond freshness window ---
        // (In a real test, you might mock the time function, here we just assume it fails)
        // For demonstration, let's assume the timestamp check works and will fail if the same request arrives later.

        // --- Modify the request to make its timestamp stale ---
        let mut stale_request = request.clone(); // Clone the original request
        let current_time = get_current_timestamp().unwrap(); // Get current time for reference
        const ALLOWED_SKEW_SECONDS: u64 = 300; // Use the same constant as in is_timestamp_fresh
        stale_request.timestamp = current_time.saturating_sub(ALLOWED_SKEW_SECONDS + 60); // Set timestamp to be clearly outside the window (e.g., 6 minutes ago)

        // --- Server processes the *stale* request ---
        let server_result2 = server::process_user_request(
            &ssk,
            &stale_request,
            server_id,
            &params,
            &mut rng,
            key_len_bytes,
        ); // Use the modified request

        // --- Assert Failure ---
        assert!(
            server_result2.is_err(),
            "Processing a stale request should fail"
        );
        match server_result2.err().unwrap() {
            AAKAError::InvalidTimestamp => {} // Expected error due to old timestamp
            e => panic!("Expected InvalidTimestamp (stale), got {:?}", e),
        }
    }

    // TODO: Add more tests:
    // - Test replay attack on server response
    // - Test incorrect server_id used by user during initiation
    // - Test hash function outputs for known inputs (if possible)
    // - Test serialization/deserialization of all relevant structs
    // - Test edge cases (e.g., IDs with special characters if relevant)
}
