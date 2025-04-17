use crate::{
    AAKAError, Curve, G1AffinePoint, ScalarField, ServerAuthResponse, ServerSecretKey, SessionKey,
    SystemParameters, UserAuthRequest, get_current_timestamp, hash_utils, is_timestamp_fresh,
};
use ark_ec::{
    AffineRepr, // Group for identity, AffineRepr for deserialization/coords
    pairing::Pairing,
};
use ark_ff::UniformRand; // Field for inverse, UniformRand for y
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize}; // For deserialization
use ark_std::rand::prelude::*;
use ark_std::{Zero, ops::Add, vec::Vec};

// --- Server Logic Implementation ---

/// Processes a user's authentication request message.
/// Verifies the user, generates a response, and computes the session key.
pub fn process_user_request<R: Rng + CryptoRng>(
    ssk: &ServerSecretKey, // Server's own secret key (SIDms)
    request: &UserAuthRequest,
    own_id: &[u8], // Server's own ID (IDms)
    params: &SystemParameters,
    rng: &mut R,
    key_len_bytes: usize, // Desired session key length
) -> Result<(ServerAuthResponse, SessionKey), AAKAError> {
    // 1. Check timestamp Tu freshness
    if !is_timestamp_fresh(request.timestamp)? {
        return Err(AAKAError::InvalidTimestamp);
    }

    // 2. Compute gx = e(M, SIDms)
    //    M is from request, SIDms is server's secret key
    let g_x = Curve::pairing(request.m, ssk.sid_ms); // M is G1, SIDms is G2

    // 3. Decrypt N = h2(gx) XOR (IDu || Ru || X) to get IDu', Ru', X'
    //    First, deserialize Ru' and X' which are G1 points. Need their lengths.
    //    Let's assume standard compressed G1 point size.
    let g1_compressed_size = G1AffinePoint::default().compressed_size();
    let n_len = request.n.len();
    if n_len <= g1_compressed_size * 2 {
        return Err(AAKAError::Deserialization(
            "N parameter too short to contain Ru and X".to_string(),
        ));
    }
    let id_len = n_len - 2 * g1_compressed_size;
    let ru_offset = id_len;
    let x_offset = id_len + g1_compressed_size;

    let h2_output = hash_utils::h2(&g_x, n_len)?; // Use the fixed gx

    // Perform XOR to get original payload bytes
    if h2_output.len() != request.n.len() {
        return Err(AAKAError::HashError(format!(
            "H2 output length ({}) does not match N length ({})",
            h2_output.len(),
            request.n.len()
        )));
    }
    let n_payload: Vec<u8> = h2_output
        .iter()
        .zip(request.n.iter())
        .map(|(h, p)| h ^ p)
        .collect();

    // Extract components
    let id_u_prime = &n_payload[0..id_len];
    let r_u_prime_bytes = &n_payload[ru_offset..x_offset];
    let x_prime_bytes = &n_payload[x_offset..];

    // Deserialize points
    let r_u_prime = G1AffinePoint::deserialize_compressed(r_u_prime_bytes)
        .map_err(|e| AAKAError::Deserialization(format!("Failed to deserialize Ru': {}", e)))?
        .into_group(); // Convert to Projective for potential calculations
    let x_prime = G1AffinePoint::deserialize_compressed(x_prime_bytes)
        .map_err(|e| AAKAError::Deserialization(format!("Failed to deserialize X': {}", e)))?
        .into_group();

    // 4. Compute W = Ru' + h0(IDu' || Ru') * Ppub_hat
    let h_0 = hash_utils::h0(id_u_prime, &r_u_prime)?;
    let h0_ppub = params.p_pub * h_0; // <-- **Corrected: Use params.p_pub (sP)**
    let w = r_u_prime.add(&h0_ppub); // <-- **Corrected: W = R'u + h0 * sP**

    // 5. Verify signature: σP =? W + h3(ID'u || R'u || X' || Tu) * X'
    let h_3 = hash_utils::h3(id_u_prime, &r_u_prime, &x_prime, request.timestamp)?;
    let h3_x_prime = x_prime * h_3;
    let rhs = w.add(&h3_x_prime); // Now RHS = R'u + h0*sP + h3*xP

    let sigma_p = params.p * request.sigma; // LHS = (ru + s*h0 + x*h3) * P

    if sigma_p != rhs {
        return Err(AAKAError::SignatureVerificationFailed);
    }

    // User is authenticated if signature is valid.

    // 6. Choose random y from Z_q*
    let y = ScalarField::rand(rng);
    if y.is_zero() {
        return Err(AAKAError::CryptoError(
            "Server random scalar y is zero".to_string(),
        ));
    }

    // 7. Compute Y = y * P
    let y_pub = params.p * y;

    // 8. Get timestamp Tms
    let timestamp_ms = get_current_timestamp()?;

    // 9. Compute t = h4(IDu' || IDms || X' || Y || Tms)
    let t = hash_utils::h4(id_u_prime, own_id, &x_prime, &y_pub, timestamp_ms)?;

    // 10. Compute Kms-u = y * (t * X' + W)
    let tx_prime = x_prime * t;
    let inner_k = tx_prime.add(&w);
    let k_ms_u_point = inner_k * y; // This is a G1Point

    // 11. Compute Session Key SKms-u = h5(Kms-u || IDu' || IDms || X' || Y)
    let session_key_bytes = hash_utils::h5(
        &k_ms_u_point, // Pass the G1Point
        id_u_prime,
        own_id,
        &x_prime,
        &y_pub,
        key_len_bytes,
    )?;

    // Prepare response
    let response = ServerAuthResponse {
        t,
        y: y_pub,
        timestamp: timestamp_ms,
    };

    Ok((response, SessionKey(session_key_bytes)))
}
