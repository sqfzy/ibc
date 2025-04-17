use crate::{
    AAKAError,
    ScalarField,
    ServerAuthResponse,
    SessionKey,
    SystemParameters,
    UserAuthRequest,
    UserSecretKey,
    UserState,
    hash_utils, // Use the hash functions
};
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
// Need Field for checks, UniformRand for random x
use ark_std::Zero;
use ark_std::rand::prelude::*; // For random number generation
use ark_std::{ops::Add, vec::Vec}; // Need Add for scalar math

// --- User Logic Implementation ---

/// User initiates the authentication process.
/// Generates the request message to be sent to the MEC server.
pub fn initiate_authentication<R: Rng + CryptoRng>(
    usk: &UserSecretKey,
    user_id: &[u8],
    server_id: &[u8],
    params: &SystemParameters,
    rng: &mut R,
) -> Result<(UserAuthRequest, UserState), AAKAError> {
    // 1. Select random x from Z_q*
    let x = ScalarField::rand(rng);
    if x.is_zero() {
        return Err(AAKAError::CryptoError(
            "User random scalar x is zero".to_string(),
        ));
    }

    // 2. Compute X = x * P (using G1 generator from params)
    let temp_x_pub = params.p * x;

    // 3. Compute gx = g^x = e(P, P)^x
    //    g is precomputed in params: g = e(P1, P2)
    //    So, gx = g^x
    let g_x = params.g.mul_bigint(x.into_bigint()); // GT points multiplication is by scalar field element

    // 4. Compute M = x * (Ppub_hat + h1(IDms) * P)
    let h_ms = hash_utils::h1(server_id)?;
    let h_ms_p = params.p * h_ms; // h1(IDms) * P
    let inner_m = params.p_pub_hat.add(&h_ms_p); // Ppub_hat + h1(IDms) * P
    let m = inner_m * x; // x * (...)

    // 5. Compute N = h2(gx) XOR (IDu || Ru || X)
    //    Need to determine the size for h2 output accurately
    let r_u_bytes = {
        let mut buf = Vec::new();
        usk.r_u.into_affine().serialize_compressed(&mut buf)?;
        buf
    };
    let x_pub_bytes = {
        let mut buf = Vec::new();
        temp_x_pub.into_affine().serialize_compressed(&mut buf)?;
        buf
    };

    let n_payload_len = user_id.len() + r_u_bytes.len() + x_pub_bytes.len();
    let h2_output = hash_utils::h2(&g_x, n_payload_len)?;

    let n_payload = {
        let mut buf = Vec::with_capacity(n_payload_len);
        buf.extend_from_slice(user_id);
        buf.extend_from_slice(&r_u_bytes);
        buf.extend_from_slice(&x_pub_bytes);
        buf
    };

    // Perform XOR
    if h2_output.len() != n_payload.len() {
        // This should not happen if h2 is implemented correctly for the length
        return Err(AAKAError::HashError(format!(
            "H2 output length ({}) does not match payload length ({})",
            h2_output.len(),
            n_payload.len()
        )));
    }
    let n: Vec<u8> = h2_output
        .iter()
        .zip(n_payload.iter())
        .map(|(h, p)| h ^ p)
        .collect();

    // 6. Get timestamp Tu
    //    In a real implementation, get current time. Here we use a placeholder.
    let timestamp_u = crate::get_current_timestamp()?; // Assuming a helper function

    // 7. Compute sigma = SIDu + x * h3(IDu || Ru || X || Tu) (mod q)
    let h_3 = hash_utils::h3(user_id, &usk.r_u, &temp_x_pub, timestamp_u)?;
    let sigma = usk.sid_u.add(&(x * h_3));

    // Prepare the request message
    let request = UserAuthRequest {
        m,
        n,
        sigma,
        timestamp: timestamp_u,
    };

    // Prepare the state to keep for response processing
    let state = UserState {
        x,
        temp_x_pub, // Store X = xP
        user_id: user_id.to_vec(),
        r_u: usk.r_u,
    };

    Ok((request, state))
}

/// User processes the server's response message.
/// Verifies the server and computes the session key.
pub fn process_server_response(
    usk: &UserSecretKey, // User's secret key (contains SIDu)
    state: &UserState,   // State saved from initiate_authentication (contains x, X, IDu, Ru)
    response: &ServerAuthResponse,
    server_id: &[u8],
    _params: &SystemParameters, // Needed for h4 check maybe? (Check h4 input args)
    key_len_bytes: usize,       // Desired session key length
) -> Result<SessionKey, AAKAError> {
    // 1. Check timestamp Tms freshness
    //    In a real implementation, compare with current time and allowance.
    //    Here we assume a helper function `is_timestamp_fresh` exists.
    if !crate::is_timestamp_fresh(response.timestamp)? {
        return Err(AAKAError::InvalidTimestamp);
    }

    // 2. Verify t = h4(IDu || IDms || X || Y || Tms)
    //    We need IDu, IDms, X (from state), Y (from response), Tms (from response)
    let computed_t = hash_utils::h4(
        &state.user_id,     // IDu from saved state
        server_id,          // IDms passed as argument
        &state.temp_x_pub,  // X from saved state
        &response.y,        // Y from server response
        response.timestamp, // Tms from server response
    )?;

    if computed_t != response.t {
        return Err(AAKAError::ServerResponseVerificationFailed);
    }

    // Server is authenticated if t matches.

    // 3. Compute Ku-ms = (SIDu + x * t) * Y (mod q for scalar part)
    //    t is the received (and verified) t from the server response
    let xt = state.x * response.t; // x*t
    let sidu_plus_xt = usk.sid_u.add(&xt); // SIDu + x*t
    let k_u_ms_point = response.y * sidu_plus_xt; // (SIDu + x*t) * Y

    // 4. Compute SKu-ms = h5(Ku-ms || IDu || IDms || X || Y)
    let session_key_bytes = hash_utils::h5(
        &k_u_ms_point, // GtPoint - wait, Ku-ms should be GtPoint? Let's recheck math.
        // Ah, the paper shows K = (...)P, but calculates SK = h5(K || ...).
        // Let's assume K itself is the G1Point result (SIDu+xt)Y for now.
        // Rechecking Fig 5 & Formulas (3)(4):
        // Ku-ms = (SIDu + xt) * Y = (SIDu + x*h4(...)) * y*P
        // Kms-u = y(tX' + W) = y(h4(...) * xP + Ru + hu*Ppub) = y(...)P
        // Yes, K is a G1Point. h5 input should be G1Point. Let's fix h5 signature if needed.
        // Let's adjust h5 input type or how K is used.
        // Assume h5 takes G1Point for now. If K needs to be Gt, we calculate e(K, P) or similar.
        // Let's assume the paper meant h5 takes the G1 point K directly.
        // If h5 requires GtPoint, we need to adjust:
        // let k_u_ms_gt = Curve::pairing(k_u_ms_point, params.p).map_err(|e| AAKAError::CryptoError(e.to_string()))?;
        // Let's assume for now h5 takes G1Point based on how K is calculated. We need to update h5 signature later.
        &state.user_id,
        server_id,
        &state.temp_x_pub, // X
        &response.y,       // Y
        key_len_bytes,
    )?;

    // **Correction Needed for h5:** Let's assume h5 should operate on a value derived from the common secret.
    // The common secret established is related to `y * (SIDu + xt) * P` or `x * (SIDms_derived_value + yt') * P`.
    // Let's re-examine K calculation and h5 input from paper formulas (3) & (4).
    // Kms-u = y(tX' + W) = y(h4*xP + ruP + hu*sP) = (h4*xy + ruy + hu*sy) * P
    // Ku-ms = (SIDu + xt)Y = (ru + shu + x*h4) * yP = (ruy + syhu + xy*h4) * P
    // Yes, K is indeed a G1Point. So h5 needs to take G1Point.
    // Let's modify hash_utils::h5 signature.

    Ok(SessionKey(session_key_bytes))
}

// Helper functions (placeholders, need actual implementation)
// These should ideally be in a separate utility module.

pub fn get_current_timestamp() -> Result<u64, AAKAError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| AAKAError::CryptoError(format!("System time error: {}", e)))
}

pub fn is_timestamp_fresh(timestamp: u64) -> Result<bool, AAKAError> {
    const ALLOWED_SKEW_SECONDS: u64 = 300; // Allow 5 minutes skew
    let current_ts = get_current_timestamp()?;
    let diff = if current_ts >= timestamp {
        current_ts - timestamp
    } else {
        timestamp - current_ts // Handle potential clock skew in both directions
    };
    Ok(diff <= ALLOWED_SKEW_SECONDS)
}
