use crate::{
    AAKAError,
    Curve,
    G1Point,
    G2Point,
    MasterSecretKey,
    ScalarField,
    ServerSecretKey,
    SystemParameters,
    UserSecretKey, // Use the hash functions we defined
    hash_utils,
};
use ark_ec::{Group, pairing::Pairing}; // Need CurveGroup for zero(), Group for identity
use ark_ff::{Field, UniformRand}; // Need Field for inverse, UniformRand for random generation
use ark_std::Zero;
use ark_std::ops::Add;
use ark_std::rand::prelude::*; // For random number generation (e.g., thread_rng) // Need Add trait

// --- RC Logic Implementation ---

/// Generates system parameters and master secret key.
pub fn setup<R: Rng + CryptoRng>(
    rng: &mut R,
) -> Result<(SystemParameters, MasterSecretKey), AAKAError> {
    // 1. Generate Master Secret Keys s, ŝ
    let s = ScalarField::rand(rng);
    let s_hat = ScalarField::rand(rng); // Use ŝ notation internally as s_hat

    // Ensure s and s_hat are not zero (extremely unlikely, but good practice)
    if s.is_zero() || s_hat.is_zero() {
        return Err(AAKAError::CryptoError(
            "Master secret key generation resulted in zero".to_string(),
        ));
    }

    let msk = MasterSecretKey { s, s_hat };

    // 2. Get the generator P for G1
    let p1_gen = G1Point::generator(); // Generator P (in G1)

    // 3. Compute Public Keys Ppub = sP, Ppub_hat = ŝP (using G1 generator)
    let p_pub = p1_gen * s;
    let p_pub_hat = p1_gen * s_hat;

    // 4. Compute g = e(P1, P2) where P1 is G1 generator, P2 is G2 generator
    let p2_gen = G2Point::generator(); // Generator for G2 <-- **Get G2 generator**
    let g = Curve::pairing(p1_gen, p2_gen); // <-- **Use G1 and G2 generators**

    let params = SystemParameters {
        p: p1_gen,
        p_pub,
        p_pub_hat,
        g,
    };

    Ok((params, msk))
}

/// Registers a mobile user and generates their secret key.
/// Requires the master secret key `s`.
pub fn register_user<R: Rng + CryptoRng>(
    msk: &MasterSecretKey,
    id_u: &[u8],
    rng: &mut R,
) -> Result<UserSecretKey, AAKAError> {
    // 1. Choose random ru from Z_q*
    let r_u_scalar = ScalarField::rand(rng);
    if r_u_scalar.is_zero() {
        return Err(AAKAError::CryptoError(
            "User registration random scalar ru is zero".to_string(),
        ));
    }

    // 2. Compute Ru = ru * P
    let generator_p = G1Point::generator(); // Get the generator P
    let r_u_point = generator_p * r_u_scalar;

    // 3. Compute hu = h0(IDu || Ru)
    let h_u = hash_utils::h0(id_u, &r_u_point)?;

    // 4. Compute SIDu = ru + s * hu (mod q)
    // Ensure we use msk.s here
    let s_mul_h_u = msk.s * h_u;
    let sid_u = r_u_scalar.add(&s_mul_h_u); // Perform addition in the field Z_q

    Ok(UserSecretKey {
        r_u: r_u_point,
        sid_u,
    })
}

/// Registers an MEC server and generates its secret key.
/// Requires the master secret key `ŝ`.
pub fn register_server(
    msk: &MasterSecretKey,
    id_ms: &[u8],
    // No RNG needed here unless h1 implementation required randomness beyond the hash
) -> Result<ServerSecretKey, AAKAError> {
    // 1. Compute hms = h1(IDms)
    let h_ms = hash_utils::h1(id_ms)?;

    // 2. Compute denominator = ŝ + hms (mod q)
    // Ensure we use msk.s_hat here
    let denominator = msk.s_hat.add(&h_ms);

    // Check if denominator is zero (should not happen with random s_hat and good hash)
    if denominator.is_zero() {
        return Err(AAKAError::CryptoError(
            "Denominator (s_hat + h_ms) is zero during server registration".to_string(),
        ));
    }

    // 3. Compute inverse of denominator: (ŝ + hms)^-1 mod q
    let inv_denominator = denominator.inverse().ok_or_else(|| {
        // Should only fail if denominator is zero, which we already checked
        AAKAError::CryptoError("Failed to compute modular inverse for server key".to_string())
    })?;

    // 4. Compute SIDms = (ŝ + hms)^-1 * P
    let generator_p2 = G2Point::generator();
    let sid_ms_point = generator_p2 * inv_denominator;

    Ok(ServerSecretKey {
        sid_ms: sid_ms_point,
    })
}
