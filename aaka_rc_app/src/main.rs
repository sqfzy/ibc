use anyhow::{Result, anyhow};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use dotenvy::dotenv;
use ibc_aaka_scheme::{
    MasterSecretKey, // Import core types and rc functions
    SystemParameters,
    rc,
};
use parking_lot::RwLock; // Use RwLock for interior mutability of state
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc}; // Use Arc for shared state // For RNG

// --- State Management ---

// Structure to hold the RC's state (parameters and master key)
// We wrap it in Arc<RwLock<...>> for safe concurrent access in Axum handlers
#[derive(Clone)]
struct RcState {
    inner: Arc<RwLock<InnerRcState>>,
}

struct InnerRcState {
    params: Option<SystemParameters>,
    msk: Option<MasterSecretKey>,
    rng: StdRng, // Keep a seeded RNG for deterministic key generation if needed in handlers
}

impl RcState {
    fn new() -> Result<Self> {
        // Return Result to handle setup errors
        println!("Initializing RC State...");
        // Initialize RNG first
        // Use a fixed seed for simplicity/demonstration
        let mut rng = StdRng::seed_from_u64(12345u64);

        // Perform setup immediately
        println!("Running initial setup...");
        // Call rc::setup directly
        let (params, msk) = rc::setup(&mut rng)?; // Use anyhow context
        println!("Initial setup complete.");

        // Create the initial state with params and msk populated
        let initial_state = InnerRcState {
            params: Some(params),
            msk: Some(msk), // Store MSK in memory (simplification!)
            rng,            // Move rng into state
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(initial_state)),
        })
    }
}

// --- Request/Response Payloads ---

#[derive(Deserialize)]
struct RegisterRequest {
    id: String, // User or Server ID as string
}

// Use hex encoding for serialized points/scalars in JSON for better readability/transfer
#[derive(Serialize)]
struct UserRegistrationResponse {
    r_u_hex: String,
    sid_u_hex: String,
}

#[derive(Serialize)]
struct ServerRegistrationResponse {
    sid_ms_hex: String,
}

#[derive(Serialize)]
struct SystemParametersResponse {
    p_hex: String,
    p_pub_hex: String,
    p_pub_hat_hex: String,
    g_hex: String,
}

// --- Utility Functions ---

// Helper to serialize arkworks types to hex string
fn ark_to_hex<T: CanonicalSerialize>(item: &T) -> Result<String> {
    let mut buffer = Vec::new();
    item.serialize_compressed(&mut buffer)
        .map_err(|e| anyhow!("Serialization failed: {}", e))?;
    Ok(hex::encode(buffer))
}

// Helper to deserialize arkworks types from hex string
// Not strictly needed for RC responses, but useful pattern
#[allow(dead_code)] // Allow unused for now
fn hex_to_ark<T: CanonicalDeserialize>(hex_str: &str) -> Result<T> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("Hex decoding failed: {}", e))?;
    T::deserialize_compressed(&bytes[..]).map_err(|e| anyhow!("Deserialization failed: {}", e))
}

// --- Axum Handlers ---

// Handler for GET /params
// Returns the system public parameters
async fn get_params(
    State(state): State<RcState>,
) -> Result<Json<SystemParametersResponse>, AppError> {
    let state_read = state.inner.read();
    // Since setup runs at start, params should always exist unless setup failed initially
    if let Some(params) = &state_read.params {
        let response = SystemParametersResponse {
            p_hex: ark_to_hex(&params.p)?,
            p_pub_hex: ark_to_hex(&params.p_pub)?,
            p_pub_hat_hex: ark_to_hex(&params.p_pub_hat)?,
            g_hex: ark_to_hex(&params.g)?,
        };
        Ok(Json(response))
    } else {
        // This case should ideally not happen if RcState::new() succeeds
        Err(AppError(anyhow!(
            "Internal error: System parameters are unexpectedly missing."
        )))
    }
}

// Handler for POST /setup
// Initializes the system parameters and master key (only once)
async fn setup_system(
    State(state): State<RcState>,
) -> Result<Json<SystemParametersResponse>, AppError> {
    let state_read = state.inner.read();
    if let Some(params) = &state_read.params {
        let response = SystemParametersResponse {
            p_hex: ark_to_hex(&params.p)?,
            p_pub_hex: ark_to_hex(&params.p_pub)?,
            p_pub_hat_hex: ark_to_hex(&params.p_pub_hat)?,
            g_hex: ark_to_hex(&params.g)?,
        };
        Ok(Json(response))
    } else {
        Err(AppError(anyhow!(
            "Internal error: System parameters are unexpectedly missing after initialization."
        )))
    }
}

// Handler for POST /register/user
async fn register_user(
    State(state): State<RcState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<UserRegistrationResponse>, AppError> {
    println!("Registering user: {}", payload.id);
    let mut state_write = state.inner.write(); // Need mutable access for RNG

    let InnerRcState { msk, rng, .. } = &mut *state_write;
    if let Some(msk) = msk {
        let user_id_bytes = payload.id.as_bytes();
        let usk = rc::register_user(msk, user_id_bytes, rng)?;

        let response = UserRegistrationResponse {
            r_u_hex: ark_to_hex(&usk.r_u)?,
            sid_u_hex: ark_to_hex(&usk.sid_u)?, // Serialize ScalarField
        };
        Ok(Json(response))
    } else {
        Err(AppError(anyhow!(
            "System not initialized. Call /setup first."
        )))
    }
}

// Handler for POST /register/server
async fn register_server(
    State(state): State<RcState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<ServerRegistrationResponse>, AppError> {
    println!("Registering server: {}", payload.id);
    let state_read = state.inner.read(); // Read lock might be enough if RNG state isn't mutated often

    if let Some(msk) = &state_read.msk {
        let server_id_bytes = payload.id.as_bytes();
        // **Ensure register_server uses the corrected G2 logic**
        let ssk = rc::register_server(msk, server_id_bytes)?;

        let response = ServerRegistrationResponse {
            // **Ensure ServerSecretKey contains G2Point and it serializes correctly**
            sid_ms_hex: ark_to_hex(&ssk.sid_ms)?, // Serialize G2Point
        };
        Ok(Json(response))
    } else {
        Err(AppError(anyhow!(
            "System not initialized. Call /setup first."
        )))
    }
}

// --- Main Application Setup ---

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    // Initialize state
    let rc_state = RcState::new()?;

    // Build Axum app
    let app = Router::new()
        .route("/setup", post(setup_system)) // Endpoint to initialize
        .route("/params", get(get_params)) // Endpoint to get public params
        .route("/register/user", post(register_user)) // Endpoint for user registration
        .route("/register/server", post(register_server)) // Endpoint for server registration
        .with_state(rc_state); // Share the state with handlers

    // Get listen address from environment variable or use default
    let listen_addr = env::var("RC_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3001".to_string());

    // Run the server
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?; // Use listen_addr
    println!("RC Server listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}

// --- Custom Error Type for Axum ---
// Make Axum return proper errors using anyhow for simplicity
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        eprintln!("Error occurred: {:?}", self.0); // Log the full error details
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Internal Server Error: {}", self.0), // Simplified user message
        )
            .into_response()
    }
}

// Implement conversion from anyhow::Error to AppError
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
