use aaka_rc_app::{
    telemetry::init_subscriber,
    util::{collect_shares, distribute_shares},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use blahaj::{Share, Sharks};
use dotenvy::dotenv;
use eyre::{Result, anyhow, bail};
use figment::{
    Figment,
    providers::{self, Format},
};
use ibc_aaka_scheme::{
    MasterSecretKey, // Import core types and rc functions
    SystemParameters,
    rc,
};
use rand::thread_rng;
use reqwest::Client;
// Use RwLock for interior mutability of state
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, str::FromStr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{Level, debug, info, instrument, warn};
use tracing_error::ErrorLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Deserialize)]
struct RcConfig {
    addr: String,
    nodes: Vec<String>,
    threshold: usize,
}

impl RcConfig {
    fn peers(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|&node| node != &self.addr)
            .cloned()
            .collect()
    }
}

// Structure to hold the RC's state (parameters and master key)
// We wrap it in Arc<RwLock<...>> for safe concurrent access in Axum handlers
#[derive(Clone)]
struct RcState {
    inner: Arc<RwLock<InnerRcState>>,
}

struct InnerRcState {
    params: Option<SystemParameters>,
    share: Option<Share>,
    config: RcConfig,
}

impl RcState {
    fn new(config: RcConfig) -> Result<Self> {
        let initial_state = InnerRcState {
            params: None,
            share: None,
            config,
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(initial_state)),
        })
    }
}

// --- Request/Response Payloads ---

#[derive(Debug, Deserialize)]
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
    debug!("Calling get_params handler");

    let state_read = state.inner.read().await;
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
        Err(AppError(anyhow!(
            "RC should be initialized first by calling /setup endpoint before /get_params."
        )))
    }
}

// Handler for POST /setup
// Initializes the system parameters and master key (only once)
async fn setup_system(
    State(state): State<RcState>,
) -> Result<Json<SystemParametersResponse>, AppError> {
    let mut state_write = state.inner.write().await;
    let nodes_count = state_write.config.nodes.len();

    // 生成主密钥，但这只是临时的，节点本身不存储msk
    let (params, msk) = rc::gen_parameter_and_msk(&mut thread_rng())?; // Use anyhow context
    let mut shares = msk.into_shares(state_write.config.threshold, nodes_count);

    let response = SystemParametersResponse {
        p_hex: ark_to_hex(&params.p)?,
        p_pub_hex: ark_to_hex(&params.p_pub)?,
        p_pub_hat_hex: ark_to_hex(&params.p_pub_hat)?,
        g_hex: ark_to_hex(&params.g)?,
    };

    state_write.params = Some(params);
    state_write.share = Some(shares.pop().unwrap()); // 为当前节点分配一个 share

    distribute_shares(&shares, &state_write.config.peers()).await?;

    Ok(Json(response))
}

// Handler for POST /register/user
async fn register_user(
    State(state): State<RcState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<UserRegistrationResponse>, AppError> {
    let mut state_write = state.inner.write().await;

    let Some(share) = &state_write.share else {
        return Err(AppError(anyhow!(
            "RC must be initialized first by calling /setup endpoint before user registration."
        )));
    };

    let shares = collect_shares(share.clone(), &state_write.config.peers()).await?;
    let msk = MasterSecretKey::from_shares(shares, state_write.config.threshold)?;
    let mut rng = thread_rng();
    let user_id_bytes = payload.id.as_bytes();
    let usk = rc::register_user(&msk, user_id_bytes, &mut rng)?;

    let response = UserRegistrationResponse {
        r_u_hex: ark_to_hex(&usk.r_u)?,
        sid_u_hex: ark_to_hex(&usk.sid_u)?, // Serialize ScalarField
    };
    Ok(Json(response))
}

// Handler for POST /register/server
async fn register_server(
    State(state): State<RcState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<ServerRegistrationResponse>, AppError> {
    debug!("Calling register_server handler. payload: {:?}", payload);

    let state_read = state.inner.read().await; // Read lock might be enough if RNG state isn't mutated often

    let Some(share) = &state_read.share else {
        return Err(AppError(anyhow!(
            "RC must be initialized first by calling /setup endpoint before server registration."
        )));
    };

    let shares = collect_shares(share.clone(), &state_read.config.peers()).await?;
    let msk = MasterSecretKey::from_shares(shares, state_read.config.threshold)?;
    let server_id_bytes = payload.id.as_bytes();
    // **Ensure register_server uses the corrected G2 logic**
    let ssk = rc::register_server(&msk, server_id_bytes)?;

    let response = ServerRegistrationResponse {
        // **Ensure ServerSecretKey contains G2Point and it serializes correctly**
        sid_ms_hex: ark_to_hex(&ssk.sid_ms)?, // Serialize G2Point
    };
    Ok(Json(response))
}

// Handler for POST /set_shares
async fn set_share(
    State(state): State<RcState>,
    Json(share): Json<Vec<u8>>,
) -> Result<(), AppError> {
    debug!("Calling set_shares handler. share: {:?}", share);

    let mut state_write = state.inner.write().await;

    state_write.share = Some(
        Share::try_from(share.as_slice())
            .map_err(|e| AppError(anyhow!("Failed to deserialize share: {}", e)))?,
    );
    Ok(())
}

// Handler for GET /get_shares
async fn get_share(State(state): State<RcState>) -> Result<Json<Vec<u8>>, AppError> {
    debug!("Calling get_shares handler");

    let state_read = state.inner.read().await;
    let Some(share) = &state_read.share else {
        return Err(AppError(eyre::anyhow!(
            "No share available. Ensure /set_share was called first."
        )));
    };

    Ok(Json(share.into()))
}

// --- Main Application Setup ---

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let (sink, _guard) = tracing_appender::non_blocking(std::io::stdout());
    init_subscriber(sink);

    let config = Figment::new()
        .merge(providers::Json::file("config.json"))
        .merge(providers::Env::prefixed("RC_"))
        .extract::<RcConfig>()?;
    let self_addr = config.addr.clone();

    let rc_state = RcState::new(config)?;

    // Build Axum app
    let app = Router::new()
        .route("/setup", get(setup_system)) // Endpoint to initialize
        .route("/params", get(get_params)) // Endpoint to get public params
        .route("/register/user", post(register_user)) // Endpoint for user registration
        .route("/register/server", post(register_server)) // Endpoint for server registration
        .route("/set_share", post(set_share))
        .route("/get_share", get(get_share))
        .layer(TraceLayer::new_for_http())
        .with_state(rc_state); // Share the state with handlers

    // Run the server
    let listener = tokio::net::TcpListener::bind(&self_addr).await?; // Use listen_addr
    println!("RC Server listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}

// --- Custom Error Type for Axum ---
// Make Axum return proper errors using anyhow for simplicity
struct AppError(eyre::Error);

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

impl<E> From<E> for AppError
where
    E: Into<eyre::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
