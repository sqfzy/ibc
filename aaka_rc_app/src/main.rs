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
use blahaj::{Share, Sharks};
use dotenvy::dotenv;
use ibc_aaka_scheme::{
    MasterSecretKey, // Import core types and rc functions
    SystemParameters,
    rc,
};
use reqwest::Client;
// Use RwLock for interior mutability of state
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, str::FromStr, sync::Arc};
use tokio::sync::RwLock;
use tracing::{Level, debug, info, warn};

// 用于从 config.json 加载配置
#[derive(Deserialize)]
struct Config {
    rc_addr: String,
    nodes: Vec<String>,
}

// --- State Management ---

// Structure to hold the RC's state (parameters and master key)
// We wrap it in Arc<RwLock<...>> for safe concurrent access in Axum handlers
#[derive(Clone)]
struct RcState {
    inner: Arc<RwLock<InnerRcState>>,
}

struct InnerRcState {
    params: Option<SystemParameters>,
    // msk: Option<MasterSecretKey>,
    rng: StdRng, // Keep a seeded RNG for deterministic key generation if needed in handlers
    // 集群中所有节点（包括自己）的地址
    peers: Arc<Vec<String>>,
    // 自己的地址
    self_addr: String,
    shares: Vec<Share>,
}

impl RcState {
    fn new(self_addr: String, peers: Vec<String>) -> Result<Self> {
        let rng = StdRng::from_entropy();

        // Create the initial state with params and msk populated
        let initial_state = InnerRcState {
            params: None,
            // msk: None,                    // Store MSK in memory (simplification!)
            rng,                    // Move rng into state
            shares: Vec::new(),     // Initialize empty shares vector
            peers: Arc::new(peers), // Store peers in an Arc for shared access
            self_addr,              // Store self address
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(initial_state)),
        })
    }
}

impl InnerRcState {
    async fn recover_secret(&self) -> Result<MasterSecretKey, AppError> {
        let nodes_count = self.peers.len();

        let mut shares = self.shares.clone();
        for peer_addr in self.peers.iter() {
            if peer_addr == &self.self_addr {
                // Skip self, we already have our own share
                continue;
            }

            // Collect shares from all peers
            let res = reqwest::get(format!("http://{peer_addr}/get_shares")).await;

            match res {
                Ok(response) => {
                    if let Ok(shares_bytes) = response.json::<Vec<Vec<u8>>>().await {
                        for share_bytes in shares_bytes {
                            if let Ok(share) = Share::try_from(share_bytes.as_slice()) {
                                shares.push(share);
                            }
                        }
                    }
                }
                Err(e) => warn!("Failed to get shares from {}: {}", peer_addr, e),
            }
        }

        Ok(MasterSecretKey::from_shares(shares, nodes_count)?)
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
    debug!("Calling setup_system handler");

    let mut state_write = state.inner.write().await;
    if state_write.self_addr != state_write.peers[0] {
        // Only allow setup on the first node in the peer list
        return Err(AppError(anyhow!(
            "Setup can only be called on the first node in the peer list."
        )));
    }

    // Perform setup immediately
    info!("Running initial setup...");
    // Call rc::setup directly
    let (params, msk) = rc::setup(&mut state_write.rng)?; // Use anyhow context
    info!("Initial setup complete.");

    state_write.params = Some(params.clone()); // Store system parameters

    let nodes_count = state_write.peers.len();

    let shares = msk
        .into_shares(nodes_count)
        .into_iter()
        .map(|s| Vec::from(&s))
        .collect::<Vec<Vec<u8>>>();

    for (i, peer) in state_write.peers.to_vec().into_iter().enumerate() {
        if peer == state_write.self_addr {
            state_write.shares =
                vec![Share::try_from(shares[i].as_slice()).map_err(|e| AppError(anyhow!(e)))?]; // Store own share
            continue; // Skip self
        }

        // Send shares to other peers
        let res = Client::new()
            .post(format!("http://{}/set_shares", peer))
            .json(&vec![shares[i].clone()])
            .send()
            .await;

        match res {
            Ok(_) => println!("Shares sent to peer: {}", peer),
            Err(e) => warn!("Failed to send shares to {}: {}", peer, e),
        }
    }

    let response = SystemParametersResponse {
        p_hex: ark_to_hex(&params.p)?,
        p_pub_hex: ark_to_hex(&params.p_pub)?,
        p_pub_hat_hex: ark_to_hex(&params.p_pub_hat)?,
        g_hex: ark_to_hex(&params.g)?,
    };
    Ok(Json(response))
}

// Handler for POST /register/user
async fn register_user(
    State(state): State<RcState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<UserRegistrationResponse>, AppError> {
    debug!("Calling register_user handler. payload: {:?}", payload);

    // println!("Registering user: {}", payload.id);
    let mut state_write = state.inner.write().await; // Need mutable access for RNG

    let msk = state_write.recover_secret().await?;
    let InnerRcState { rng, .. } = &mut *state_write;
    let user_id_bytes = payload.id.as_bytes();
    let usk = rc::register_user(&msk, user_id_bytes, rng)?;

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

    let msk = state_read.recover_secret().await?;
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
async fn set_shares(
    State(state): State<RcState>,
    Json(shares): Json<Vec<Vec<u8>>>,
) -> Result<StatusCode, AppError> {
    debug!("Calling set_shares handler. shares: {:?}", shares);

    let mut state_write = state.inner.write().await;

    let shares = shares
        .into_iter()
        .map(|s| Share::try_from(s.as_slice()).map_err(|e| AppError(anyhow!(e))))
        .collect::<Result<Vec<Share>, AppError>>()?;

    state_write.shares = shares;
    Ok(StatusCode::OK)
}

// Handler for GET /get_shares
async fn get_shares(State(state): State<RcState>) -> Result<Json<Vec<Vec<u8>>>, AppError> {
    debug!("Calling get_shares handler");

    let state_read = state.inner.read().await;
    let shares = &state_read.shares;

    // Convert each Share to Vec<u8>
    let shares_bytes: Vec<Vec<u8>> = shares.iter().map(Vec::from).collect();
    Ok(Json(shares_bytes))
}

// --- Main Application Setup ---

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_max_level(Level::from_str(&level)?)
        .init();

    // 从 config.json 加载集群节点信息
    let config_str = std::fs::read_to_string("config.json")?;
    let config: Config = serde_json::from_str(&config_str)?;
    let peers = config.nodes;

    let self_uri_str = env::var("RC_ADDR").unwrap_or(config.rc_addr.clone());

    if !peers.contains(&self_uri_str.to_string()) {
        warn!(
            "Self URI '{}' is not in the config.json peer list.",
            self_uri_str
        );
    }

    // Initialize state
    let rc_state = RcState::new(self_uri_str.clone(), peers)?;

    // Build Axum app
    let app = Router::new()
        .route("/setup", get(setup_system)) // Endpoint to initialize
        .route("/params", get(get_params)) // Endpoint to get public params
        .route("/register/user", post(register_user)) // Endpoint for user registration
        .route("/register/server", post(register_server)) // Endpoint for server registration
        .route("/set_shares", post(set_shares))
        .route("/get_shares", get(get_shares))
        .with_state(rc_state); // Share the state with handlers

    // Run the server
    let listener = tokio::net::TcpListener::bind(&self_uri_str).await?; // Use listen_addr
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
