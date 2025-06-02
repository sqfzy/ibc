use anyhow::{Context, Result, anyhow};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize}; // For deserializing keys/params
use ark_std::rand::{SeedableRng, rngs::StdRng};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::post,
};
use dotenvy::dotenv;
use ibc_aaka_scheme::{
    G1Point, // Import base crypto types
    ScalarField,
    ServerSecretKey, // Import core types and server functions
    SystemParameters,
    UserAuthRequest,
    server,
};
use parking_lot::RwLock; // Although state is read-only after init, use RwLock for consistency pattern
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc}; // For RNG

// --- State Management ---

// Structure to hold the MS Server's state
#[derive(Clone)]
struct MsState {
    inner: Arc<RwLock<InnerMsState>>,
}

struct InnerMsState {
    server_id: String,
    params: SystemParameters,
    ssk: ServerSecretKey, // Server's own secret key
    rng: StdRng,          // RNG for server operations (like generating y)
}

// --- Request/Response Payloads ---

// UserAuthRequest is defined in the library, but we need to deserialize it from JSON.
// We expect the JSON fields to match the UserAuthRequest struct fields,
// potentially with hex-encoded points/scalars.
#[derive(Deserialize)]
struct AuthRequestPayload {
    // Assume points and scalars are sent as hex strings from the client
    m_hex: String,
    n: String, // N is Vec<u8>, maybe base64 encode it? Or keep as hex? Let's try hex.
    sigma_hex: String,
    timestamp: u64,
}

// ServerAuthResponse is defined in the library, but we need to serialize it to JSON.
#[derive(Serialize)]
struct AuthResponsePayload {
    // Serialize points and scalars to hex strings
    t_hex: String,
    y_hex: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct AuthSuccessResponse {
    message: String,
    response: AuthResponsePayload,
    // In a real app, we wouldn't send the key back!
    // For demo purposes ONLY:
    session_key_hex: String,
}

// --- Data structure for RC /register/server response ---
#[derive(Deserialize, Debug)]
struct RcServerRegistrationResponse {
    sid_ms_hex: String,
}

// --- Data structure for RC /params response ---
#[derive(Deserialize, Debug)]
struct RcSystemParametersResponse {
    p_hex: String,
    p_pub_hex: String,
    p_pub_hat_hex: String,
    g_hex: String,
}

// --- Utility Functions ---

// Helper to deserialize arkworks types from hex string
fn hex_to_ark<T: CanonicalDeserialize>(hex_str: &str) -> Result<T> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| anyhow!("Hex decoding failed for '{}': {}", hex_str, e))?;
    T::deserialize_compressed(&bytes[..]).map_err(|e| anyhow!("Ark Deserialization failed: {}", e))
}

// Helper to serialize arkworks types to hex string
fn ark_to_hex<T: CanonicalSerialize>(item: &T) -> Result<String> {
    let mut buffer = Vec::new();
    item.serialize_compressed(&mut buffer)
        .map_err(|e| anyhow!("Ark Serialization failed: {}", e))?;
    Ok(hex::encode(buffer))
}

// --- Axum Handler ---

// Handler for POST /auth/initiate
async fn handle_auth_request(
    State(state): State<MsState>,
    Json(payload): Json<AuthRequestPayload>,
) -> Result<Json<AuthSuccessResponse>, AppError> {
    println!("Received authentication request");
    let state_locked = state.inner.read(); // Read lock should be sufficient
    let mut rng = state_locked.rng.clone(); // Clone RNG if needed per request, or lock state_write

    // 1. Deserialize request data from hex/base64
    let m: G1Point = hex_to_ark(&payload.m_hex).context("Failed to deserialize M from hex")?;
    let n_bytes = hex::decode(&payload.n).context("Failed to decode N from hex")?;
    let sigma: ScalarField =
        hex_to_ark(&payload.sigma_hex).context("Failed to deserialize sigma from hex")?;

    let request = UserAuthRequest {
        m,
        n: n_bytes,
        sigma,
        timestamp: payload.timestamp,
    };

    // 2. Call the core library function
    // Assuming key_len_bytes is fixed for this server instance
    let key_len_bytes = 32; // e.g., AES-256

    let server_result = server::process_user_request(
        &state_locked.ssk,
        &request,
        state_locked.server_id.as_bytes(), // Server's own ID
        &state_locked.params,
        &mut rng, // Pass the cloned RNG
        key_len_bytes,
    );

    match server_result {
        Ok((response, session_key)) => {
            println!(
                "Authentication successful. Server Session Key: {}",
                hex::encode(&session_key.0)
            );
            // 3. Serialize the response to hex JSON format
            let response_payload = AuthResponsePayload {
                t_hex: ark_to_hex(&response.t)?,
                y_hex: ark_to_hex(&response.y)?,
                timestamp: response.timestamp,
            };

            let success_response = AuthSuccessResponse {
                message: "Authentication successful".to_string(),
                response: response_payload,
                session_key_hex: hex::encode(&session_key.0), // DEMO ONLY
            };
            Ok(Json(success_response))
        }
        Err(e) => {
            println!("Authentication failed: {:?}", e);
            // Convert specific AAKAError types to appropriate HTTP status codes if desired
            // For now, just return a generic error via AppError
            Err(AppError(anyhow!("Authentication failed: {}", e)))
        }
    }
}

// --- Main Application Setup ---

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    // --- Load Configuration from Environment Variables ---
    let server_id =
        env::var("MS_SERVER_ID").context("Missing MS_SERVER_ID environment variable")?;
    let listen_addr = env::var("MS_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3002".to_string());
    // RC URL is now mandatory if params might need fetching
    let rc_url = env::var("MS_RC_URL").context(
        "Missing MS_RC_URL environment variable. Needed for fetching params if not set in env.",
    )?;

    // --- Load/Fetch System Parameters ---
    println!("Loading system parameters...");
    let params: SystemParameters;

    // Try loading all params from environment variables first
    let p_hex_env = env::var("MS_PARAMS_P_HEX");
    let p_pub_hex_env = env::var("MS_PARAMS_P_PUB_HEX");
    let p_pub_hat_hex_env = env::var("MS_PARAMS_P_PUB_HAT_HEX");
    let g_hex_env = env::var("MS_PARAMS_G_HEX");

    if let (Ok(p_hex), Ok(p_pub_hex), Ok(p_pub_hat_hex), Ok(g_hex)) =
        (p_hex_env, p_pub_hex_env, p_pub_hat_hex_env, g_hex_env)
    {
        // All params found in environment, deserialize them
        println!("Found all parameters in environment variables. Deserializing...");
        params = SystemParameters {
            p: hex_to_ark(&p_hex).context("Failed to load param P from env var")?,
            p_pub: hex_to_ark(&p_pub_hex).context("Failed to load param Ppub from env var")?,
            p_pub_hat: hex_to_ark(&p_pub_hat_hex)
                .context("Failed to load param Ppub_hat from env var")?,
            g: hex_to_ark(&g_hex).context("Failed to load param G from env var")?,
        };
        println!("Parameters loaded successfully from environment.");
    } else {
        // One or more parameter environment variables missing, fetch from RC
        println!(
            "One or more parameter environment variables missing. Fetching from RC at {}...",
            rc_url
        );
        let client = reqwest::Client::new();
        let params_rc_url = format!("{}/params", rc_url);
        let resp = client.get(&params_rc_url).send().await.context(format!(
            "Failed to connect to RC params endpoint: {}",
            params_rc_url
        ))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read body".into());
            return Err(anyhow!(
                "RC returned error status {} when fetching params: {}",
                status,
                body
            ));
        }

        let params_resp: RcSystemParametersResponse = resp
            .json()
            .await
            .context("Failed to parse JSON params response from RC")?;

        println!("Deserializing parameters received from RC...");
        params = SystemParameters {
            p: hex_to_ark(&params_resp.p_hex).context("Failed to load param P from RC response")?,
            p_pub: hex_to_ark(&params_resp.p_pub_hex)
                .context("Failed to load param Ppub from RC response")?,
            p_pub_hat: hex_to_ark(&params_resp.p_pub_hat_hex)
                .context("Failed to load param Ppub_hat from RC response")?,
            g: hex_to_ark(&params_resp.g_hex).context("Failed to load param G from RC response")?,
        };
        println!("Parameters loaded successfully from RC.");
    }

    // --- Load Server Secret Key (must be present in env) ---
    println!("Loading server secret key...");
    let ssk: ServerSecretKey;
    let ssk_sid_ms_hex_env = env::var("MS_SSK_SID_MS_HEX");

    if let Ok(ssk_hex) = ssk_sid_ms_hex_env {
        // Key found in environment, deserialize it
        println!("Found server key in environment variable MS_SSK_SID_MS_HEX. Deserializing...");
        ssk = ServerSecretKey {
            sid_ms: hex_to_ark(&ssk_hex)
                .context("Failed to load server key SIDms (G2) from env var")?,
        };
        println!("Server secret key loaded successfully from environment.");
    } else {
        // Key not found in environment, register with RC to get it
        println!(
            "Server key not found in environment. Registering with RC at {}...",
            rc_url
        );
        let client = reqwest::Client::new();
        let register_url = format!("{}/register/server", rc_url);

        #[derive(Serialize)] // Need Serialize for the request body
        struct RegisterPayload<'a> {
            id: &'a str,
        }
        let payload = RegisterPayload { id: &server_id };

        let resp = client
            .post(&register_url)
            .json(&payload)
            .send()
            .await
            .context(format!(
                "Failed to send registration request to RC: {}",
                &register_url
            ))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read body".into());
            return Err(anyhow!(
                "RC returned error status {} during server registration: {}",
                status,
                body
            ));
        }

        let reg_resp: RcServerRegistrationResponse = resp
            .json()
            .await
            .context("Failed to parse JSON registration response from RC")?;

        println!("Successfully registered with RC. Deserializing received key...");
        ssk = ServerSecretKey {
            sid_ms: hex_to_ark(&reg_resp.sid_ms_hex)
                .context("Failed to load server key SIDms (G2) from RC response")?,
        };
        println!("Server secret key obtained successfully from RC.");
        // --- Optional: Save the key ---
        // If you wanted persistence, here you would write reg_resp.sid_ms_hex
        // to a file or update the .env file programmatically (more complex).
        // println!("Optional: Consider saving this key hex to MS_SSK_SID_MS_HEX env var for next time: {}", reg_resp.sid_ms_hex);
    }

    // --- Initialize state (using loaded config) ---
    let ms_state = MsState {
        inner: Arc::new(RwLock::new(InnerMsState {
            server_id, // Loaded from env
            params,    // Loaded from env or fetched from RC
            ssk,       // Loaded from env
            rng: StdRng::seed_from_u64(67890u64),
        })),
    };

    // --- Build Axum app ---
    let app = Router::new()
        .route("/auth/initiate", post(handle_auth_request))
        .with_state(ms_state);

    // --- Run the server ---
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    println!("MS Server listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}
// --- Custom Error Type for Axum (same as in RC app) ---
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        eprintln!("Error occurred: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR, // Or map specific errors (e.g., Bad Request for deserialization)
            format!("Error: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
