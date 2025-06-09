use anyhow::{Context, Result, anyhow};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use clap::Parser;
use dotenvy::dotenv;
use ibc_aaka_scheme::{ServerAuthResponse, SystemParameters, UserSecretKey, user};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use tracing::{error, info, warn}; // Add Serialize for saving UserKeyData // Add fs and PathBuf for file operations

// --- Command Line Arguments (remain the same) ---
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    user_id: String,
    #[arg(short, long)]
    server_id: String,
    #[arg(long, env = "MS_RC_URL", default_value = "http://localhost:3001")]
    rc_url: String,
    #[arg(long, env = "MS_LISTEN_ADDR", default_value = "localhost:3002")]
    ms_addr: String,
    /// Path to store/load the user's key file (JSON format)
    #[arg(long, default_value = "user_key.json")]
    key_file: PathBuf,
    /// Force re-registration with RC, ignoring existing key file
    #[arg(long, default_value_t = false)]
    force_register: bool,
    #[arg(long, default_value_t = 32)]
    key_len: usize,
}

#[derive(Debug, Deserialize)]
struct Config {
    ms_id: String,
    user_id: String,
    rc_url: String,
    ms_url: String,
    key_file: PathBuf,
    key_len: usize,
}

// --- Data Structures for Communication (remain the same) ---
#[derive(Deserialize, Debug)]
struct RcSystemParametersResponse {
    p_hex: String,
    p_pub_hex: String,
    p_pub_hat_hex: String,
    g_hex: String,
}

#[derive(Deserialize, Debug, Serialize, Clone)] // Add Serialize, Clone for saving
struct RcUserRegistrationResponse {
    r_u_hex: String,
    sid_u_hex: String,
}

#[derive(Deserialize, Debug)]
struct MsAuthResponsePayload {
    t_hex: String,
    y_hex: String,
    timestamp: u64,
}

#[derive(Deserialize, Debug)]
struct MsAuthSuccessResponse {
    message: String,
    response: MsAuthResponsePayload,
    // session_key_hex: String, // From MS (DEMO ONLY)
}

// --- Structure for storing user key data locally ---
#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserKeyData {
    user_id: String, // Store ID for verification
    key_info: RcUserRegistrationResponse,
}

// --- Utility Functions (remain the same) ---
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

// --- Function to load or register user key ---
async fn load_or_register_user_key(
    config: &Config,
    client: &reqwest::Client,
) -> Result<UserKeyData> {
    // FIX: 
    // if config.key_file.exists() {
    if false {
        info!(
            "Attempting to load user key from file: {:?}",
            config.key_file
        );
        let content = fs::read_to_string(&config.key_file)
            .context(format!("Failed to read key file: {:?}", config.key_file))?;
        let stored_data: UserKeyData = serde_json::from_str(&content).context(format!(
            "Failed to parse JSON from key file: {:?}",
            config.key_file
        ))?;

        // Optional: Verify if the stored ID matches the requested ID
        if stored_data.user_id == config.user_id {
            info!("User key loaded successfully for '{}'.", config.user_id);
            return Ok(stored_data);
        } else {
            warn!(
                "Key file exists but for a different user ID ({} vs {}). Proceeding with registration.",
                stored_data.user_id, config.user_id
            );
            // Fall through to registration
        }
    }

    // Key file doesn't exist, doesn't match, or force_register is true
    info!(
        "Registering user '{}' with RC at {}...",
        config.user_id, config.rc_url
    );
    let register_url = format!("{}/register/user", config.rc_url);

    #[derive(Serialize)]
    struct RegisterPayload<'a> {
        id: &'a str,
    }
    let payload = RegisterPayload {
        id: &config.user_id,
    };

    let resp = client
        .post(&register_url)
        .json(&payload)
        .send()
        .await
        .context(format!(
            "Failed to send user registration request to RC: {register_url}",
        ))?
        .error_for_status()?;

    let reg_resp: RcUserRegistrationResponse = resp
        .json()
        .await
        .context("Failed to parse JSON user registration response from RC")?;

    info!("User registered successfully.");

    let new_key_data = UserKeyData {
        user_id: config.user_id.clone(),
        key_info: reg_resp.clone(), // Clone response for saving
    };

    // Attempt to save the new key data
    match serde_json::to_string_pretty(&new_key_data) {
        Ok(json_content) => match fs::write(&config.key_file, json_content) {
            Ok(_) => info!("User key saved to file: {:?}", config.key_file),
            Err(e) => warn!(
                "Failed to save user key to file {:?}: {}",
                config.key_file, e
            ),
        },
        Err(e) => warn!("Failed to serialize user key data for saving: {}", e),
    }

    Ok(new_key_data) // Return the newly obtained key data
}

// --- Main Application Logic ---

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config: Config = serde_json::from_str(&std::fs::read_to_string("config.json")?)
        .context("Failed to parse configuration from file")?;

    // --- Initialize HTTP client ---
    let client = reqwest::Client::new();

    // --- Step 1: Load/Fetch System Parameters ---
    info!("Fetching system parameters from RC at {}...", config.rc_url);
    let params_rc_url = format!("{}/params", config.rc_url);

    let params_resp: RcSystemParametersResponse = client
        .get(&params_rc_url)
        .send()
        .await
        .context(format!("Failed to get params from RC: {params_rc_url}"))?
        .error_for_status()?
        .json()
        .await
        .context("Failed to parse params JSON from RC")?;
    info!("System parameters fetched successfully.");

    let params = SystemParameters {
        p: hex_to_ark(&params_resp.p_hex)?,
        p_pub: hex_to_ark(&params_resp.p_pub_hex)?,
        p_pub_hat: hex_to_ark(&params_resp.p_pub_hat_hex)?,
        g: hex_to_ark(&params_resp.g_hex)?,
    };

    // --- Step 2: Load or Register User Key ---
    info!(
        "Loading or registering user key for '{}' with RC at {}...",
        config.user_id, config.rc_url
    );
    let user_key_data = load_or_register_user_key(&config, &client).await?;

    // Deserialize the loaded/fetched user key
    let usk = UserSecretKey {
        r_u: hex_to_ark(&user_key_data.key_info.r_u_hex)?,
        sid_u: hex_to_ark(&user_key_data.key_info.sid_u_hex)?,
    };

    // --- Step 3: Initiate Authentication (Call Core Lib) ---
    // (Logic remains the same, uses loaded usk and params)
    let mut rng = StdRng::from_entropy();
    let (request, user_state) = user::initiate_authentication(
        &usk,
        config.user_id.as_bytes(),
        config.ms_id.as_bytes(),
        &params,
        &mut rng,
    )
    .context("Failed to initiate authentication")?;

    info!("Authentication request generated successfully.");

    // --- Step 4: Send Request to MS (Serialize to JSON with hex) ---
    // (Logic remains the same)
    #[derive(Serialize)]
    struct AuthRequestPayloadForSend {
        m_hex: String,
        n: String,
        sigma_hex: String,
        timestamp: u64,
    }

    let request_payload = AuthRequestPayloadForSend {
        m_hex: ark_to_hex(&request.m)?,
        n: hex::encode(&request.n),
        sigma_hex: ark_to_hex(&request.sigma)?,
        timestamp: request.timestamp,
    };

    info!("Sending authentication request to MS...");

    let ms_auth_url = format!("{}/auth/initiate", config.ms_url);
    let res = client
        .post(&ms_auth_url)
        .json(&request_payload)
        .send()
        .await?
        .error_for_status()?;

    info!(
        "Authentication request sent successfully to MS at {}",
        ms_auth_url
    );

    // --- Step 5: Process Response from MS ---
    let success_resp: MsAuthSuccessResponse = res.json().await?; // Simplified
    info!(
        "Received successful response from MS: {}",
        success_resp.message
    );

    // Deserialize the inner response payload
    let server_response_data = ServerAuthResponse {
        t: hex_to_ark(&success_resp.response.t_hex)?,
        y: hex_to_ark(&success_resp.response.y_hex)?,
        timestamp: success_resp.response.timestamp,
    };

    let user_session_key_result = user::process_server_response(
        &usk,
        &user_state,
        &server_response_data,
        config.ms_id.as_bytes(),
        &params,
        config.key_len,
    );
    match user_session_key_result {
        Ok(key) => {
            info!("SUCCESS: Client Session key is {:?}", hex::encode(&key.0));
            std::process::exit(0);
        }
        Err(e) => {
            // ... (print error, exit 1) ...
            error!("ERROR: Failed to process server response: {:?}", e);
            std::process::exit(1);
        }
    }
}
