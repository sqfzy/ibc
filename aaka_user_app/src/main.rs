use anyhow::{Context, Result, anyhow};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use clap::Parser;
use dotenvy::dotenv;
use ibc_aaka_scheme::{ServerAuthResponse, SystemParameters, UserSecretKey, user};
use serde::{Deserialize, Serialize}; // Add Serialize for saving UserKeyData
use std::{fs, path::PathBuf}; // Add fs and PathBuf for file operations

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
// fn ark_to_hex<T: CanonicalSerialize>(item: &T) -> Result<String> {
//     let mut buffer = Vec::new();
//     item.serialize_compressed(&mut buffer)
//         .map_err(|e| anyhow!("Ark Serialization failed: {}", e))?;
//     Ok(hex::encode(buffer))
// }

// --- Function to load or register user key ---
async fn load_or_register_user_key(args: &Args, client: &reqwest::Client) -> Result<UserKeyData> {
    if !args.force_register && args.key_file.exists() {
        println!("Attempting to load user key from file: {:?}", args.key_file);
        let content = fs::read_to_string(&args.key_file)
            .context(format!("Failed to read key file: {:?}", args.key_file))?;
        let stored_data: UserKeyData = serde_json::from_str(&content).context(format!(
            "Failed to parse JSON from key file: {:?}",
            args.key_file
        ))?;

        // Optional: Verify if the stored ID matches the requested ID
        if stored_data.user_id == args.user_id {
            println!("User key loaded successfully for '{}'.", args.user_id);
            return Ok(stored_data);
        } else {
            println!(
                "Warning: Key file exists but for a different user ID ({} vs {}). Proceeding with registration.",
                stored_data.user_id, args.user_id
            );
            // Fall through to registration
        }
    }

    // Key file doesn't exist, doesn't match, or force_register is true
    println!(
        "Registering user '{}' with RC at {}...",
        args.user_id, args.rc_url
    );
    let register_url = format!("{}/register/user", args.rc_url);

    #[derive(Serialize)]
    struct RegisterPayload<'a> {
        id: &'a str,
    }
    let payload = RegisterPayload { id: &args.user_id };

    let resp = client
        .post(&register_url)
        .json(&payload)
        .send()
        .await
        .context(format!(
            "Failed to send user registration request to RC: {}",
            register_url
        ))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read body".into());
        return Err(anyhow!(
            "RC returned error status {} during user registration: {}",
            status,
            body
        ));
    }

    let reg_resp: RcUserRegistrationResponse = resp
        .json()
        .await
        .context("Failed to parse JSON user registration response from RC")?;

    println!("User registered successfully.");

    let new_key_data = UserKeyData {
        user_id: args.user_id.clone(),
        key_info: reg_resp.clone(), // Clone response for saving
    };

    // Attempt to save the new key data
    match serde_json::to_string_pretty(&new_key_data) {
        Ok(json_content) => match fs::write(&args.key_file, json_content) {
            Ok(_) => println!("User key saved to file: {:?}", args.key_file),
            Err(e) => println!(
                "Warning: Failed to save user key to file {:?}: {}",
                args.key_file, e
            ),
        },
        Err(e) => println!(
            "Warning: Failed to serialize user key data for saving: {}",
            e
        ),
    }

    Ok(new_key_data) // Return the newly obtained key data
}

// --- Main Application Logic ---

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let args = Args::parse();

    // --- Initialize HTTP client ---
    let client = reqwest::Client::new();

    // --- Step 1: Load/Fetch System Parameters ---
    println!("Fetching system parameters from RC at {}...", args.rc_url);
    let params_rc_url = format!("{}/params", args.rc_url);
    let params_resp: RcSystemParametersResponse = client
        .get(&params_rc_url)
        .send()
        .await
        .context(format!("Failed to get params from RC: {}", params_rc_url))?
        .json()
        .await
        .context("Failed to parse params JSON from RC")?;

    let params = SystemParameters {
        p: hex_to_ark(&params_resp.p_hex)?,
        p_pub: hex_to_ark(&params_resp.p_pub_hex)?,
        p_pub_hat: hex_to_ark(&params_resp.p_pub_hat_hex)?,
        g: hex_to_ark(&params_resp.g_hex)?,
    };
    println!("System parameters loaded successfully.");

    // --- Step 2: Load or Register User Key ---
    let user_key_data = load_or_register_user_key(&args, &client).await?;

    // Deserialize the loaded/fetched user key
    let usk = UserSecretKey {
        r_u: hex_to_ark(&user_key_data.key_info.r_u_hex)?,
        sid_u: hex_to_ark(&user_key_data.key_info.sid_u_hex)?,
    };

    // --- Step 3: Initiate Authentication (Call Core Lib) ---
    // (Logic remains the same, uses loaded usk and params)
    let mut rng = StdRng::seed_from_u64(99999u64);
    let (_, user_state) = user::initiate_authentication(
        &usk,
        args.user_id.as_bytes(),
        args.server_id.as_bytes(),
        &params,
        &mut rng,
    )
    .context("Failed to initiate authentication")?;

    println!(
        "Initiating authentication for user '{}' with server '{}'...",
        args.user_id, args.server_id
    );

    // --- Step 4: Send Request to MS (Serialize to JSON with hex) ---
    // (Logic remains the same)
    #[derive(Serialize)]
    struct AuthRequestPayloadForSend {/* ... */}
    let request_payload = AuthRequestPayloadForSend { /* ... */ }; // Populate from request
    // ...
    let ms_auth_url = format!("http://{}/auth/initiate", args.ms_addr);
    println!("Sending request to: {}", ms_auth_url);
    let res = client
        .post(&ms_auth_url)
        .json(&request_payload)
        .send()
        .await?; // Simplified error handling

    // --- Step 5: Process Response from MS ---
    // (Logic remains the same)
    if res.status().is_success() {
        let success_resp: MsAuthSuccessResponse = res.json().await?; // Simplified
        println!(
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
            args.server_id.as_bytes(),
            &params,
            args.key_len,
        );
        match user_session_key_result {
            Ok(_) => {
                println!("SUCCESS: Session keys match!");
                std::process::exit(0);
            }
            Err(e) => {
                // ... (print error, exit 1) ...
                eprintln!("ERROR: Failed to process server response: {:?}", e);
                std::process::exit(1);
            }
        }
    } else {
        // ... (Handle MS error response, exit 1) ...
        eprintln!("ERROR: MS returned error status {}", res.status());
        std::process::exit(1);
    }
}
