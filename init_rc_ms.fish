echo "--- Starting AAKA Protocol Test ---"

# Configuration (adjust paths if needed)
set RC_BIN target/debug/aaka_rc_app
set MS_BIN target/debug/aaka_ms_server
set USER_BIN target/debug/aaka_user_app
set ENV_FILE .env

# User and Server IDs for testing
set USER_ID "testuser@fish.test"
set SERVER_ID "testserver.fish.test"

# Clean up previous run (optional)
# pkill -f aaka_rc_app
# pkill -f aaka_ms_server
# rm -f $ENV_FILE # Careful, this deletes the file! Only if you want to recreate it.

# --- Build Projects ---
echo "Building projects..."
cargo build
if test $status -ne 0
    echo "Build failed!"
    exit 1
end

# --- Step 1: Setup/Start RC ---
echo "Starting RC Server in background..."
# Start RC and capture its PID
$RC_BIN &
set RC_PID $last_pid
echo "RC PID: $RC_PID"
# Give RC a moment to start
sleep 2

# Check if RC started (very basic check)
if not ps -p $RC_PID > /dev/null
    echo "RC Server failed to start!"
    exit 1
end

# --- Step 2: Call RC API to Setup and Register ---
# Use curl to interact with RC API
set RC_URL (echo "http://localhost:3001") # Read from .env or default

echo "Running RC Setup via API ($RC_URL)..."
curl -s -X POST $RC_URL/setup > /dev/null # Discard output, just need it to run
if test $status -ne 0; echo "RC Setup failed!"; pkill -P $RC_PID; exit 1; end

echo "Fetching parameters from RC..."
set PARAMS_JSON (curl -s $RC_URL/params)
if test $status -ne 0; echo "Failed to get params from RC!"; pkill -P $RC_PID; exit 1; end
# Extract hex values using jq (install jq if you don't have it: sudo apt install jq / brew install jq)
# Or use basic string manipulation if jq is not available
set PARAMS_P_HEX (echo $PARAMS_JSON | jq -r .p_hex)
set PARAMS_P_PUB_HEX (echo $PARAMS_JSON | jq -r .p_pub_hex)
set PARAMS_P_PUB_HAT_HEX (echo $PARAMS_JSON | jq -r .p_pub_hat_hex)
set PARAMS_G_HEX (echo $PARAMS_JSON | jq -r .g_hex)
echo "Params P(G1) hex: $PARAMS_P_HEX" # Verify extraction

echo "Registering user '$USER_ID' with RC..."
set USER_REG_JSON (curl -s -X POST -H "Content-Type: application/json" -d "{\"id\": \"$USER_ID\"}" $RC_URL/register/user)
if test $status -ne 0; echo "Failed to register user!"; pkill -P $RC_PID; exit 1; end
set USK_R_U_HEX (echo $USER_REG_JSON | jq -r .r_u_hex)
set USK_SID_U_HEX (echo $USER_REG_JSON | jq -r .sid_u_hex)
echo "User Ru(G1) hex: $USK_R_U_HEX" # Verify extraction

echo "Registering server '$SERVER_ID' with RC..."
set SERVER_REG_JSON (curl -s -X POST -H "Content-Type: application/json" -d "{\"id\": \"$SERVER_ID\"}" $RC_URL/register/server)
if test $status -ne 0; echo "Failed to register server!"; pkill -P $RC_PID; exit 1; end
set SSK_SID_MS_HEX (echo $SERVER_REG_JSON | jq -r .sid_ms_hex)
echo "Server SIDms(G2) hex: $SSK_SID_MS_HEX" # Verify extraction

# --- Step 3: Setup .env for MS (or pass via env vars) ---
# Option A: Create/Update .env (ensure MS reads this specific .env)
# Make sure the .env file used by MS app contains these values
# This script assumes MS app reads the same .env or gets vars passed
echo "Updating .env file for MS (or ensure MS reads these env vars)..."
# (This part might need adjustment based on how MS loads config.
#  Simplest might be to pass directly as environment variables in step 4)

# --- Step 4: Start MS Server ---
echo "Starting MS Server in background..."
# Pass necessary config as environment variables
set -x MS_SERVER_ID $SERVER_ID
set -x MS_PARAMS_P_HEX $PARAMS_P_HEX
set -x MS_PARAMS_P_PUB_HEX $PARAMS_P_PUB_HEX
set -x MS_PARAMS_P_PUB_HAT_HEX $PARAMS_P_PUB_HAT_HEX
set -x MS_PARAMS_G_HEX $PARAMS_G_HEX
set -x MS_SSK_SID_MS_HEX $SSK_SID_MS_HEX
# MS_LISTEN_ADDR and MS_RC_URL can also be set if needed, otherwise defaults are used

$MS_BIN &
set MS_PID $last_pid
# Unset temporary env vars if desired
set -e MS_SERVER_ID MS_PARAMS_P_HEX MS_PARAMS_P_PUB_HEX MS_PARAMS_P_PUB_HAT_HEX MS_PARAMS_G_HEX MS_SSK_SID_MS_HEX
echo "MS PID: $MS_PID"
sleep 2

if not ps -p $MS_PID > /dev/null
    echo "MS Server failed to start!"
    pkill -P $RC_PID # Kill RC before exiting
    exit 1
end

wait
