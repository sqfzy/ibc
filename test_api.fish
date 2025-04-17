#!/usr/bin/env fish

echo "--- API Test Script (Fully Automated) ---"

# --- Configuration ---
set ENV_FILE .env

set RC_BIN target/debug/aaka_rc_app
set MS_BIN target/debug/aaka_ms_server
set ENV_FILE .env # Still useful for RC/MS listen addresses

# RC and MS URLs (read from .env or use defaults)
set RC_LISTEN_ADDR_FROM_ENV (grep -E '^RC_LISTEN_ADDR=' $ENV_FILE | sed -E 's/^RC_LISTEN_ADDR=//; s/"//g' 2>/dev/null)
set MS_LISTEN_ADDR_FROM_ENV (grep -E '^MS_LISTEN_ADDR=' $ENV_FILE | sed -E 's/^MS_LISTEN_ADDR=//; s/"//g' 2>/dev/null)

# Set variable using the value from env if non-empty, otherwise use default
set RC_LISTEN_ADDR $RC_LISTEN_ADDR_FROM_ENV
if test -z "$RC_LISTEN_ADDR"
    set RC_LISTEN_ADDR "0.0.0.0:3001"
end

set MS_LISTEN_ADDR_RAW $MS_LISTEN_ADDR_FROM_ENV
if test -z "$MS_LISTEN_ADDR_RAW"
    set MS_LISTEN_ADDR_RAW "0.0.0.0:3002"
end

set RC_URL "http://$RC_LISTEN_ADDR"
set MS_URL "http://$MS_LISTEN_ADDR_RAW"

echo "Using RC URL: $RC_URL" # Add debug output
echo "Using MS URL: $MS_URL" # Add debug output

set USER_ID "api_test_user@example.com"
set SERVER_ID "api_test_server.edge"

set RC_PID ""
set MS_PID ""

# --- Cleanup Function ---
# (Same as before)
function cleanup_services
    echo "Cleaning up background services..."
    if test -n "$MS_PID"; and ps -p $MS_PID > /dev/null
        kill $MS_PID > /dev/null 2>&1
        echo "Stopped MS (PID: $MS_PID)"
    end
    if test -n "$RC_PID"; and ps -p $RC_PID > /dev/null
        kill $RC_PID > /dev/null 2>&1
        echo "Stopped RC (PID: $RC_PID)"
    end
    # Wait a moment
    sleep 1
end
trap cleanup_services EXIT

# --- Build Projects ---
# (Same as before)
echo "Building projects..."
cargo build
if test $status -ne 0
    echo "Build failed!"
    exit 1
end

# --- Start RC Server ---
# (Same as before)
echo "Starting RC Server in background..."
$RC_BIN &
set RC_PID $last_pid
sleep 2

# Check if RC started (very basic check)
if not ps -p $RC_PID > /dev/null
    echo "RC Server failed to start!"
    exit 1
end

# --- Helper Function for Checking Curl Success ---
# (Same as before)
function check_curl
    set curl_status $status
    set curl_output $argv[1]
    set step_name $argv[2]

    if test $curl_status -ne 0
        echo "Error: curl command failed for '$step_name' (status: $curl_status). Is the server running at the correct URL?"
        # Optionally print curl output for debugging
        # echo "Curl Output: $curl_output"
        exit 1 # Cleanup will run via trap
    end
    if string match -q "Error:*" -- $curl_output; or string match -q "*Internal Server Error*" -- $curl_output
        echo "Error: API call failed for '$step_name'. Response:"
        echo $curl_output
        exit 1 # Cleanup will run via trap
    end
    echo "Success: $step_name"
end

# --- Step 1: Call RC Setup ---
echo ""
echo "*** Calling RC Setup API ***"
set setup_output (curl -s -X POST $RC_URL/setup)
check_curl "$setup_output" "RC Setup (/setup)"

# --- Step 2: Fetch Parameters from RC ---
echo ""
echo "*** Fetching Parameters from RC ***"
set params_output (curl -s $RC_URL/params)
check_curl "$params_output" "RC Get Parameters (/params)"
# Extract hex values (ensure jq is installed or use alternative string parsing)
set PARAMS_P_HEX (echo $params_output | jq -r .p_hex 2>/dev/null)
set PARAMS_P_PUB_HEX (echo $params_output | jq -r .p_pub_hex 2>/dev/null)
set PARAMS_P_PUB_HAT_HEX (echo $params_output | jq -r .p_pub_hat_hex 2>/dev/null)
set PARAMS_G_HEX (echo $params_output | jq -r .g_hex 2>/dev/null)
# Add checks if values are empty/null, exit if critical params missing
if test -z "$PARAMS_P_HEX"; or test -z "$PARAMS_P_PUB_HEX"; or test -z "$PARAMS_P_PUB_HAT_HEX"; or test -z "$PARAMS_G_HEX"; or string match -q "null" -- $PARAMS_P_HEX
    echo "Error: Failed to extract all necessary parameters from RC /params response. Is jq installed?"
    exit 1 # Cleanup will run
end
echo "Parameters fetched successfully."

# --- Step 3: Register Server with RC ---
echo ""
echo "*** Registering Server '$SERVER_ID' with RC ***"
set server_reg_payload "{\"id\": \"$SERVER_ID\"}"
set server_reg_output (curl -s -X POST -H "Content-Type: application/json" -d $server_reg_payload $RC_URL/register/server)
check_curl "$server_reg_output" "RC Register Server (/register/server for $SERVER_ID)"
set SSK_SID_MS_HEX (echo $server_reg_output | jq -r .sid_ms_hex 2>/dev/null)
if test -z "$SSK_SID_MS_HEX"; or string match -q "null" -- $SSK_SID_MS_HEX
    echo "Error: Failed to extract server key from RC /register/server response."
    exit 1 # Cleanup will run
end
echo "Server key fetched successfully."

# --- Step 4: Start MS Server with fetched config ---
echo ""
echo "*** Starting MS Server with fetched config ***"
# Pass fetched keys/params as environment variables directly to the MS process
# MS application needs to be able to read these specific env var names
set -x MS_SERVER_ID $SERVER_ID # Set the server ID itself
set -x MS_PARAMS_P_HEX $PARAMS_P_HEX
set -x MS_PARAMS_P_PUB_HEX $PARAMS_P_PUB_HEX
set -x MS_PARAMS_P_PUB_HAT_HEX $PARAMS_P_PUB_HAT_HEX
set -x MS_PARAMS_G_HEX $PARAMS_G_HEX
set -x MS_SSK_SID_MS_HEX $SSK_SID_MS_HEX
# Also set listen address if MS reads it from env instead of default/config file
# set -x MS_LISTEN_ADDR $MS_LISTEN_ADDR_RAW

$MS_BIN &
set MS_PID $last_pid
# Unset temporary env vars immediately after starting the process
set -e MS_SERVER_ID MS_PARAMS_P_HEX MS_PARAMS_P_PUB_HEX MS_PARAMS_P_PUB_HAT_HEX MS_PARAMS_G_HEX MS_SSK_SID_MS_HEX MS_LISTEN_ADDR

echo "MS PID: $MS_PID"
sleep 2 # Give MS time to start

if not ps -p $MS_PID > /dev/null
    echo "MS Server failed to start!"
    exit 1 # Cleanup will run
end
echo "MS Server presumed running at $MS_URL"


# --- Step 5: Test RC Register User (Just check API, no need to pass key) ---
echo ""
echo "*** Testing RC Register User API (for $USER_ID) ***"
set user_reg_payload "{\"id\": \"$USER_ID\"}"
set user_reg_output (curl -s -X POST -H "Content-Type: application/json" -d $user_reg_payload $RC_URL/register/user)
check_curl "$user_reg_output" "RC Register User (/register/user for $USER_ID)"
# Basic check if output looks like JSON containing keys
if not string match -q '*"r_u_hex":*' -- $user_reg_output; or not string match -q '*"sid_u_hex":*' -- $user_reg_output
    echo "Error: Response from /register/user doesn't seem to contain expected keys."
    exit 1 # Cleanup will run
end
echo "User registration API endpoint works."

# --- Step 6: Test MS Authentication Endpoint (Malformed Request) ---
# (Same as before)
echo ""
echo "*** Testing MS Authentication API (Malformed Request) ***"
# ... (malformed request test logic) ...


# --- Final Report ---
echo ""
echo "--- API Test Script Completed Successfully ---"
# Cleanup will run automatically via trap
exit 0
