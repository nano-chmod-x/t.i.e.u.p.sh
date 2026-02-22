#!/bin/bash

# ==============================================================================
# SCRIPT: api_interact.sh
# DESCRIPTION: A functional script to interact with a REST API using GET and POST.
# ==============================================================================

# [SAFE EXECUTION DIRECTIVES]
set -euo pipefail
trap 'echo -e "\n[!] Script interrupted by user. Exiting..."; exit 1' SIGINT SIGTERM

# [DEPENDENCY CHECK]
# We use 'jq' here to format the JSON output so it's readable in the terminal.
for cmd in curl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[ERROR] Required dependency '$cmd' not found."
        echo "Please install it (e.g., 'sudo apt install $cmd' or 'brew install $cmd')."
        exit 1
    fi
done

# [CONFIGURATION]
# Using your provided UUID as the Authorization token
API_KEY="96a7364a-8eb8-4ba5-9a9e-cc4c9c690fc7"
BASE_URL="https://jsonplaceholder.typicode.com"

echo "--- REST API INTERACTION SCRIPT ---"
echo "Targeting: $BASE_URL"
echo "-----------------------------------"

# ==============================================================================
# FUNCTION: Perform a GET Request (Fetch Data)
# ==============================================================================
fetch_data() {
    local endpoint=$1
    echo -e "\n\e[1;34m[GET]\e[0m Fetching data from /${endpoint}..."
    
    # curl flags: 
    # -s (silent, hides progress bar) 
    # -w (write-out, captures HTTP status code)
    # -o (output file, we pipe to jq instead)
    
    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X GET "${BASE_URL}/${endpoint}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Accept: application/json")

    # Extract the body and the status code
    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e "\e[32m[SUCCESS] Status: $HTTP_STATUS\e[0m"
        echo "$HTTP_BODY" | jq '.' | head -n 15
        echo "    ... (output truncated for readability)"
    else
        echo -e "\e[31m[FAILED] Status: $HTTP_STATUS\e[0m"
    fi
}

# ==============================================================================
# FUNCTION: Perform a POST Request (Send Data)
# ==============================================================================
send_data() {
    local endpoint=$1
    local payload=$2
    echo -e "\n\e[1;34m[POST]\e[0m Sending payload to /${endpoint}..."
    
    HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "${BASE_URL}/${endpoint}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "${payload}")

    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    # 201 is the standard HTTP status for "Created"
    if [ "$HTTP_STATUS" -eq 201 ] || [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e "\e[32m[SUCCESS] Status: $HTTP_STATUS\e[0m"
        echo -e "Server responded with:"
        echo "$HTTP_BODY" | jq '.'
    else
        echo -e "\e[31m[FAILED] Status: $HTTP_STATUS\e[0m"
        echo "$HTTP_BODY"
    fi
}

# [EXECUTION PHASE]

# 1. Test a GET request (Fetching a single simulated forum post)
fetch_data "posts/1"

sleep 1

# 2. Test a POST request (Simulating sending a prompt to an AI or creating a database entry)
# JSON payloads require strict formatting with double quotes.
PROMPT_PAYLOAD=$(cat <<EOF
{
  "title": "Terminal Request",
  "body": "Initialize system diagnostics using key $API_KEY.",
  "userId": 99
}
EOF
)

send_data "posts" "$PROMPT_PAYLOAD"

echo -e "\n\e[1;32m[COMPLETE]\e[0m Interaction cycle finished gracefully."
