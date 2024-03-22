#!/bin/bash

# Define the path to your Go executable
EXECUTABLE="./jmessage_client"

# Define variables for all the flags for easier modification
ATTACH_DIR="./JMESSAGE_DOWNLOADS"
DOMAIN="localhost"
PASSWORD="1234"
PORT=8080
USERNAME="dorian"
# USERNAME="matthew"

# Add boolean flags as needed. Uncomment to enable.
NOTLS="-notls" # Uncomment this line to use HTTP
#HEADLESS="-headless" # Uncomment for headless mode
REG="-reg"             # Uncomment to register a new username and password
STRICTTLS="-stricttls" # Uncomment to disallow self-signed certificates

# Construct the command with all flags
CMD_REG="$EXECUTABLE -domain $DOMAIN -port $PORT -username $REG $USERNAME -password $PASSWORD "
CMD_LOGIN="$EXECUTABLE -domain $DOMAIN -port $PORT -username $USERNAME -password $PASSWORD"

# Run the command
# CMD=$CMD_REG
CMD=$CMD_LOGIN

echo "Running command: $CMD"
$CMD

# Note: Remove or comment out the echo line above in a production script for security reasons, especially if passwords are involved.
