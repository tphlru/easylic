#!/bin/bash
set -e

# Generate server keys if they don't exist
if [ ! -f "easylic/server/server_private.key" ] || [ ! -f "easylic/server/server_public.key" ]; then
    echo "Generating server keys..."
    easylic keygen
else
    echo "Server keys already exist, skipping generation"
fi

# Start the server
exec uvicorn easylic.server.core:app --host 0.0.0.0 --port 8000