#!/bin/bash
export DATABASE_URL="postgres://dirextalk:dirextalk_pass@localhost:15433/dirextalk?sslmode=disable"
export SERVICE_TOKEN_FILE="$PWD/../tokens/ms-to-agent.token"
export INSTANCE_ID="agent-local-001"

./dirextalk-agent --config=config.yaml serve
