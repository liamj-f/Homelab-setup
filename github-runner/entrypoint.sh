#!/bin/bash
set -e

cd /actions-runner

# Hardcoded defaults
WORKDIR="/runner_data"
LABELS="self-hosted,linux,arm64,pi4"
RUNNER_NAME="pi4-runner"

if [ -z "${REPO_URL}" ]; then
  echo "❌ ERROR: REPO_URL environment variable is required"
  exit 1
fi

if [ -z "${RUNNER_TOKEN}" ]; then
  echo "❌ ERROR: RUNNER_TOKEN environment variable is required"
  exit 1
fi

echo "📦 Configuring GitHub Runner..."
./config.sh \
  --url "${REPO_URL}" \
  --token "${RUNNER_TOKEN}" \
  --name "${RUNNER_NAME}" \
  --work "${WORKDIR}" \
  --labels "${LABELS}" \
  --unattended \
  --replace

echo "🚀 Starting runner..."
exec ./bin/Runner.Listener run --startuptype service
