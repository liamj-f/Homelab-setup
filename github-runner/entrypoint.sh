#!/bin/bash
set -e

cd /actions-runner

# Register runner
./config.sh \
  --url "https://github.com/liamj-f/rpi4-docker" \
  --token "${RUNNER_TOKEN}" \
  --name "pi4-runner" \
  --work "_work" \
  --labels "self-hosted,linux,arm64" \
  --unattended \
  --replace

# Start runner
exec ./bin/Runner.Listener run --startuptype service
