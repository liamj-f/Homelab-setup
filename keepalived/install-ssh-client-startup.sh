#!/usr/bin/env sh
# osixia baseimage custom startup script - runs once as root when the
# container starts, before keepalived's own services come up. The
# osixia/keepalived image ships only curl, not an ssh client, but notify.sh
# needs ssh to stop containers on the peer node during failover.
set -e

if ! command -v ssh >/dev/null 2>&1; then
  apk add --no-cache openssh-client
fi
