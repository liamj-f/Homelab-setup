#!/bin/bash
# Installs the GitHub CLI so `git push`/`pull` and `gh auth login` work from
# a terminal inside code-server, without a one-off manual install each time
# the container is recreated. Runs on every container start (linuxserver's
# custom-cont-init.d convention) - guarded so it's a no-op once gh is present.
set -e

if ! command -v gh >/dev/null 2>&1; then
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg
  apt-get update -qq
  apt-get install -y --no-install-recommends gh
  rm -rf /var/lib/apt/lists/*
fi
