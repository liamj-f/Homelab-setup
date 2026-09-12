#!/bin/bash
# Installs the dev tools used from a code-server terminal - gh, tmux, git,
# Claude Code - and configures git identity + gh auth. Runs on every
# container start (linuxserver's custom-cont-init.d convention); each step
# is guarded/idempotent so re-running it is a no-op once done.
set -e

# gh has no package in Ubuntu/Debian's default repos - GitHub only ships it
# through their own apt repo, so the keyring + source list must be added
# before apt can see it at all. Once that's done it's a normal apt package,
# so it installs alongside tmux/git in the same apt-get install below.
if ! command -v gh >/dev/null 2>&1; then
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg
  chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list
fi


MISSING_PKGS=()
command -v gh   >/dev/null 2>&1 || MISSING_PKGS+=(gh)
command -v tmux >/dev/null 2>&1 || MISSING_PKGS+=(tmux)
command -v git  >/dev/null 2>&1 || MISSING_PKGS+=(git)

if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
  apt-get update -qq
  apt-get install -y --no-install-recommends "${MISSING_PKGS[@]}"
  rm -rf /var/lib/apt/lists/*
fi

# Claude Code has no apt package, or a repo to add one - install it via
# Anthropic's native installer, run as the abc user (PUID/PGID-mapped,
# home /config) so the binary lands on that user's PATH instead of root's.
if ! su abc -c 'command -v claude' >/dev/null 2>&1; then
  su abc -c 'curl -fsSL https://claude.ai/install.sh | bash'
fi

# Git identity for commits made from code-server, and a check that gh is
# authenticated - both idempotent, safe to run every start.
su abc -c "git config --global user.name 'liamj-f'"
su abc -c "git config --global user.email 'liamjamesfagg+github@gmail.com'"
