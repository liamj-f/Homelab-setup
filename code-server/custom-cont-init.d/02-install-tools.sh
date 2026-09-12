#!/bin/bash

set -e

chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list


apt-get update -qq
apt-get install -y --no-install-recommends git, tmux, gh

# Claude Code has no apt package - install it via Anthropic's native
# installer, run as the abc user (PUID/PGID-mapped, home /config) so the
# binary lands on that user's PATH instead of root's.
if ! su abc -c 'command -v claude' >/dev/null 2>&1; then
  su abc -c 'curl -fsSL https://claude.ai/install.sh | bash'
fi

su abc -c "git config --global user.name 'liamj-f'"
su abc -c "git config --global user.email 'liamjamesfagg+github@gmail.com'"
