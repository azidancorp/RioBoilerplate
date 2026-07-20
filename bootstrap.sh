#!/usr/bin/env bash
# Create the initial verified root user. Forwards all flags to
# app.scripts.bootstrap_root (e.g. --email, --password, --strict).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$REPO_ROOT/venv/bin/activate" ]]; then
    echo "ERROR: venv not found at $REPO_ROOT/venv." \
        "Create it first: python -m venv venv && source venv/bin/activate" \
        "&& python -m pip install --require-hashes -r requirements-dev.txt" >&2
    exit 1
fi

source "$REPO_ROOT/venv/bin/activate"
cd "$REPO_ROOT/app"
exec python -m app.scripts.bootstrap_root "$@"
