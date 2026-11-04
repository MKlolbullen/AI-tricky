#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
umask 077
if [[ ! -x .venv/bin/python ]]; then
    printf '%s\n' 'Create the environment first: python3 -m venv .venv' 'Then install requirements.txt (native) or requirements-cai.txt (CAI).'
    exit 1
fi
if [[ ! -f dist/client/index.html ]]; then
    printf '%s\n' 'Build the interface first: npm ci && npm run build'
    exit 1
fi
exec .venv/bin/python -m backend
