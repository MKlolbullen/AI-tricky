#!/usr/bin/env bash
#
# installation.sh — set up AI-tricky on this machine.
#
# This installs the local platform (web UI, FastAPI backend, SQLite history)
# and, optionally, the external security CLI tools used by the migrated
# mini-tricky catalog.
#
#   ./installation.sh                 # project setup + install all catalog tools
#   ./installation.sh --project-only  # just the platform (UI + backend)
#   ./installation.sh --tools-only    # just the external CLI tools
#   ./installation.sh --with-cai      # also create the optional CAI SDK venv
#   ./installation.sh --no-build      # skip the production UI build
#   ./installation.sh --yes           # never prompt; assume "yes"
#   ./installation.sh --help          # full usage
#
# Anything after `--` is forwarded to scripts/install-tools.sh, e.g.:
#   ./installation.sh --with-cai -- --tools=recon --yes
#   ./installation.sh --tools-only -- --list
#
# The script is idempotent: re-running it skips work that is already done.
# It never contacts an assessment target; it only installs software.
set -Eeuo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd -- "$HERE"

# ---- options -----------------------------------------------------------------
DO_PROJECT=1
DO_TOOLS=1
WITH_CAI=0
DO_BUILD=1
ASSUME_YES=0
TOOL_ARGS=()

usage() {
  sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-only) DO_TOOLS=0 ;;
    --tools-only)   DO_PROJECT=0; DO_BUILD=0 ;;
    --with-cai)     WITH_CAI=1 ;;
    --no-build)     DO_BUILD=0 ;;
    -y|--yes)       ASSUME_YES=1; TOOL_ARGS+=(--yes) ;;
    -h|--help)      usage 0 ;;
    --)             shift; TOOL_ARGS+=("$@"); break ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
  shift
done

# ---- pretty output -----------------------------------------------------------
if [[ -t 1 ]]; then
  B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
else
  B=""; G=""; Y=""; R=""; C=""; N=""
fi
say()  { printf '%s==>%s %s\n' "$C$B" "$N" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%swarn%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s err%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

trap 'die "failed near line $LINENO (see output above)"' ERR

# ---- helpers -----------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# version_ge A B  -> true when A >= B (dotted numeric compare)
version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

confirm() {
  [[ "$ASSUME_YES" == 1 ]] && return 0
  local reply
  read -r -p "$1 [Y/n] " reply || true
  [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

# ---- prerequisite checks -----------------------------------------------------
check_project_prereqs() {
  say "Checking prerequisites"
  local missing=()

  if have node; then
    local nv; nv="$(node -v | sed 's/^v//')"
    if version_ge "$nv" "18.0.0"; then ok "Node.js $nv"; else
      warn "Node.js $nv found but >= 18 is recommended"
    fi
  else
    missing+=("Node.js 18+ (https://nodejs.org or your package manager / nvm)")
  fi
  have npm || missing+=("npm (ships with Node.js)")

  if have python3; then
    local pv; pv="$(python3 -c 'import platform;print(platform.python_version())')"
    if version_ge "$pv" "3.11.0"; then ok "Python $pv"; else
      warn "Python $pv found; 3.11+ recommended (3.12 is the reference)"
    fi
  else
    missing+=("Python 3.11+ (https://www.python.org)")
  fi
  have git || missing+=("git")

  if [[ ${#missing[@]} -gt 0 ]]; then
    printf '%s\n' "Missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    die "Install the items above, then re-run ./installation.sh"
  fi
}

# ---- project setup -----------------------------------------------------------
setup_node() {
  say "Installing JavaScript dependencies"
  if [[ -f package-lock.json ]]; then
    npm ci
  else
    npm install
  fi
  ok "node_modules ready"
}

setup_python() {
  say "Creating Python environment (.venv) and installing backend requirements"
  [[ -d .venv ]] || python3 -m venv .venv
  ./.venv/bin/python -m pip install --quiet --upgrade pip
  ./.venv/bin/python -m pip install --quiet -r requirements.txt
  ok "Backend venv ready (.venv)"
}

setup_cai() {
  say "Creating optional CAI SDK environment (.venv-cai)"
  warn "cai-framework is an optional upstream dependency with its own mixed license."
  [[ -d .venv-cai ]] || python3 -m venv .venv-cai
  ./.venv-cai/bin/python -m pip install --quiet --upgrade pip
  if ./.venv-cai/bin/python -m pip install --quiet -r requirements-cai.txt; then
    ok "CAI venv ready (.venv-cai)"
  else
    warn "CAI install failed; the platform still runs without it (planning only for CAI nodes)."
  fi
}

build_ui() {
  say "Building the production UI (dist/)"
  npm run build
  if [[ -f dist/client/index.html && -f dist/server/index.js && -f dist/.openai/hosting.json ]]; then
    ok "Build complete (dist/client, dist/server, dist/.openai)"
  else
    warn "Build finished but expected dist artifacts are missing; check 'npm run build' output."
  fi
}

# ---- external tools ----------------------------------------------------------
install_tools() {
  say "Installing external catalog tools via scripts/install-tools.sh"
  if [[ ! -x scripts/install-tools.sh ]]; then
    chmod +x scripts/install-tools.sh 2>/dev/null || true
  fi
  bash scripts/install-tools.sh "${TOOL_ARGS[@]}"
}

# ---- run ---------------------------------------------------------------------
printf '%s\n' "${B}AI-tricky installer${N}"
printf '%s\n\n' "Local-first, AI-assisted security workflow platform."

if [[ "$DO_PROJECT" == 1 ]]; then
  check_project_prereqs
  setup_node
  setup_python
  [[ "$WITH_CAI" == 1 ]] && setup_cai
  [[ "$DO_BUILD" == 1 ]] && build_ui
fi

if [[ "$DO_TOOLS" == 1 ]]; then
  install_tools || warn "Tool installation reported problems; see its summary above."
fi

# ---- next steps --------------------------------------------------------------
echo
say "Done."
if [[ "$DO_PROJECT" == 1 ]]; then
  cat <<EOF
Start the platform:

  ${B}./start-local.sh${N}          # production build on http://127.0.0.1:8787
  ${B}npm run dev${N}               # developer mode (Vite UI + backend, hot reload)

The UI, API, SQLite history and job directories all run locally.
EOF
fi
if [[ "$DO_TOOLS" == 1 ]]; then
  cat <<EOF

If any tools were installed to a per-user location, make sure these are on PATH:

  export PATH="\$HOME/.local/bin:\$HOME/go/bin:\$HOME/.cargo/bin:\$PATH"

Then open the Templates catalog (or Local workspace → Run setup → "Check
workflow readiness") to see which tool binaries are now detected.
EOF
fi
