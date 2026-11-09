#!/usr/bin/env bash
#
# build-binary.sh — build a standalone AI-tricky executable with PyInstaller.
#
# Produces a single self-contained binary at dist-bin/ai-tricky that bundles the
# FastAPI backend, the built UI and the runtime data files (catalog, native
# registry, payloads). It needs no Python or Node at runtime. The optional CAI
# SDK stays external (set CAI_PYTHON to an interpreter that has cai-framework);
# native assessment and the whole platform run without it.
#
# The binary is platform-specific (built here for this OS/arch) and large, so it
# is NOT committed to git — distribute it via GitHub Releases. Run from a clean
# checkout:  ./scripts/build-binary.sh
#
# Options:
#   --no-ui-build   reuse an existing dist/client instead of rebuilding the UI
#   --help
set -Eeuo pipefail
cd -- "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"

PYINSTALLER_VERSION="6.11.1"
BUILD_VENV=".venv-build"
NO_UI_BUILD=0
for arg in "$@"; do
  case "$arg" in
    --no-ui-build) NO_UI_BUILD=1 ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

say() { printf '==> %s\n' "$*"; }

# ---- 1. built UI -------------------------------------------------------------
if [[ "$NO_UI_BUILD" == 0 || ! -f dist/client/index.html ]]; then
  say "Building the UI (npm run build)"
  npm run build
fi
[[ -f dist/client/index.html ]] || { echo "dist/client/index.html missing after build" >&2; exit 1; }

# ---- 2. build environment ----------------------------------------------------
say "Preparing build environment ($BUILD_VENV) with PyInstaller $PYINSTALLER_VERSION"
[[ -d "$BUILD_VENV" ]] || python3 -m venv "$BUILD_VENV"
"./$BUILD_VENV/bin/python" -m pip install --quiet --upgrade pip
"./$BUILD_VENV/bin/python" -m pip install --quiet -r requirements.txt "pyinstaller==${PYINSTALLER_VERSION}"

# ---- 3. bundle data (ROOT-relative paths resolve inside the bundle) ----------
# PyInstaller's --add-data separator is ':' on POSIX and ';' on Windows.
# Absolute source paths: PyInstaller resolves --add-data sources relative to the
# --specpath directory, so bare relative paths would not be found.
SEP=":"; [[ "${OS:-}" == "Windows_NT" ]] && SEP=";"
ROOT="$PWD"
DATA=(
  "${ROOT}/dist/client${SEP}dist/client"
  "${ROOT}/src/mini-tricky-catalog.json${SEP}src"
  "${ROOT}/src/native-registry.json${SEP}src"
  "${ROOT}/src/templates.json${SEP}src"
  "${ROOT}/backend/gf-patterns.json${SEP}backend"
  "${ROOT}/support-data/manifest.json${SEP}support-data"
  "${ROOT}/third-party/mini-tricky/payloads${SEP}third-party/mini-tricky/payloads"
)
ADD_DATA=(); for d in "${DATA[@]}"; do ADD_DATA+=(--add-data "$d"); done

# ---- 4. build ----------------------------------------------------------------
say "Building the binary"
"./$BUILD_VENV/bin/pyinstaller" --noconfirm --clean --onefile \
  --name ai-tricky \
  --distpath dist-bin --workpath .build-bin --specpath .build-bin \
  --paths "$ROOT" \
  "${ADD_DATA[@]}" \
  --collect-submodules backend \
  --collect-submodules uvicorn \
  scripts/binary_entry.py

if [[ -x dist-bin/ai-tricky ]]; then
  say "Done: dist-bin/ai-tricky ($(du -h dist-bin/ai-tricky | cut -f1))"
  echo "Run it with:  ./dist-bin/ai-tricky   (serves http://127.0.0.1:8787)"
else
  echo "Build finished but dist-bin/ai-tricky is missing; check the output above." >&2
  exit 1
fi
