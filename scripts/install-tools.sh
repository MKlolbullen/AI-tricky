#!/usr/bin/env bash
#
# install-tools.sh — install the external CLI tools used by the AI-tricky
# (mini-tricky) catalog.
#
# AI-tricky does not bundle third-party binaries. Each catalog adapter runs a
# real executable that must be on your PATH. This script installs those
# executables across their native ecosystems (Go, Rust, Python/pipx, Ruby,
# npm, system packages, Git builds and GitHub release binaries).
#
# Usage:
#   scripts/install-tools.sh --web-recon     # pinned starter binaries
#   scripts/install-tools.sh                 # install everything it can
#   scripts/install-tools.sh --list          # print the tool/method table, exit
#   scripts/install-tools.sh --tools=recon   # only a category (see --list)
#   scripts/install-tools.sh --tools=httpx,nuclei,ffuf
#   scripts/install-tools.sh --methods=go,pipx    # only these install methods
#   scripts/install-tools.sh --skip=nmap,amass    # skip specific tools
#   scripts/install-tools.sh --skip-toolchains    # don't try to install Go/Rust/pipx
#   scripts/install-tools.sh --prefix=$HOME/.local  # where launchers/binaries go
#   scripts/install-tools.sh --yes           # never prompt
#
# It is idempotent (a tool already on PATH is skipped), never aborts on a
# single tool's failure, and prints a summary of installed / skipped / failed /
# manual tools at the end. It installs software only; it never touches an
# assessment target.
#
# Notes:
#   * Some tools are large or vendor-specific; those are listed as "manual"
#     with a pointer rather than installed blindly.
#   * Review what this runs before using it on a shared or production host.
set -Euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT="$(cd -- "$HERE/.." >/dev/null 2>&1 && pwd)"

# ---- options -----------------------------------------------------------------
PREFIX="${AI_TRICKY_PREFIX:-}"
WEB_RECON=0
ONLY_TOOLS=""
ONLY_METHODS=""
SKIP_TOOLS=""
SKIP_TOOLCHAINS=0
ASSUME_YES=0
LIST_ONLY=0
GO_VERSION="1.26.4"

for arg in "$@"; do
  case "$arg" in
    --list)            LIST_ONLY=1 ;;
    --web-recon)       WEB_RECON=1 ;;
    --yes|-y)          ASSUME_YES=1 ;;
    --skip-toolchains) SKIP_TOOLCHAINS=1 ;;
    --tools=*)         ONLY_TOOLS="${arg#*=}" ;;
    --methods=*)       ONLY_METHODS="${arg#*=}" ;;
    --skip=*)          SKIP_TOOLS="${arg#*=}" ;;
    --prefix=*)        PREFIX="${arg#*=}" ;;
    -h|--help)         sed -n '2,38p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ -z "$PREFIX" ]]; then
  if [[ "$WEB_RECON" == 1 ]]; then
    PREFIX="$HOME/.local/share/ai-tricky/web-recon"
  else
    PREFIX="$HOME/.local"
  fi
fi
BIN="$PREFIX/bin"
OPT="$PREFIX/opt/ai-tricky-tools"
LOCK="$ROOT/toolchains/web-recon.tsv"

# ---- output ------------------------------------------------------------------
if [[ -t 1 ]]; then
  B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; D=$'\e[2m'; N=$'\e[0m'
else B=""; G=""; Y=""; R=""; C=""; D=""; N=""; fi
say()  { printf '%s==>%s %s\n' "$C$B" "$N" "$*"; }
ok()   { printf '  %sok%s   %s\n' "$G" "$N" "$*"; }
skip() { printf '  %s--%s   %s\n' "$D" "$N" "$*"; }
warn() { printf '  %swarn%s %s\n' "$Y" "$N" "$*"; }
fail() { printf '  %sfail%s %s\n' "$R" "$N" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }
in_csv() { # in_csv needle csv
  local n="$1" c=",$2,"; [[ "$c" == *",$n,"* ]]
}

# ---- platform / package manager ---------------------------------------------
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
case "$UNAME_S" in Linux) OS=linux ;; Darwin) OS=darwin ;; *) OS=unknown ;; esac
case "$UNAME_M" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) GOARCH="$UNAME_M" ;;
esac

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then have sudo && SUDO="sudo"; fi

PKG=""
if   have apt-get; then PKG=apt
elif have dnf;     then PKG=dnf
elif have pacman;  then PKG=pacman
elif have zypper;  then PKG=zypper
elif have brew;    then PKG=brew
fi

pkg_install() { # pkg_install name...
  [[ -z "$PKG" ]] && return 1
  case "$PKG" in
    apt)    $SUDO apt-get update -y >/dev/null 2>&1 || true; $SUDO apt-get install -y "$@" ;;
    dnf)    $SUDO dnf install -y "$@" ;;
    pacman) $SUDO pacman -Sy --noconfirm "$@" ;;
    zypper) $SUDO zypper --non-interactive install "$@" ;;
    brew)   brew install "$@" ;;
  esac
}

confirm() {
  [[ "$ASSUME_YES" == 1 ]] && return 0
  local r; read -r -p "$1 [Y/n] " r || true; [[ -z "$r" || "$r" =~ ^[Yy] ]]
}

# ---- result tracking ---------------------------------------------------------
R_OK=(); R_SKIP=(); R_FAIL=(); R_MANUAL=()

# ---- toolchains --------------------------------------------------------------
ensure_base() {
  for c in curl git tar; do
    have "$c" || { warn "$c missing; attempting install"; pkg_install "$c" >/dev/null 2>&1 || true; }
  done
  have unzip || pkg_install unzip >/dev/null 2>&1 || true
  if ! have make || ! have gcc; then
    pkg_install build-essential >/dev/null 2>&1 || pkg_install make gcc >/dev/null 2>&1 || true
  fi
}

have_go() {
  [[ "$(go version 2>/dev/null)" == "go version go"* ]]
}

ensure_go() {
  if ! have_go && [[ -x "$OPT/go/bin/go" ]]; then
    export PATH="$OPT/go/bin:$PATH"
  fi
  if have_go; then ok "$(go version)"; else
    [[ "$SKIP_TOOLCHAINS" == 1 ]] && { warn "go not found (--skip-toolchains)"; return 1; }
    say "Installing Go $GO_VERSION to $OPT/go"
    local tgz="go${GO_VERSION}.${OS}-${GOARCH}.tar.gz" expected actual stage
    have python3 || { fail "Python 3 is required to verify the Go archive"; return 1; }
    expected="$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' | python3 -c '
import json, sys
print(next(f["sha256"] for release in json.load(sys.stdin) for f in release["files"] if f["filename"] == sys.argv[1]))
' "$tgz")" || return 1
    stage="$(mktemp -d "$OPT/go-install.XXXXXXXX")" || return 1
    if curl -fsSL "https://go.dev/dl/$tgz" -o "$stage/$tgz"; then
      actual="$(python3 -c 'import hashlib, sys; print(hashlib.file_digest(open(sys.argv[1], "rb"), "sha256").hexdigest())' "$stage/$tgz")"
      if [[ "$actual" == "$expected" ]] && tar -C "$stage" -xzf "$stage/$tgz" && [[ -x "$stage/go/bin/go" ]]; then
        rm -rf "$OPT/go"
        mv "$stage/go" "$OPT/go"
        export PATH="$OPT/go/bin:$PATH"
      else
        fail "Go archive checksum or extraction failed"
      fi
    fi
    rm -rf "$stage"
    have_go || { fail "Go install failed"; return 1; }
  fi
  if [[ "$WEB_RECON" == 1 ]]; then
    export GOBIN="$BIN"
  else
    export GOBIN="${GOBIN:-$HOME/go/bin}"
  fi
  mkdir -p "$GOBIN"; export PATH="$GOBIN:$PATH"
  export GOFLAGS="${GOFLAGS:-}"
  return 0
}

ensure_rust() {
  if have cargo; then ok "cargo $(cargo --version | awk '{print $2}')"; return 0; fi
  [[ "$SKIP_TOOLCHAINS" == 1 ]] && { warn "cargo not found (--skip-toolchains)"; return 1; }
  say "Installing Rust toolchain via rustup"
  if curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path >/dev/null 2>&1; then
    # shellcheck disable=SC1090
    [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
  fi
  have cargo || { fail "cargo install failed"; return 1; }
}

ensure_pipx() {
  if have pipx; then ok "pipx present"; return 0; fi
  [[ "$SKIP_TOOLCHAINS" == 1 ]] && { warn "pipx not found (--skip-toolchains)"; return 1; }
  say "Installing pipx"
  python3 -m pip install --user --quiet pipx >/dev/null 2>&1 || pkg_install pipx >/dev/null 2>&1 || true
  export PATH="$HOME/.local/bin:$PATH"
  python3 -m pipx ensurepath >/dev/null 2>&1 || true
  have pipx || python3 -m pipx --version >/dev/null 2>&1
}
pipx_bin() { have pipx && echo pipx || echo "python3 -m pipx"; }

# ---- generic installers ------------------------------------------------------
ghrelease_install() { # ghrelease_install owner/repo asset_regex binname
  local repo="$1" rx="$2" binname="$3"
  local api="https://api.github.com/repos/${repo}/releases/latest"
  local auth=(); [[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  local url
  url="$(curl -fsSL "${auth[@]}" "$api" 2>/dev/null \
        | grep -oE '"browser_download_url": *"[^"]+"' \
        | cut -d'"' -f4 | grep -E "$rx" | head -n1 || true)"
  [[ -z "$url" ]] && { fail "$binname: no release asset matched /$rx/"; return 1; }
  local tmp; tmp="$(mktemp -d)"; local file="$tmp/${url##*/}"
  curl -fsSL "$url" -o "$file" || { rm -rf "$tmp"; return 1; }
  case "$file" in
    *.zip)         ( cd "$tmp" && unzip -oq "$file" ) ;;
    *.tar.gz|*.tgz)( cd "$tmp" && tar xzf "$file" ) ;;
    *.tar.bz2)     ( cd "$tmp" && tar xjf "$file" ) ;;
  esac
  local src
  src="$(find "$tmp" -type f -name "$binname" -perm -u+x 2>/dev/null | head -n1)"
  [[ -z "$src" ]] && src="$(find "$tmp" -type f -name "$binname" 2>/dev/null | head -n1)"
  [[ -z "$src" && -f "$file" ]] && { chmod +x "$file"; src="$file"; }
  [[ -z "$src" ]] && { fail "$binname: binary not found in asset"; rm -rf "$tmp"; return 1; }
  install -m 0755 "$src" "$BIN/$binname"; rm -rf "$tmp"
}

gitpy_install() { # gitpy_install name repo entry launcher
  local name="$1" repo="$2" entry="$3" launcher="$4"
  local dir="$OPT/$name"
  if [[ -d "$dir/.git" ]]; then ( cd "$dir" && git pull --ff-only -q ) || true
  else git clone --depth 1 -q "$repo" "$dir" || { fail "$name: clone failed"; return 1; }; fi
  if [[ ! -x "$dir/.venv/bin/python" ]]; then python3 -m venv "$dir/.venv" || { fail "$name: venv failed"; return 1; }; fi
  "$dir/.venv/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  if   [[ -f "$dir/requirements.txt" ]]; then "$dir/.venv/bin/pip" install --quiet -r "$dir/requirements.txt" >/dev/null 2>&1 || warn "$name: some Python deps failed"
  elif [[ -f "$dir/setup.py" || -f "$dir/pyproject.toml" ]]; then "$dir/.venv/bin/pip" install --quiet "$dir" >/dev/null 2>&1 || true
  fi
  cat > "$BIN/$launcher" <<EOF
#!/usr/bin/env bash
cd "$dir" && exec "$dir/.venv/bin/python" "$dir/$entry" "\$@"
EOF
  chmod +x "$BIN/$launcher"
  [[ -f "$dir/$entry" ]] || { fail "$launcher: entry $entry not found in repo"; return 1; }
}

# ---- special-case installers -------------------------------------------------
install_findomain() {
  if [[ "$GOARCH" == arm64 && "$OS" == linux ]]; then ghrelease_install Findomain/Findomain 'findomain-aarch64$' findomain
  elif [[ "$OS" == darwin ]]; then ghrelease_install Findomain/Findomain 'findomain-macos\.zip' findomain
  else ghrelease_install Findomain/Findomain 'findomain-linux\.zip' findomain; fi
}
install_aquatone()  { ghrelease_install michenriksen/aquatone "aquatone_${OS}_${GOARCH}_.*\.zip" aquatone; }
install_crawlergo() { ghrelease_install Qianlitp/crawlergo "crawlergo_${OS}_${GOARCH}\.zip" crawlergo; }
install_kiterunner(){ ghrelease_install assetnote/kiterunner "kiterunner_.*_${OS}_${GOARCH}\.tar\.gz" kr; }
install_ppfuzz()    { ghrelease_install dwisiswant0/ppfuzz "ppfuzz-.*-(x86_64|aarch64)-.*-${OS}-gnu\.tar\.gz" ppfuzz; }
install_grype()     { curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "$BIN" >/dev/null 2>&1; }
install_syft()      { curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b "$BIN" >/dev/null 2>&1; }
install_massdns() {
  local dir="$OPT/massdns"
  [[ -d "$dir/.git" ]] || git clone --depth 1 -q https://github.com/blechschmidt/massdns "$dir" || return 1
  ( cd "$dir" && make -s ) || return 1
  install -m 0755 "$dir/bin/massdns" "$BIN/massdns"
}
install_testssl() {
  local dir="$OPT/testssl.sh"
  [[ -d "$dir/.git" ]] || git clone --depth 1 -q https://github.com/drwetter/testssl.sh "$dir" || return 1
  ln -sf "$dir/testssl.sh" "$BIN/testssl.sh"
}
install_joomscan() {
  local dir="$OPT/joomscan"
  [[ -d "$dir/.git" ]] || git clone --depth 1 -q https://github.com/OWASP/joomscan "$dir" || return 1
  cat > "$BIN/joomscan" <<EOF
#!/usr/bin/env bash
exec perl "$dir/joomscan.pl" "\$@"
EOF
  chmod +x "$BIN/joomscan"
  have perl || warn "joomscan needs perl (install perl + required CPAN modules)"
}

# ---- tool manifest -----------------------------------------------------------
# One record per line:  name | category | method | source
#   methods: go cargo pipx gem npm apt fn gitpy manual
#   gitpy source = "repo_url entry_file launcher_name"
#   fn    source = "function_name"
#   manual source = "pointer text"
MANIFEST=$(cat <<'MF'
subfinder|recon|go|github.com/projectdiscovery/subfinder/v2/cmd/subfinder
assetfinder|recon|go|github.com/tomnomnom/assetfinder
amass|recon|go|github.com/owasp-amass/amass/v4/...
findomain|recon|fn|install_findomain
chaos|recon|go|github.com/projectdiscovery/chaos-client/cmd/chaos
github-subdomains|recon|go|github.com/gwen001/github-subdomains
gitlab-subdomains|recon|go|github.com/gwen001/gitlab-subdomains
github-endpoints|recon|gitpy|https://github.com/gwen001/github-search github-endpoints.py github-endpoints
theHarvester|osint|pipx|theHarvester
spiderfoot|osint|gitpy|https://github.com/smicallef/spiderfoot sf.py spiderfoot
bbot|osint|pipx|bbot
censys|osint|pipx|censys
shodan|osint|pipx|shodan
uncover|osint|go|github.com/projectdiscovery/uncover/cmd/uncover
crtsh|recon|manual|crt.sh client, e.g. https://github.com/az7rb/crt.sh
cero|recon|go|github.com/glebarez/cero
dnsx|dns|go|github.com/projectdiscovery/dnsx/cmd/dnsx
shuffledns|dns|go|github.com/projectdiscovery/shuffledns/cmd/shuffledns
puredns|dns|go|github.com/d3mondev/puredns/v2
massdns|dns|fn|install_massdns
dnsgen|dns|pipx|dnsgen
gotator|dns|go|github.com/Josue87/gotator
alterx|dns|go|github.com/projectdiscovery/alterx/cmd/alterx
dnsvalidator|dns|pipx|git+https://github.com/vortexau/dnsvalidator
dnsreaper|dns|gitpy|https://github.com/punk-security/dnsReaper main.py dnsreaper
mapcidr|dns|go|github.com/projectdiscovery/mapcidr/cmd/mapcidr
asnmap|dns|go|github.com/projectdiscovery/asnmap/cmd/asnmap
cdncheck|dns|go|github.com/projectdiscovery/cdncheck/cmd/cdncheck
hakip2host|dns|go|github.com/hakluke/hakip2host
dsieve|dns|go|github.com/trickest/dsieve
httpx|http|go|github.com/projectdiscovery/httpx/cmd/httpx
httprobe|http|go|github.com/tomnomnom/httprobe
hakcheckurl|http|go|github.com/hakluke/hakcheckurl
smap|recon|go|github.com/s0md3v/smap/cmd/smap
naabu|recon|go|github.com/projectdiscovery/naabu/v2/cmd/naabu
nmap|recon|apt|nmap
masscan|recon|apt|masscan
rustscan|recon|cargo|rustscan
tlsx|tls|go|github.com/projectdiscovery/tlsx/cmd/tlsx
sslscan|tls|apt|sslscan
testssl.sh|tls|fn|install_testssl
katana|crawl|go|github.com/projectdiscovery/katana/cmd/katana
hakrawler|crawl|go|github.com/hakluke/hakrawler
gospider|crawl|go|github.com/jaeles-project/gospider
crawlergo|crawl|fn|install_crawlergo
cariddi|crawl|go|github.com/edoardottt/cariddi/cmd/cariddi
gau|crawl|go|github.com/lc/gau/v2/cmd/gau
waybackurls|crawl|go|github.com/tomnomnom/waybackurls
waymore|crawl|pipx|waymore
urlfinder|crawl|go|github.com/projectdiscovery/urlfinder/cmd/urlfinder
subjs|crawl|go|github.com/lc/subjs
getJS|crawl|go|github.com/003random/getJS/v2
linkfinder|crawl|gitpy|https://github.com/GerbenJavado/LinkFinder linkfinder.py linkfinder
xnLinkFinder|crawl|pipx|xnLinkFinder
jsluice|crawl|go|github.com/BishopFox/jsluice/cmd/jsluice
mantra|secrets|manual|github.com/Brosck/mantra (Go) — verify fork before install
SecretFinder|secrets|gitpy|https://github.com/m4ll0k/SecretFinder SecretFinder.py SecretFinder
trufflehog|secrets|go|github.com/trufflesecurity/trufflehog/v3
gitleaks|secrets|go|github.com/gitleaks/gitleaks/v8
gitdorker|secrets|gitpy|https://github.com/obheda12/GitDorker GitDorker.py gitdorker
meg|crawl|go|github.com/tomnomnom/meg
unfurl|misc|go|github.com/tomnomnom/unfurl
anew|misc|go|github.com/tomnomnom/anew
qsreplace|misc|go|github.com/tomnomnom/qsreplace
uro|misc|pipx|uro
gf|misc|go|github.com/tomnomnom/gf
rush|misc|go|github.com/shenwei356/rush
interlace|misc|pipx|git+https://github.com/codingo/Interlace
notify|misc|go|github.com/projectdiscovery/notify/cmd/notify
interactsh-client|misc|go|github.com/projectdiscovery/interactsh/cmd/interactsh-client
oasdiff|misc|go|github.com/oasdiff/oasdiff
nuclei|vuln|go|github.com/projectdiscovery/nuclei/v3/cmd/nuclei
jaeles|vuln|go|github.com/jaeles-project/jaeles
nikto|vuln|apt|nikto
wapiti|vuln|pipx|wapiti3
ffuf|fuzzing|go|github.com/ffuf/ffuf/v2
feroxbuster|fuzzing|cargo|feroxbuster
gobuster|fuzzing|go|github.com/OJ/gobuster/v3
dirsearch|fuzzing|pipx|dirsearch
dirb|fuzzing|apt|dirb
dirhunt|fuzzing|pipx|dirhunt
wfuzz|fuzzing|pipx|wfuzz
wordlister|fuzzing|gitpy|https://github.com/4n4nk3/Wordlister wordlister.py wordlister
cewl|fuzzing|apt|cewl
x8|fuzzing|cargo|x8
arjun|fuzzing|pipx|arjun
paramspider|fuzzing|pipx|git+https://github.com/devanshbatham/ParamSpider
paraminer|fuzzing|manual|no single canonical CLI; see Burp Param Miner or x8
kr|fuzzing|fn|install_kiterunner
dalfox|xss|go|github.com/hahwul/dalfox/v2
xsstrike|xss|gitpy|https://github.com/s0md3v/XSStrike xsstrike.py xsstrike
Gxss|xss|go|github.com/KathanP19/Gxss
kxss|xss|go|github.com/Emoe/kxss
xsrfprobe|xss|pipx|xsrfprobe
ppfuzz|xss|fn|install_ppfuzz
sqlmap|sqli|pipx|sqlmap
ghauri|sqli|pipx|git+https://github.com/r0oth3x49/ghauri
commix|rce|gitpy|https://github.com/commixproject/commix commix.py commix
tplmap|ssti|manual|legacy Python 2 (github.com/epinna/tplmap); prefer sstimap
sstimap|ssti|pipx|git+https://github.com/vladko312/SSTImap
crlfuzz|crlf|go|github.com/dwisiswant0/crlfuzz/cmd/crlfuzz
oralyzer|crlf|pipx|git+https://github.com/r0075h3ll/Oralyzer
ssrfmap|ssrf|gitpy|https://github.com/swisskyrepo/SSRFmap ssrfmap.py ssrfmap
ssrf-sheriff|ssrf|go|github.com/teknogeek/ssrf-sheriff
gopherus|ssrf|manual|Python 2 tool (github.com/tarunkant/Gopherus)
smuggler|http|gitpy|https://github.com/defparam/smuggler smuggler.py smuggler
nomore403|http|go|github.com/devploit/nomore403
byp4xx|http|manual|github.com/lobuhi/byp4xx (fork-dependent)
shortscan|http|go|github.com/bitquark/shortscan/cmd/shortscan
jwt_tool|auth|gitpy|https://github.com/ticarpi/jwt_tool jwt_tool.py jwt_tool
cors_scan|misc|pipx|corscanner
csprecon|misc|go|github.com/edoardottt/csprecon/cmd/csprecon
shcheck|misc|gitpy|https://github.com/santoru/shcheck shcheck.py shcheck
graphql-cop|api|gitpy|https://github.com/dolevf/graphql-cop graphql-cop.py graphql-cop
graphw00f|api|gitpy|https://github.com/dolevf/graphw00f main.py graphw00f
clairvoyance|api|pipx|clairvoyance
APIFuzzer|api|pipx|APIFuzzer
restler|api|manual|github.com/microsoft/restler-fuzzer (requires .NET build)
whatweb|fingerprint|apt|whatweb
wappalyzer|fingerprint|manual|official CLI deprecated; this catalog's webanalyze covers it
webanalyze|fingerprint|go|github.com/rverton/webanalyze/cmd/webanalyze
wafw00f|fingerprint|pipx|wafw00f
gowitness|screenshot|go|github.com/sensepost/gowitness
aquatone|screenshot|fn|install_aquatone
cmseek|cms|gitpy|https://github.com/Tuhinshubhra/CMSeeK cmseek.py cmseek
wpscan|cms|gem|wpscan
joomscan|cms|fn|install_joomscan
droopescan|cms|pipx|droopescan
s3scanner|cloud|go|github.com/sa7mon/S3Scanner
cloud_enum|cloud|gitpy|https://github.com/initstring/cloud_enum cloud_enum.py cloud_enum
subjack|takeover|go|github.com/haccer/subjack
subzy|takeover|go|github.com/PentestPad/subzy
nrich|misc|manual|gitlab.com/shodan-public/nrich (download release binary)
semgrep|sast|pipx|semgrep
retire|sast|npm|retire
syft|sbom|fn|install_syft
grype|sbom|fn|install_grype
jq|util|apt|jq
sniper|framework|manual|github.com/1N3/Sn1per (vendor installer; review first)
zap-baseline.py|framework|manual|install OWASP ZAP (www.zaproxy.org); script ships with ZAP
MF
)

locked_go_spec() {
  awk -F '\t' -v tool="$1" '$1 == tool { print $2 "@" $3; exit }' "$LOCK"
}

if [[ "$WEB_RECON" == 1 ]]; then
  MANIFEST="$(awk -F '\t' '!/^#/ && NF == 3 { print $1 "|web-recon|go|" $2 "@" $3 }' "$LOCK")"
fi

# ---- listing -----------------------------------------------------------------
if [[ "$LIST_ONLY" == 1 ]]; then
  printf '%-22s %-12s %-8s %s\n' "TOOL" "CATEGORY" "METHOD" "SOURCE"
  printf '%-22s %-12s %-8s %s\n' "----" "--------" "------" "------"
  while IFS='|' read -r name cat method source; do
    [[ -z "$name" || "$name" == \#* ]] && continue
    printf '%-22s %-12s %-8s %s\n' "$name" "$cat" "$method" "$source"
  done <<< "$MANIFEST"
  exit 0
fi

# ---- plan: which toolchains are needed --------------------------------------
NEED_GO=0 NEED_RUST=0 NEED_PIPX=0 SELECTED=0
while IFS='|' read -r name cat method source; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  if [[ -n "$ONLY_TOOLS" ]] && ! in_csv "$name" "$ONLY_TOOLS" && ! in_csv "$cat" "$ONLY_TOOLS"; then continue; fi
  if [[ -n "$ONLY_METHODS" ]] && ! in_csv "$method" "$ONLY_METHODS"; then continue; fi
  if [[ -n "$SKIP_TOOLS" ]] && in_csv "$name" "$SKIP_TOOLS"; then continue; fi
  SELECTED=$((SELECTED + 1))
  case "$method" in go) NEED_GO=1 ;; cargo) NEED_RUST=1 ;; pipx) NEED_PIPX=1 ;; esac
done <<< "$MANIFEST"

if [[ "$SELECTED" == 0 ]]; then
  echo "No install recipes match the selection." >&2
  exit 2
fi
say "AI-tricky catalog tool installer"
echo "  prefix:    $PREFIX  (binaries/launchers in $BIN)"
echo "  platform:  $OS/$GOARCH   package manager: ${PKG:-none}"
[[ -n "$ONLY_TOOLS"   ]] && echo "  filter:    tools/categories = $ONLY_TOOLS"
[[ -n "$ONLY_METHODS" ]] && echo "  filter:    methods = $ONLY_METHODS"
[[ -n "$SKIP_TOOLS"   ]] && echo "  skipping:  $SKIP_TOOLS"
echo

if ! confirm "Install tools now?"; then echo "Aborted."; exit 0; fi

mkdir -p "$BIN" "$OPT/logs" || exit 1
LOG_DIR="$(mktemp -d "$OPT/logs/install.XXXXXXXX")" || exit 1
say "Preparing toolchains"
ensure_base
[[ "$NEED_GO"   == 1 ]] && { ensure_go   || warn "Go tools will be skipped"; }
[[ "$NEED_RUST" == 1 ]] && { ensure_rust || warn "Rust tools will be skipped"; }
[[ "$NEED_PIPX" == 1 ]] && { ensure_pipx || warn "pipx tools will be skipped"; }
echo

# ---- install loop ------------------------------------------------------------
install_logged() {
  local name="$1"; shift
  (umask 077; "$@" 2>&1 | tail -c 65536 > "$LOG_DIR/$name.log")
}

install_locked_go() {
  local name="$1" spec="$2" stage status=0
  if ! have_go || ! have python3; then
    R_FAIL+=("$name"); fail "$name (requires the Go compiler and Python 3)"; return 1
  fi
  if [[ -x "$BIN/$name" ]] && python3 "$HERE/check-recon-tools.py" --tool "$name" --binary "$BIN/$name" >/dev/null; then
    R_SKIP+=("$name"); skip "$name (pinned version already installed)"; return 0
  fi
  stage="$(mktemp -d "$BIN/.build.XXXXXXXX")" || { R_FAIL+=("$name"); return 1; }
  install_logged "$name" env GOBIN="$stage" GOFLAGS=-mod=mod go install "$spec" &&
    python3 "$HERE/check-recon-tools.py" --tool "$name" --binary "$stage/$name" >> "$LOG_DIR/$name.log" 2>&1 &&
    mv -f "$stage/$name" "$BIN/$name" || status=$?
  rm -rf "$stage"
  if [[ "$status" == 0 ]]; then
    R_OK+=("$name"); ok "$name ($spec)"
  else
    R_FAIL+=("$name"); fail "$name (see $LOG_DIR/$name.log)"
  fi
  return "$status"
}

install_one() { # install_one name method source
  local name="$1" method="$2" source="$3"
  if [[ "$WEB_RECON" == 1 ]]; then
    install_locked_go "$name" "$source"
    return $?
  fi
  # Preserve existing executables on the generic install path.
  if [[ "$method" != manual ]] && have "$name"; then R_SKIP+=("$name"); skip "$name (already on PATH)"; return 0; fi

  case "$method" in
    go)
      have_go || { R_FAIL+=("$name"); fail "$name (Go compiler unavailable)"; return 1; }
      local spec
      spec="$(locked_go_spec "$name")"
      if install_logged "$name" env GOFLAGS=-mod=mod go install "${spec:-${source}@latest}"; then R_OK+=("$name"); ok "$name (go)"; else R_FAIL+=("$name"); fail "$name (go install failed)"; fi ;;
    cargo)
      have cargo || { R_FAIL+=("$name"); fail "$name (cargo unavailable)"; return 1; }
      if install_logged "$name" cargo install "$source"; then R_OK+=("$name"); ok "$name (cargo)"; else R_FAIL+=("$name"); fail "$name (cargo install failed)"; fi ;;
    pipx)
      have pipx || python3 -m pipx --version >/dev/null 2>&1 || { R_FAIL+=("$name"); fail "$name (pipx unavailable)"; return 1; }
      if install_logged "$name" $(pipx_bin) install --force "$source"; then R_OK+=("$name"); ok "$name (pipx)"; else R_FAIL+=("$name"); fail "$name (pipx install failed)"; fi ;;
    gem)
      have gem || { R_FAIL+=("$name"); fail "$name (ruby/gem unavailable)"; return 1; }
      if install_logged "$name" $SUDO gem install "$source" || install_logged "$name-user" gem install --user-install "$source"; then R_OK+=("$name"); ok "$name (gem)"; else R_FAIL+=("$name"); fail "$name (gem install failed)"; fi ;;
    npm)
      have npm || { R_FAIL+=("$name"); fail "$name (npm unavailable)"; return 1; }
      if install_logged "$name" npm install -g "$source" || install_logged "$name-system" $SUDO npm install -g "$source"; then R_OK+=("$name"); ok "$name (npm)"; else R_FAIL+=("$name"); fail "$name (npm install failed)"; fi ;;
    apt)
      if install_logged "$name" pkg_install "$source"; then R_OK+=("$name"); ok "$name ($PKG)"; else R_FAIL+=("$name"); fail "$name (system package install failed)"; fi ;;
    gitpy)
      # shellcheck disable=SC2086
      set -- $source
      if install_logged "$name" gitpy_install "$name" "$1" "$2" "${3:-$name}"; then R_OK+=("$name"); ok "$name (git+venv)"; else R_FAIL+=("$name"); fi ;;
    fn)
      if install_logged "$name" "$source"; then R_OK+=("$name"); ok "$name (binary)"; else R_FAIL+=("$name"); fail "$name (download/build failed)"; fi ;;
    manual)
      R_MANUAL+=("$name :: $source"); warn "$name — manual: $source" ;;
    *) R_FAIL+=("$name"); fail "$name (unknown method '$method')" ;;
  esac
}

say "Installing tools"
while IFS='|' read -r name cat method source; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  if [[ -n "$ONLY_TOOLS" ]] && ! in_csv "$name" "$ONLY_TOOLS" && ! in_csv "$cat" "$ONLY_TOOLS"; then continue; fi
  if [[ -n "$ONLY_METHODS" ]] && ! in_csv "$method" "$ONLY_METHODS"; then continue; fi
  if [[ -n "$SKIP_TOOLS" ]] && in_csv "$name" "$SKIP_TOOLS"; then continue; fi
  install_one "$name" "$method" "$source" || true
done <<< "$MANIFEST"

# ---- summary -----------------------------------------------------------------
echo
say "Summary"
printf '  %sinstalled%s %d   %salready present%s %d   %sfailed%s %d   %smanual%s %d\n' \
  "$G" "$N" "${#R_OK[@]}" "$D" "$N" "${#R_SKIP[@]}" "$R" "$N" "${#R_FAIL[@]}" "$Y" "$N" "${#R_MANUAL[@]}"

if [[ ${#R_FAIL[@]} -gt 0 ]]; then
  echo; echo "${R}Failed${N} (re-run with that tool, or install it by hand):"
  printf '  - %s\n' "${R_FAIL[@]}"
  echo "  Local diagnostics: $LOG_DIR"
fi
if [[ ${#R_MANUAL[@]} -gt 0 ]]; then
  echo; echo "${Y}Manual${N} (not auto-installed):"
  printf '  - %s\n' "${R_MANUAL[@]}"
fi

echo
cat <<EOF
Add the install locations to your PATH (e.g. in ~/.bashrc or ~/.zshrc):

  export PATH="$BIN:\$HOME/go/bin:\$HOME/.cargo/bin:\$PATH"

Then verify what AI-tricky can now see:
  * Templates catalog → readiness badges, or
  * Local workspace → Run setup → "Check workflow readiness".

Install pinned support data and register it in the local workspace:
  python3 scripts/setup-support-data.py
  python3 scripts/setup-support-data.py --install nuclei-templates --install jaeles-signatures

Or use Local workspace → Inputs → Templates, resolvers and wordlists.
Installing data does not bind it to a workflow or start an assessment.
EOF

# The pinned profile requires every selected binary to install successfully.
if [[ "$WEB_RECON" == 1 && ${#R_FAIL[@]} -gt 0 ]]; then exit 1; fi
# Preserve the generic installer's partial-success behavior.
if [[ ${#R_OK[@]} -eq 0 && ${#R_SKIP[@]} -eq 0 && ${#R_FAIL[@]} -gt 0 ]]; then exit 1; fi
exit 0
