#!/usr/bin/env bash
#  ReconPipe Installer
#  Installs everything ReconPipe can use on major Linux distros
#  (Debian, Ubuntu, Kali, Mint, Fedora, RHEL, Arch, openSUSE, and derivatives)
#
#  Core (a useful first scan): Python deps, Chaos, subfinder, dnsx, httpx,
#  Katana, gospider, waymore/gau/waybackurls, TruffleHog, Gitleaks, GUI.
#  Extra (installed when possible): amass, assetfinder, findomain, hakrawler,
#  paramspider, LinkFinder, naabu, whatweb, wappalyzer, gowitness, nuclei,
#  jsluice, jsleak, spray.
#
#  Missing extras are skipped at scan time; they do not abort install.

set -euo pipefail

# Colors
RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

log()     { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} ${CYAN}[*]${RESET} $1"; }
success() { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} ${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} ${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} ${RED}[-]${RESET} $1"; }
header()  { echo -e "\n${CYAN}${BOLD}── $1 ──────────────────────────────────────────${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIN_GO_MAJOR=1
MIN_GO_MINOR=21
GO_FALLBACK_VERSION="1.22.10"
SHARED_BIN="/usr/local/bin"

# Must be present for a useful scan (verify fails if any are missing).
CORE_TOOLS=(chaos httpx katana subfinder dnsx gau gospider waybackurls waymore trufflehog gitleaks)

# Insstalled when posible; ReconPipe skips them if absent.
EXTRA_TOOLS=(
    jsluice anew amass assetfinder findomain hakrawler paramspider linkfinder
    naabu whatweb wappalyzer gowitness nuclei jsleak spray
)

TOOLS=("${CORE_TOOLS[@]}" "${EXTRA_TOOLS[@]}")

# Banner ( same here, 2010 banner bruh.)
echo -e "${CYAN}${BOLD}"
echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗██████╗ ███████╗"
echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║██╔══██╗██╔════╝"
echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝██║██████╔╝█████╗  "
echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔═══╝ ██║██╔═══╝ ██╔══╝  "
echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ██║██║     ███████╗"
echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝     ╚══════╝"
echo -e "${RESET}${DIM}  Installer — Linux (Debian / Ubuntu / Kali / Fedora / Arch / openSUSE)${RESET}"
echo ""

# Privilege helper
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    if command -v sudo &>/dev/null; then
        warn "Not running as root. Using sudo for system installs."
        SUDO="sudo"
    else
        error "Root privileges required (install sudo or re-run as root)."
        exit 1
    fi
else
    SUDO=""
fi


# packages must land in their home, not /root, or the shell won't find them.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
else
    REAL_USER="$(id -un)"
    REAL_HOME="$HOME"
fi
REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")"
[[ -n "$REAL_HOME" ]] || REAL_HOME="/home/$REAL_USER"

GOPATH="$REAL_HOME/go"
GOBIN="$GOPATH/bin"
PY_USER_BIN="$REAL_HOME/.local/bin"
VENDOR_DIR="$REAL_HOME/.reconpipe/vendor"
TOOL_PATH="/usr/local/go/bin:$SHARED_BIN:/usr/bin:/bin:$GOBIN:$PY_USER_BIN"

success "Installing for user: $REAL_USER  (home: $REAL_HOME)"

# Run a command as the real user with a predictable Go/Python environment
run_as_user() {
    if [[ "$REAL_USER" == "$(id -un)" ]]; then
        env HOME="$REAL_HOME" GOPATH="$GOPATH" GOBIN="$GOBIN" PATH="$TOOL_PATH:$PATH" "$@"
    else
        sudo -u "$REAL_USER" -H env HOME="$REAL_HOME" GOPATH="$GOPATH" GOBIN="$GOBIN" PATH="$TOOL_PATH:$PATH" "$@"
    fi
}

own_by_user() {
    [[ -e "$1" ]] || return 0
    $SUDO chown -R "$REAL_USER":"$REAL_GROUP" "$1" 2>/dev/null || true
}


append_rc() {
    local marker=$1 content=$2 rc
    for rc in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc" "$REAL_HOME/.profile"; do
        if [[ ! -f "$rc" ]]; then
            [[ "$rc" == "$REAL_HOME/.bashrc" ]] || continue
            $SUDO touch "$rc"
            own_by_user "$rc"
        fi
        grep -qF "$marker" "$rc" 2>/dev/null && continue
        printf '\n%s\n' "$content" | $SUDO tee -a "$rc" >/dev/null
        own_by_user "$rc"
    done
}

cpu_arch() {
    uname -m
}

# Detect distro + package manager
detect_os() {
    DISTRO_ID="unknown"
    DISTRO_LIKE=""
    DISTRO_NAME="Unknown Linux"
    PKG_MGR=""

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_LIKE="${ID_LIKE:-}"
        DISTRO_NAME="${PRETTY_NAME:-$NAME}"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO_ID="rhel"
        DISTRO_NAME="$(cat /etc/redhat-release)"
    fi

    local candidates="$DISTRO_ID $DISTRO_LIKE"
    if echo "$candidates" | grep -Eqi 'debian|ubuntu|kali|linuxmint|pop|parrot|raspbian|elementary|zorin'; then
        PKG_MGR="apt"
    elif echo "$candidates" | grep -Eqi 'fedora|rhel|centos|rocky|alma|amzn|ol|mageia'; then
        if command -v dnf &>/dev/null; then
            PKG_MGR="dnf"
        else
            PKG_MGR="yum"
        fi
    elif echo "$candidates" | grep -Eqi 'arch|manjaro|endeavouros|garuda|blackarch|artix'; then
        PKG_MGR="pacman"
    elif echo "$candidates" | grep -Eqi 'suse|opensuse|sles'; then
        PKG_MGR="zypper"
    else
        # Fall back to whatever package manager exists on the box
        if command -v apt-get &>/dev/null; then
            PKG_MGR="apt"
        elif command -v dnf &>/dev/null; then
            PKG_MGR="dnf"
        elif command -v yum &>/dev/null; then
            PKG_MGR="yum"
        elif command -v pacman &>/dev/null; then
            PKG_MGR="pacman"
        elif command -v zypper &>/dev/null; then
            PKG_MGR="zypper"
        fi
    fi

    if [[ -z "$PKG_MGR" ]]; then
        error "Unsupported Linux distribution (no apt/dnf/yum/pacman/zypper found)."
        error "Detected: $DISTRO_NAME"
        exit 1
    fi

    success "Detected: $DISTRO_NAME  (pkg: $PKG_MGR)"
}

# Package helpers
pkg_available() {
    local pkg=$1
    case "$PKG_MGR" in
        apt)    apt-cache show "$pkg" &>/dev/null ;;
        dnf)    dnf info "$pkg" &>/dev/null ;;
        yum)    yum info "$pkg" &>/dev/null ;;
        pacman) pacman -Si "$pkg" &>/dev/null ;;
        zypper) zypper search -x "$pkg" &>/dev/null ;;
        *)      return 1 ;;
    esac
}

resolve_first_available() {
    local pkg
    for pkg in "$@"; do
        if pkg_available "$pkg"; then
            echo "$pkg"
            return 0
        fi
    done
    return 1
}

pkg_install() {
    if [[ $# -eq 0 ]]; then
        return 0
    fi
    case "$PKG_MGR" in
        apt)
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
            ;;
        dnf)
            $SUDO dnf install -y -q "$@"
            ;;
        yum)
            $SUDO yum install -y -q "$@"
            ;;
        pacman)
            $SUDO pacman -Sy --noconfirm --needed "$@"
            ;;
        zypper)
            $SUDO zypper --non-interactive install -y "$@"
            ;;
    esac
}

pkg_update() {
    case "$PKG_MGR" in
        apt)    $SUDO apt-get update -qq ;;
        dnf)    $SUDO dnf check-update -q || true ;;
        yum)    $SUDO yum check-update -q || true ;;
        pacman) $SUDO pacman -Sy --noconfirm ;;
        zypper) $SUDO zypper --non-interactive refresh ;;
    esac
}

add_if_available() {
    local -n _arr=$1
    shift
    local pkg resolved
    for pkg in "$@"; do
        resolved="$(resolve_first_available "$pkg" || true)"
        if [[ -n "$resolved" ]]; then
            _arr+=("$resolved")
        fi
    done
}

install_system_packages() {
    header "STEP 1: System packages"

    log "Refreshing package indexes ($PKG_MGR)..."
    pkg_update

    local base_pkgs=()
    local go_pkg=""
    local chromium_pkg=""
    local chromium_driver_pkg=""
    local webview_gtk=""

    case "$PKG_MGR" in
        apt)
            base_pkgs=(curl wget git python3 python3-pip python3-venv python3-setuptools unzip ca-certificates)
            if pkg_available build-essential; then
                base_pkgs+=(build-essential)
            else
                base_pkgs+=(gcc g++ make)
            fi
            add_if_available base_pkgs python3-dev python3-gi python3-gi-cairo gir1.2-gtk-3.0 \
                libpcap-dev nmap jq ruby ruby-dev nodejs npm whatweb \
                libffi-dev
            go_pkg="$(resolve_first_available golang-go golang go || true)"
            chromium_pkg="$(resolve_first_available chromium chromium-browser || true)"
            chromium_driver_pkg="$(resolve_first_available chromium-driver chromedriver || true)"
            webview_gtk="$(resolve_first_available gir1.2-webkit2-4.1 gir1.2-webkit2-4.0 || true)"
            ;;
        dnf|yum)
            base_pkgs=(curl wget git python3 python3-pip python3-setuptools unzip ca-certificates gcc gcc-c++ make)
            add_if_available base_pkgs python3-devel python3-gobject libpcap-devel nmap jq ruby ruby-devel \
                nodejs npm whatweb libffi-devel
            go_pkg="$(resolve_first_available golang go || true)"
            chromium_pkg="$(resolve_first_available chromium || true)"
            chromium_driver_pkg="$(resolve_first_available chromedriver || true)"
            webview_gtk="$(resolve_first_available webkit2gtk4.1 webkit2gtk4.0 webkit2gtk3 || true)"
            ;;
        pacman)
            base_pkgs=(curl wget git python python-pip python-setuptools unzip ca-certificates base-devel)
            add_if_available base_pkgs python-gobject gtk3 libpcap nmap jq ruby nodejs npm whatweb libffi
            go_pkg="$(resolve_first_available go || true)"
            chromium_pkg="$(resolve_first_available chromium || true)"
            chromium_driver_pkg="$(resolve_first_available chromedriver || true)"
            webview_gtk="$(resolve_first_available webkit2gtk-4.1 webkit2gtk || true)"
            ;;
        zypper)
            base_pkgs=(curl wget git python3 python3-pip python3-setuptools unzip ca-certificates gcc gcc-c++ make)
            add_if_available base_pkgs python3-devel libpcap-devel nmap jq ruby ruby-devel nodejs npm libffi-devel
            go_pkg="$(resolve_first_available go golang || true)"
            chromium_pkg="$(resolve_first_available chromium || true)"
            chromium_driver_pkg="$(resolve_first_available chromedriver || true)"
            webview_gtk="$(resolve_first_available webkit2gtk-4_1-0 libwebkit2gtk-4_0-37 || true)"
            ;;
    esac

    local to_install=("${base_pkgs[@]}")
    [[ -n "$go_pkg" ]] && to_install+=("$go_pkg")
    [[ -n "$chromium_pkg" ]] && to_install+=("$chromium_pkg")
    [[ -n "$chromium_driver_pkg" ]] && to_install+=("$chromium_driver_pkg")
    [[ -n "$webview_gtk" ]] && to_install+=("$webview_gtk")

    log "Installing: ${to_install[*]}"
    if pkg_install "${to_install[@]}"; then
        success "System packages installed"
    else
        warn "Batch install failed — retrying packages one by one..."
        local pkg
        for pkg in "${to_install[@]}"; do
            if pkg_install "$pkg"; then
                success "$pkg"
            else
                warn "Could not install $pkg (continuing)"
            fi
        done
    fi

    if [[ -z "$chromium_pkg" ]]; then
        warn "Chromium package not found in repos (needed for --headless Katana and gowitness)."
    fi
}

# Go setup
go_version_ok() {
    command -v go &>/dev/null || return 1
    local ver major minor
    ver="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
    major="${ver%%.*}"
    minor="${ver#*.}"
    minor="${minor%%.*}"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    if (( major > MIN_GO_MAJOR )) || { (( major == MIN_GO_MAJOR )) && (( minor >= MIN_GO_MINOR )); }; then
        return 0
    fi
    return 1
}

install_go_official() {
    local arch go_arch tmp_dir tarball url
    arch="$(cpu_arch)"
    case "$arch" in
        x86_64|amd64) go_arch="amd64" ;;
        aarch64|arm64) go_arch="arm64" ;;
        armv7l|armhf) go_arch="armv6l" ;;
        i386|i686) go_arch="386" ;;
        *)
            error "Unsupported CPU architecture for official Go install: $arch"
            return 1
            ;;
    esac

    tarball="go${GO_FALLBACK_VERSION}.linux-${go_arch}.tar.gz"
    url="https://go.dev/dl/${tarball}"
    tmp_dir="$(mktemp -d)"

    log "Downloading Go ${GO_FALLBACK_VERSION} (${go_arch})..."
    if ! curl -fsSL "$url" -o "${tmp_dir}/${tarball}"; then
        error "Failed to download $url"
        rm -rf "$tmp_dir"
        return 1
    fi

    log "Installing Go to /usr/local/go..."
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "${tmp_dir}/${tarball}"
    rm -rf "$tmp_dir"

    export PATH="/usr/local/go/bin:$PATH"
    append_rc '/usr/local/go/bin' '# Official Go toolchain
export PATH="/usr/local/go/bin:$PATH"'
    success "Go $(go version | awk '{print $3}') installed from go.dev"
}

setup_go_env() {
    header "STEP 2: Go environment"

    export PATH="/usr/local/go/bin:$PATH"
    if [[ ! -d "$GOBIN" ]]; then
        $SUDO mkdir -p "$GOBIN"
        own_by_user "$GOPATH"
    fi
    $SUDO mkdir -p "$PY_USER_BIN" "$VENDOR_DIR"
    own_by_user "$PY_USER_BIN"
    own_by_user "$REAL_HOME/.reconpipe"

    if ! command -v go &>/dev/null; then
        warn "Go not found after package install — installing official toolchain..."
        install_go_official || {
            error "Could not install Go. Install manually: https://go.dev/dl/"
            exit 1
        }
    elif ! go_version_ok; then
        warn "Go $(go version 2>/dev/null | awk '{print $3}') is older than ${MIN_GO_MAJOR}.${MIN_GO_MINOR} — upgrading..."
        install_go_official || warn "Official Go install failed; continuing with system Go"
    fi

    if ! command -v go &>/dev/null; then
        error "Go is required but not available."
        exit 1
    fi

    append_rc 'GOBIN' '# Go binaries (ReconPipe) — ahead of pip so ProjectDiscovery httpx wins
export GOPATH="$HOME/go"
export GOBIN="$HOME/go/bin"
export PATH="$GOBIN:$PATH"'

    append_rc '.local/bin' '# Python user binaries (ReconPipe)
export PATH="$PATH:$HOME/.local/bin"'

    export PATH="$GOBIN:$PY_USER_BIN:$PATH"
    success "Go: $(go version 2>/dev/null | awk '{print $3}')  GOBIN=$GOBIN"
}

# Python deps
run_pip() {
    run_as_user pip3 install --user "$@" -q 2>/dev/null && return 0
    run_as_user pip3 install --user "$@" -q --break-system-packages 2>/dev/null && return 0
    run_as_user python3 -m pip install --user "$@" -q --break-system-packages 2>/dev/null && return 0
    $SUDO pip3 install "$@" -q --break-system-packages 2>/dev/null && return 0
    return 1
}

install_pip_pkg() {
    local pkg=$1
    log "pip install $pkg..."
    if run_pip "$pkg"; then
        success "$pkg installed"
        return 0
    fi
    warn "$pkg failed — try: pip3 install $pkg --user --break-system-packages"
    return 1
}

install_python_deps() {
    header "STEP 3: Python dependencies"

    if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
        log "Installing from requirements.txt..."
        if run_pip -r "$SCRIPT_DIR/requirements.txt"; then
            success "requirements.txt installed"
        else
            warn "requirements.txt batch install failed — installing packages individually"
            install_pip_pkg aiohttp || true
            install_pip_pkg PyYAML || true
            install_pip_pkg nicegui || true
            install_pip_pkg pywebview || true
        fi
    else
        install_pip_pkg aiohttp || true
        install_pip_pkg PyYAML || true
        install_pip_pkg nicegui || true
        install_pip_pkg pywebview || true
    fi

    install_pip_pkg waymore || true
    install_pip_pkg boto3 || warn "boto3 is optional (cleaner AWS STS checks)"
    install_pip_pkg jsbeautifier || true
}

# Locate a tool in the places this installer writes to
find_tool() {
    local name=$1 p
    for p in "$SHARED_BIN/$name" "$GOBIN/$name" "$PY_USER_BIN/$name" \
             "/usr/local/bin/$name" "/usr/bin/$name" "/bin/$name"; do
        if [[ -x "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    if command -v "$name" &>/dev/null; then
        command -v "$name"
        return 0
    fi
    return 1
}

tool_present() {
    find_tool "$1" >/dev/null 2>&1
}

install_go_tool() {
    local name=$1
    local pkg=$2
    local extra_env="${3:-}"

    if tool_present "$name"; then
        log "$name already present — updating..."
    else
        log "Installing $name (go install; may take a few minutes)..."
    fi

    local out
    # Install as the real user into ~/go/bin — never as root into /root/go/bin.
    if out="$(run_as_user env GOPATH="$GOPATH" GOBIN="$GOBIN" ${extra_env} go install "$pkg" 2>&1)"; then
        if [[ -x "$GOBIN/$name" ]] || tool_present "$name"; then
            success "$name → $(find_tool "$name" 2>/dev/null || echo "$GOBIN/$name")"
            own_by_user "$GOBIN/$name" 2>/dev/null || true
            return 0
        fi
        warn "$name: go install reported success but $GOBIN/$name is missing"
        return 1
    fi
    error "$name failed:"
    echo -e "${DIM}$(printf '%s\n' "$out" | tail -5)${RESET}"
    return 1
}

try_pkg_tool() {
    local name=$1
    shift
    tool_present "$name" && return 0
    local pkg
    pkg="$(resolve_first_available "$@" || true)"
    if [[ -n "$pkg" ]]; then
        log "Installing $name from package $pkg..."
        pkg_install "$pkg" && tool_present "$name"
        return $?
    fi
    return 1
}

install_user_script() {
    local name=$1
    local body=$2
    mkdir -p "$PY_USER_BIN"
    printf '%s\n' "$body" > "$PY_USER_BIN/$name"
    chmod 0755 "$PY_USER_BIN/$name"
    own_by_user "$PY_USER_BIN/$name"
}

install_go_tools() {
    header "STEP 4: ProjectDiscovery tools (Go)"
    install_go_tool "chaos"     "github.com/projectdiscovery/chaos-client/cmd/chaos@latest" || true
    install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx@latest" || true
    install_go_tool "katana"    "github.com/projectdiscovery/katana/cmd/katana@latest" || true
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" || true
    install_go_tool "dnsx"      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" || true
    install_go_tool "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
        || install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" \
        || warn "nuclei is optional (--nuclei)"
    install_go_tool "naabu"     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" "CGO_ENABLED=1" \
        || warn "naabu is optional (needs libpcap). Skip with --skip-naabu"

    header "STEP 5: Community tools (Go)"
    install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest" || true
    install_go_tool "gospider"    "github.com/jaeles-project/gospider@latest" || true
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest" || true
    install_go_tool "anew"        "github.com/tomnomnom/anew@latest" || true
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest" || true
    install_go_tool "hakrawler"   "github.com/hakluke/hakrawler@latest" || true
    # v2 CLI: `gowitness file -f …` (what ReconPipe calls). v3 changed to `scan file`.
    install_go_tool "gowitness"   "github.com/sensepost/gowitness@latest" || true
    install_go_tool "jsluice"     "github.com/BishopFox/jsluice/cmd/jsluice@latest" \
        || warn "jsluice is optional — katana works without it"

    # Amass v4 matches `amass enum -passive -d …`. v5 needs a newer Go toolchain.
    try_pkg_tool amass amass \
        || install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master" \
        || install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@v4.2.0" \
        || warn "amass is optional. Skip with --skip-amass"
}

install_trufflehog() {
    header "STEP 6: TruffleHog"
    if tool_present trufflehog; then
        success "trufflehog already installed"
        return 0
    fi

    log "Installing TruffleHog..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | $SUDO sh -s -- -b "$SHARED_BIN" >/dev/null 2>&1; then
        success "TruffleHog installed → $SHARED_BIN/trufflehog"
    elif install_go_tool "trufflehog" "github.com/trufflesecurity/trufflehog/v3@latest"; then
        success "TruffleHog installed via Go"
    else
        error "TruffleHog failed. Manual: https://github.com/trufflesecurity/trufflehog#installation"
    fi
}

install_gitleaks() {
    header "STEP 6b: Gitleaks"
    if tool_present gitleaks; then
        success "gitleaks already installed"
        return 0
    fi
    log "Installing Gitleaks..."
    if try_pkg_tool gitleaks gitleaks \
        || install_go_tool "gitleaks" "github.com/zricethezav/gitleaks/v8@latest" \
        || install_go_tool "gitleaks" "github.com/gitleaks/gitleaks/v8@latest"; then
        success "Gitleaks installed"
    else
        warn "Gitleaks is optional. Manual: go install github.com/zricethezav/gitleaks/v8@latest"
    fi
}

install_jsleak() {
    header "STEP 6c: jsleak"
    if tool_present jsleak; then
        success "jsleak already installed"
        return 0
    fi
    log "Installing jsleak..."
    if install_go_tool "jsleak" "github.com/byt3hx/jsleak@latest" \
        || install_go_tool "jsleak" "github.com/channyein1337/jsleak@latest"; then
        success "jsleak installed"
    else
        warn "jsleak is optional. Manual: go install github.com/byt3hx/jsleak@latest"
    fi
}

install_findomain() {
    header "STEP 6d: findomain"
    if tool_present findomain; then
        success "findomain already installed"
        return 0
    fi
    if try_pkg_tool findomain findomain; then
        success "findomain installed from distro package"
        return 0
    fi

    local zip_name dest tmp
    case "$(cpu_arch)" in
        x86_64|amd64) zip_name="findomain-linux.zip" ;;
        aarch64|arm64) zip_name="findomain-aarch64.zip" ;;
        i386|i686) zip_name="findomain-linux-i386.zip" ;;
        *)
            warn "No prebuilt findomain for $(cpu_arch). Skip with --skip-findomain"
            return 0
            ;;
    esac

    log "Downloading findomain ($zip_name)..."
    tmp="$(mktemp -d)"
    if curl -fsSL "https://github.com/findomain/findomain/releases/latest/download/${zip_name}" \
        -o "$tmp/findomain.zip" \
        && unzip -qo "$tmp/findomain.zip" -d "$tmp"; then
        dest="$(find "$tmp" -maxdepth 2 -type f -name 'findomain*' ! -name '*.zip' | head -1)"
        if [[ -n "$dest" ]]; then
            chmod +x "$dest"
            $SUDO mv "$dest" "$GOBIN/findomain"
            own_by_user "$GOBIN/findomain"
            success "findomain → $GOBIN/findomain"
        else
            warn "findomain zip had no binary"
        fi
    else
        warn "findomain download failed. Skip with --skip-findomain"
    fi
    rm -rf "$tmp"
}

install_spray() {
    header "STEP 6e: spray (opt-in --spray)"
    if tool_present spray; then
        success "spray already installed"
        return 0
    fi

    local asset
    case "$(cpu_arch)" in
        x86_64|amd64) asset="spray_linux_amd64" ;;
        aarch64|arm64) asset="spray_linux_arm64" ;;
        i386|i686) asset="spray_linux_386" ;;
        *)
            warn "No prebuilt spray for $(cpu_arch)"
            return 0
            ;;
    esac

    log "Downloading chainreactors/spray..."
    if curl -fsSL "https://github.com/chainreactors/spray/releases/latest/download/${asset}" \
        -o "$GOBIN/spray"; then
        chmod +x "$GOBIN/spray"
        own_by_user "$GOBIN/spray"
        success "spray → $GOBIN/spray"
        return 0
    fi
    if install_go_tool "spray" "github.com/chainreactors/spray@latest"; then
        return 0
    fi
    warn "spray is optional (only used with --spray). https://github.com/chainreactors/spray"
}

install_paramspider() {
    header "STEP 6f: ParamSpider"
    if tool_present paramspider; then
        success "paramspider already installed"
        return 0
    fi
    log "Installing ParamSpider..."
    if run_pip "git+https://github.com/devanshbatham/ParamSpider.git"; then
        success "paramspider installed"
        return 0
    fi
    local src="$VENDOR_DIR/ParamSpider"
    rm -rf "$src"
    if run_as_user git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git "$src" \
        && run_pip "$src"; then
        success "paramspider installed from git"
        own_by_user "$src"
        return 0
    fi
    warn "paramspider is optional. Skip with --skip-paramspider"
}

install_linkfinder() {
    header "STEP 6g: LinkFinder"
    if tool_present linkfinder; then
        success "linkfinder already installed"
        return 0
    fi

    local src="$VENDOR_DIR/LinkFinder"
    log "Cloning LinkFinder..."
    rm -rf "$src"
    if ! run_as_user git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git "$src"; then
        warn "LinkFinder clone failed (optional JS endpoint extractor)"
        return 0
    fi
    own_by_user "$src"
    run_pip -r "$src/requirements.txt" || run_pip jsbeautifier || true

    install_user_script linkfinder "#!/usr/bin/env bash
exec python3 \"$src/linkfinder.py\" \"\$@\""
    if tool_present linkfinder; then
        success "linkfinder → $PY_USER_BIN/linkfinder"
    else
        warn "LinkFinder wrapper was not created"
    fi
}

install_whatweb() {
    header "STEP 6h: WhatWeb"
    if tool_present whatweb; then
        success "whatweb already installed"
        return 0
    fi
    if try_pkg_tool whatweb whatweb; then
        success "whatweb installed from distro package"
        return 0
    fi
    local src="$VENDOR_DIR/WhatWeb"
    log "Cloning WhatWeb..."
    rm -rf "$src"
    if run_as_user git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git "$src"; then
        own_by_user "$src"
        install_user_script whatweb "#!/usr/bin/env bash
exec ruby \"$src/whatweb\" \"\$@\""
        success "whatweb → $PY_USER_BIN/whatweb"
    else
        warn "whatweb is optional. Skip with --skip-whatweb"
    fi
}
# will need to find a differnet version or package for that.
# install_wappalyzer() {
#     header "STEP 6i: Wappalyzer CLI"
#     if tool_present wappalyzer; then
#         success "wappalyzer already installed"
#         return 0
#     fi
#     if ! command -v npm &>/dev/null; then
#         warn "npm not found — skipping wappalyzer (optional tech fingerprint)"
#         return 0
#     fi
#     log "npm install -g wappalyzer (optional; pulls Chromium via puppeteer)..."
#     if run_as_user npm config set prefix "$REAL_HOME/.local" \
#         && run_as_user npm install -g wappalyzer; then
#         success "wappalyzer installed via npm"
#     else
#         warn "wappalyzer is optional. Manual: npm install -g wappalyzer"
#     fi
# }

install_nuclei_templates() {
    header "STEP 6j: Nuclei templates"
    if ! tool_present nuclei; then
        warn "nuclei missing — skip template update"
        return 0
    fi
    log "Updating nuclei templates..."
    if run_as_user nuclei -update-templates >/dev/null 2>&1 \
        || run_as_user "$(find_tool nuclei)" -update-templates >/dev/null 2>&1; then
        success "nuclei templates updated"
    else
        warn "nuclei -update-templates failed (run it later if you use --nuclei)"
    fi
}

link_tools_system_wide() {
    header "STEP 7: Expose tools in $SHARED_BIN"
    local tool src linked=0
    $SUDO mkdir -p "$SHARED_BIN"

    for tool in "${TOOLS[@]}"; do
        src="$(find_tool "$tool")" || continue
        [[ "$src" == "$SHARED_BIN/"* || "$src" == /usr/bin/* || "$src" == /bin/* ]] && continue
        if $SUDO ln -sfn "$src" "$SHARED_BIN/$tool"; then
            linked=$((linked + 1))
        else
            warn "Could not link $tool into $SHARED_BIN"
        fi
    done

    success "Linked $linked tool(s) into $SHARED_BIN"
}

install_reconpipe_commands() {
    header "STEP 7b: reconpipe / reconpipe-gui commands"
    $SUDO mkdir -p "$SHARED_BIN"
    $SUDO chmod +x "$SCRIPT_DIR/reconpipe.py" "$SCRIPT_DIR/reconpipegui.py" 2>/dev/null || true
    if [[ -x "$SCRIPT_DIR/reconpipe.py" ]] || [[ -f "$SCRIPT_DIR/reconpipe.py" ]]; then
        $SUDO ln -sfn "$SCRIPT_DIR/reconpipe.py" "$SHARED_BIN/reconpipe"
        success "CLI: $SHARED_BIN/reconpipe"
    fi
}

verify_installs() {
    header "STEP 8: Verify installs"
    echo ""
    ALL_OK=true
    local tool path ver group

    echo -e "${BOLD}  Core${RESET}  ${DIM}(needed for a useful scan)${RESET}"
    for tool in "${CORE_TOOLS[@]}"; do
        if path="$(find_tool "$tool")"; then
            ver="$("$path" --version </dev/null 2>/dev/null || "$path" -version </dev/null 2>/dev/null || echo "")"
            ver="$(printf '%s\n' "$ver" | head -1 | cut -c1-80)"
            echo -e "  ${GREEN}✓${RESET} ${BOLD}$tool${RESET}  ${DIM}${path}  ${ver}${RESET}"
        else
            echo -e "  ${RED}✗${RESET} ${BOLD}$tool${RESET}  ${DIM}not installed${RESET}"
            ALL_OK=false
        fi
    done

    echo ""
    echo -e "${BOLD}  Extra${RESET}  ${DIM}(ReconPipe skips these if missing)${RESET}"
    for tool in "${EXTRA_TOOLS[@]}"; do
        if path="$(find_tool "$tool")"; then
            echo -e "  ${GREEN}✓${RESET} ${BOLD}$tool${RESET}  ${DIM}${path}${RESET}"
        else
            echo -e "  ${YELLOW}○${RESET} ${BOLD}$tool${RESET}  ${DIM}not installed${RESET}"
        fi
    done

    echo ""
    if command -v python3 &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} ${BOLD}python3${RESET}  ${DIM}$(command -v python3)  $(python3 --version 2>/dev/null)${RESET}"
    else
        echo -e "  ${RED}✗${RESET} ${BOLD}python3${RESET}"
        ALL_OK=false
    fi
    if command -v go &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} ${BOLD}go${RESET}  ${DIM}$(command -v go)  $(go version 2>/dev/null | awk '{print $3}')${RESET}"
    fi
}

print_api_key_hint() {
    header "STEP 9: ProjectDiscovery API key"
    echo ""
    if [[ -z "${PDCP_API_KEY:-}" && -z "${CHAOS_KEY:-}" ]]; then
        warn "No Chaos/PDCP API key found."
        echo -e "  Get your free key at: ${CYAN}https://cloud.projectdiscovery.io${RESET}"
        echo -e "  Then add to your shell:"
        echo -e "  ${DIM}echo 'export PDCP_API_KEY=your_key' >> ~/.bashrc && source ~/.bashrc${RESET}"
        echo -e "  Or save it in the GUI (writes ~/.reconpipe/keys.yaml)."
    else
        success "API key detected in environment"
    fi
}

install_gui_launcher() {
    header "Desktop GUI launcher"
    local launcher="$SHARED_BIN/reconpipe-gui"
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp" <<EOF
#!/usr/bin/env bash
cd "$SCRIPT_DIR"
exec python3 "$SCRIPT_DIR/reconpipegui.py" "\$@"
EOF
    $SUDO install -m 0755 "$tmp" "$launcher"
    rm -f "$tmp"
    success "Launcher: $launcher"

    local apps="$REAL_HOME/.local/share/applications"
    run_as_user mkdir -p "$apps"
    local desktop="$apps/reconpipe.desktop"
    run_as_user tee "$desktop" >/dev/null <<EOF
[Desktop Entry]
Type=Application
Name=ReconPipe
Comment=API key leak hunter (desktop GUI)
Exec=$launcher
Path=$SCRIPT_DIR
Terminal=false
Categories=Security;Development;
StartupNotify=true
EOF
    own_by_user "$desktop"
    success "Menu entry: $desktop"
}

# Main
detect_os
install_system_packages
setup_go_env
install_python_deps
install_go_tools
install_trufflehog
install_gitleaks
install_jsleak
install_findomain
install_spray
install_paramspider
install_linkfinder
install_whatweb
# install_wappalyzer
install_nuclei_templates
link_tools_system_wide
install_reconpipe_commands
install_gui_launcher
verify_installs
print_api_key_hint

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Installation complete!${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
if $ALL_OK; then
    echo -e "  ${GREEN}${BOLD}Core tools are in place.${RESET} Extra scanners listed above are optional."
else
    echo -e "  ${YELLOW}Some core tools are missing — check the ✗ entries above.${RESET}"
    echo -e "  ${DIM}ReconPipe still runs; missing binaries are skipped.${RESET}"
fi
echo ""
echo -e "  Distro:             ${CYAN}$DISTRO_NAME${RESET}"
echo -e "  Installed for:      ${CYAN}$REAL_USER${RESET}  ${DIM}($GOBIN, linked into $SHARED_BIN)${RESET}"
echo -e "  Reload your shell:  ${CYAN}source ~/.bashrc${RESET}  (or ~/.zshrc)"
echo -e "  Run the pipeline:   ${CYAN}python3 $SCRIPT_DIR/reconpipe.py -d target.com${RESET}"
echo -e "                      ${DIM}or: reconpipe -d target.com${RESET}"
echo -e "  Launch the GUI:     ${CYAN}reconpipe-gui${RESET}  ${DIM}(desktop window, not Firefox)${RESET}"
echo -e "                      ${DIM}or: python3 $SCRIPT_DIR/reconpipegui.py${RESET}"
echo -e "  Browser fallback:   ${CYAN}python3 $SCRIPT_DIR/reconpipegui.py --browser${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo ""
