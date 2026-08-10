#!/usr/bin/env bash
#  ReconPipe Installer
#  Installs dependencies for reconpipe.py on major Linux distros
#  (Debian, Ubuntu, Kali, Mint, Fedora, RHEL, Arch, openSUSE, and derivatives)

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

# Banner
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

install_system_packages() {
    header "STEP 1: System packages"

    log "Refreshing package indexes ($PKG_MGR)..."
    pkg_update

    local base_pkgs=()
    local go_pkg=""
    local chromium_pkg=""
    local chromium_driver_pkg=""

    case "$PKG_MGR" in
        apt)
            base_pkgs=(curl wget git python3 python3-pip python3-venv unzip ca-certificates)
            # build tools (name differs slightly across Debian family)
            if pkg_available build-essential; then
                base_pkgs+=(build-essential)
            else
                base_pkgs+=(gcc g++ make)
            fi
            go_pkg="$(resolve_first_available golang-go golang go || true)"
            chromium_pkg="$(resolve_first_available chromium chromium-browser || true)"
            chromium_driver_pkg="$(resolve_first_available chromium-driver chromedriver || true)"
            ;;
        dnf|yum)
            base_pkgs=(curl wget git python3 python3-pip unzip ca-certificates gcc gcc-c++ make)
            go_pkg="$(resolve_first_available golang go || true)"
            chromium_pkg="$(resolve_first_available chromium || true)"
            chromium_driver_pkg="$(resolve_first_available chromedriver || true)"
            ;;
        pacman)
            base_pkgs=(curl wget git python python-pip unzip ca-certificates base-devel)
            go_pkg="$(resolve_first_available go || true)"
            chromium_pkg="$(resolve_first_available chromium || true)"
            chromium_driver_pkg="$(resolve_first_available chromedriver || true)"
            ;;
        zypper)
            base_pkgs=(curl wget git python3 python3-pip unzip ca-certificates gcc gcc-c++ make)
            go_pkg="$(resolve_first_available go golang || true)"
            chromium_pkg="$(resolve_first_available chromium || true)"
            chromium_driver_pkg="$(resolve_first_available chromedriver || true)"
            ;;
    esac

    local to_install=("${base_pkgs[@]}")
    [[ -n "$go_pkg" ]] && to_install+=("$go_pkg")
    [[ -n "$chromium_pkg" ]] && to_install+=("$chromium_pkg")
    [[ -n "$chromium_driver_pkg" ]] && to_install+=("$chromium_driver_pkg")

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
        warn "Chromium package not found in repos (optional for some crawlers)."
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
    arch="$(uname -m)"
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
    for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$RC" ]] || [[ "$RC" == "$HOME/.bashrc" ]]; then
            touch "$RC"
            if ! grep -q '/usr/local/go/bin' "$RC" 2>/dev/null; then
                {
                    echo ''
                    echo '# Official Go toolchain'
                    echo 'export PATH="/usr/local/go/bin:$PATH"'
                } >> "$RC"
            fi
        fi
    done
    success "Go $(go version | awk '{print $3}') installed from go.dev"
}

setup_go_env() {
    header "STEP 2: Go environment"

    export GOPATH="${GOPATH:-$HOME/go}"
    export GOBIN="${GOBIN:-$HOME/go/bin}"
    export PATH="/usr/local/go/bin:$PATH:$GOBIN"
    mkdir -p "$GOBIN"

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

    for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$RC" ]] || [[ "$RC" == "$HOME/.bashrc" ]]; then
            touch "$RC"
            if ! grep -q 'GOBIN' "$RC" 2>/dev/null; then
                {
                    echo ''
                    echo '# Go binaries (ReconPipe)'
                    echo 'export GOPATH="$HOME/go"'
                    echo 'export GOBIN="$HOME/go/bin"'
                    echo 'export PATH="$PATH:$GOBIN"'
                } >> "$RC"
                success "Added Go env to $RC"
            fi
        fi
    done

    success "Go: $(go version 2>/dev/null | awk '{print $3}')  GOBIN=$GOBIN"
}

# Python deps
# Try common pip invocation styles (user install, system, PEP 668 break flag).
run_pip() {
    local -a args=("$@")
    if command -v pip3 &>/dev/null; then
        pip3 install --user "${args[@]}" -q 2>/dev/null && return 0
        pip3 install "${args[@]}" -q 2>/dev/null && return 0
        pip3 install --user "${args[@]}" -q --break-system-packages 2>/dev/null && return 0
        pip3 install "${args[@]}" -q --break-system-packages 2>/dev/null && return 0
    fi
    if command -v python3 &>/dev/null; then
        python3 -m pip install --user "${args[@]}" -q 2>/dev/null && return 0
        python3 -m pip install "${args[@]}" -q --break-system-packages 2>/dev/null && return 0
    fi
    return 1
}

install_pip_pkg() {
    local pkg=$1
    log "pip install $pkg..."
    if run_pip "$pkg"; then
        success "$pkg installed"
    else
        warn "$pkg failed — try: pip3 install $pkg --user --break-system-packages"
    fi
}

install_python_deps() {
    header "STEP 3: Python dependencies"

    if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
        log "Installing from requirements.txt..."
        if run_pip -r "$SCRIPT_DIR/requirements.txt"; then
            success "requirements.txt installed"
        else
            warn "requirements.txt batch install failed — installing packages individually"
            install_pip_pkg aiohttp
            install_pip_pkg PyYAML
        fi
    else
        install_pip_pkg aiohttp
        install_pip_pkg PyYAML
    fi

    install_pip_pkg waymore
}

# Ensure ~/.local/bin is on PATH for --user installs
ensure_user_bin_path() {
    export PATH="$HOME/.local/bin:$PATH"
    for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$RC" ]]; then
            if ! grep -q '\.local/bin' "$RC" 2>/dev/null; then
                {
                    echo ''
                    echo '# Python user binaries'
                    echo 'export PATH="$HOME/.local/bin:$PATH"'
                } >> "$RC"
            fi
        fi
    done
}

# Go tools
install_go_tool() {
    local name=$1
    local pkg=$2
    if command -v "$name" &>/dev/null; then
        success "$name already installed — updating..."
        go install "$pkg" 2>/dev/null && success "$name updated" || warn "$name update failed"
    else
        log "Installing $name..."
        if go install "$pkg" 2>/dev/null; then
            success "$name installed → $GOBIN/$name"
        else
            error "$name failed. Manual: go install $pkg"
        fi
    fi
}

install_go_tools() {
    header "STEP 4: ProjectDiscovery tools (Go)"
    install_go_tool "chaos"     "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "katana"    "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "dnsx"      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

    header "STEP 5: Community tools (Go)"
    install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "gospider"    "github.com/jaeles-project/gospider@latest"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
    install_go_tool "anew"        "github.com/tomnomnom/anew@latest"

    log "Installing jsluice (optional katana enhancement)..."
    if go install github.com/BishopFox/jsluice/cmd/jsluice@latest 2>/dev/null; then
        success "jsluice installed"
    else
        warn "jsluice failed (optional — katana works without it)"
    fi
}

install_trufflehog() {
    header "STEP 6: TruffleHog"
    if command -v trufflehog &>/dev/null; then
        success "trufflehog already installed"
        return 0
    fi

    log "Installing TruffleHog..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | $SUDO sh -s -- -b /usr/local/bin 2>/dev/null; then
        success "TruffleHog installed → /usr/local/bin/trufflehog"
    elif go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null; then
        success "TruffleHog installed via Go"
    else
        error "TruffleHog failed. Manual: https://github.com/trufflesecurity/trufflehog#installation"
    fi
}

verify_installs() {
    header "STEP 7: Verify installs"
    echo ""
    local tools=(chaos httpx katana subfinder dnsx gau gospider waybackurls jsluice trufflehog anew waymore)
    ALL_OK=true
    local tool ver

    # Pick up freshly installed binaries without requiring a new shell
    export PATH="/usr/local/go/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"

    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            ver="$("$tool" --version 2>/dev/null || "$tool" -version 2>/dev/null || echo "found")"
            ver="$(printf '%s\n' "$ver" | head -1)"
            echo -e "  ${GREEN}✓${RESET} ${BOLD}$tool${RESET}  ${DIM}$ver${RESET}"
        else
            echo -e "  ${YELLOW}✗${RESET} ${BOLD}$tool${RESET}  ${DIM}not found in PATH${RESET}"
            ALL_OK=false
        fi
    done
}

print_api_key_hint() {
    header "STEP 8: ProjectDiscovery API key"
    echo ""
    if [[ -z "${PDCP_API_KEY:-}" && -z "${CHAOS_KEY:-}" ]]; then
        warn "No Chaos/PDCP API key found."
        echo -e "  Get your free key at: ${CYAN}https://cloud.projectdiscovery.io${RESET}"
        echo -e "  Then add to your shell:"
        echo -e "  ${DIM}echo 'export PDCP_API_KEY=your_key' >> ~/.bashrc && source ~/.bashrc${RESET}"
    else
        success "API key detected in environment"
    fi
}

# Main
detect_os
install_system_packages
setup_go_env
ensure_user_bin_path
install_python_deps
install_go_tools
install_trufflehog
verify_installs
print_api_key_hint

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Installation complete!${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
if $ALL_OK; then
    echo -e "  ${GREEN}${BOLD}All tools installed successfully.${RESET}"
else
    echo -e "  ${YELLOW}Some tools missing — check warnings above.${RESET}"
fi
echo ""
echo -e "  Distro:             ${CYAN}$DISTRO_NAME${RESET}"
echo -e "  Reload your shell:  ${CYAN}source ~/.bashrc${RESET}  (or ~/.zshrc)"
echo -e "  Run the pipeline:   ${CYAN}python3 reconpipe.py -d target.com${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo ""
