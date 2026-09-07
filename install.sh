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
SHARED_BIN="/usr/local/bin"

TOOLS=(chaos httpx katana subfinder dnsx gau gospider waybackurls jsluice trufflehog anew waymore)

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
TOOL_PATH="/usr/local/go/bin:$SHARED_BIN:/usr/bin:/bin:$GOBIN:$PY_USER_BIN"

success "Installing for user: $REAL_USER  (home: $REAL_HOME)"

# Run a command as the real user with a predictable Go/Python environment
run_as_user() {
    if [[ "$REAL_USER" == "$(id -un)" ]]; then
        env HOME="$REAL_HOME" GOPATH="$GOPATH" GOBIN="$GOBIN" PATH="$TOOL_PATH:$PATH" "$@"
    else
        sudo -u "$REAL_USER" -H env GOPATH="$GOPATH" GOBIN="$GOBIN" PATH="$TOOL_PATH:$PATH" "$@"
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

    local webview_gtk=""

    case "$PKG_MGR" in
        apt)
            base_pkgs=(curl wget git python3 python3-pip python3-venv unzip ca-certificates)
            # build tools (name differs slightly across Debian family)
            if pkg_available build-essential; then
                base_pkgs+=(build-essential)
            else
                base_pkgs+=(gcc g++ make)
            fi
            # pywebview GTK backend (desktop GUI, not Firefox)
            if pkg_available python3-gi; then
                base_pkgs+=(python3-gi)
            fi
            if pkg_available python3-gi-cairo; then
                base_pkgs+=(python3-gi-cairo)
            fi
            if pkg_available gir1.2-gtk-3.0; then
                base_pkgs+=(gir1.2-gtk-3.0)
            fi
            go_pkg="$(resolve_first_available golang-go golang go || true)"
            chromium_pkg="$(resolve_first_available chromium chromium-browser || true)"
            chromium_driver_pkg="$(resolve_first_available chromium-driver chromedriver || true)"
            webview_gtk="$(resolve_first_available gir1.2-webkit2-4.1 gir1.2-webkit2-4.0 || true)"
            ;;
        dnf|yum)
            base_pkgs=(curl wget git python3 python3-pip unzip ca-certificates gcc gcc-c++ make)
            if pkg_available python3-gobject; then
                base_pkgs+=(python3-gobject)
            fi
            go_pkg="$(resolve_first_available golang go || true)"
            chromium_pkg="$(resolve_first_available chromium || true)"
            chromium_driver_pkg="$(resolve_first_available chromedriver || true)"
            webview_gtk="$(resolve_first_available webkit2gtk4.1 webkit2gtk4.0 webkit2gtk3 || true)"
            ;;
        pacman)
            base_pkgs=(curl wget git python python-pip unzip ca-certificates base-devel)
            if pkg_available python-gobject; then
                base_pkgs+=(python-gobject)
            fi
            if pkg_available gtk3; then
                base_pkgs+=(gtk3)
            fi
            go_pkg="$(resolve_first_available go || true)"
            chromium_pkg="$(resolve_first_available chromium || true)"
            chromium_driver_pkg="$(resolve_first_available chromedriver || true)"
            webview_gtk="$(resolve_first_available webkit2gtk-4.1 webkit2gtk || true)"
            ;;
        zypper)
            base_pkgs=(curl wget git python3 python3-pip unzip ca-certificates gcc gcc-c++ make)
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
            install_pip_pkg nicegui
            install_pip_pkg pywebview
        fi
    else
        install_pip_pkg aiohttp
        install_pip_pkg PyYAML
        install_pip_pkg nicegui
        install_pip_pkg pywebview
    fi

    install_pip_pkg waymore
}

# Go tools
install_go_tool() {
    local name=$1
    local pkg=$2
    if [[ -x "$GOBIN/$name" ]]; then
        log "$name already present — updating..."
    else
        log "Installing $name..."
    fi

    local out
    if out="$(run_as_user go install "$pkg" 2>&1)"; then
        if [[ -x "$GOBIN/$name" ]]; then
            success "$name → $GOBIN/$name"
            return 0
        fi
        warn "$name: go install reported success but $GOBIN/$name is missing"
        return 1
    fi

    error "$name failed:"
    echo -e "${DIM}$(printf '%s\n' "$out" | tail -3)${RESET}"
    return 1
}



install_go_tool() {
    local tool_name="$1"
    local tool_path="$2"
    
    echo -n "Installing $tool_name... "
    
    go install "$tool_path" &>/dev/null &
    local pid=$!
    
    local elapsed=0
    # Loops while go install process running
    while kill -0 $pid 2>/dev/null; do
        printf "\rInstalling %s... [%ds elapsed]" "$tool_name" "$elapsed"
        sleep 1
        ((elapsed++))
    done

    wait $pid
    local exit_status=$?

    if [ $exit_status -eq 0 ]; then
        printf "\rinstalling %s... Done (%ds total)\n" "$tool_name" "$elapsed"
        return 0
    else
        printf "\rInstalling %s... Failed (%ds total)\n" "$tool_name" "$elapsed"
        return 1
    fi
}


install_go_tools() {
    header "STEP 4: ProjectDiscovery tools (Go)"
    install_go_tool "chaos"     "github.com/projectdiscovery/chaos-client/cmd/chaos@latest" || true
    install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx@latest" || true
    install_go_tool "katana"    "github.com/projectdiscovery/katana/cmd/katana@latest" || true
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" || true
    install_go_tool "dnsx"      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" || true

    header "STEP 5: Community tools (Go)"
    install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest" || true
    install_go_tool "gospider"    "github.com/jaeles-project/gospider@latest" || true
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest" || true
    install_go_tool "anew"        "github.com/tomnomnom/anew@latest" || true
    install_go_tool "jsluice"     "github.com/BishopFox/jsluice/cmd/jsluice@latest" \
        || warn "jsluice is optional — katana works without it"
}

install_trufflehog() {
    header "STEP 6: TruffleHog"
    if [[ -x "$SHARED_BIN/trufflehog" ]]; then
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

# Locate a tool in the places this installer writes to
find_tool() {
    local name=$1 p
    for p in "$SHARED_BIN/$name" "$GOBIN/$name" "$PY_USER_BIN/$name" "/usr/bin/$name" "/bin/$name"; do
        if [[ -x "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}


# Symlink into /usr/local/bin so the tools resolve in any shell, including
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

verify_installs() {
    header "STEP 8: Verify installs"
    echo ""
    ALL_OK=true
    local tool path ver

    for tool in "${TOOLS[@]}"; do
        if path="$(find_tool "$tool")"; then
            ver="$("$path" --version </dev/null 2>/dev/null || "$path" -version </dev/null 2>/dev/null || echo "")"
            ver="$(printf '%s\n' "$ver" | head -1)"
            echo -e "  ${GREEN}✓${RESET} ${BOLD}$tool${RESET}  ${DIM}${path}  ${ver}${RESET}"
        else
            echo -e "  ${RED}✗${RESET} ${BOLD}$tool${RESET}  ${DIM}not installed${RESET}"
            ALL_OK=false
        fi
    done
}

print_api_key_hint() {
    header "STEP 9: ProjectDiscovery API key"
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
link_tools_system_wide
install_gui_launcher
verify_installs
print_api_key_hint

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Installation complete!${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
if $ALL_OK; then
    echo -e "  ${GREEN}${BOLD}All tools installed successfully.${RESET}"
else
    echo -e "  ${YELLOW}Some tools missing — check the ✗ entries above.${RESET}"
fi
echo ""
echo -e "  Distro:             ${CYAN}$DISTRO_NAME${RESET}"
echo -e "  Installed for:      ${CYAN}$REAL_USER${RESET}  ${DIM}($GOBIN, linked into $SHARED_BIN)${RESET}"
echo -e "  Reload your shell:  ${CYAN}source ~/.bashrc${RESET}  (or ~/.zshrc)"
echo -e "  Run the pipeline:   ${CYAN}python3 reconpipe.py -d target.com${RESET}"
echo -e "  Launch the GUI:     ${CYAN}reconpipe-gui${RESET}  ${DIM}(desktop window, not Firefox)${RESET}"
echo -e "                      ${DIM}or: python3 $SCRIPT_DIR/reconpipegui.py${RESET}"
echo -e "  Browser fallback:   ${CYAN}python3 reconpipegui.py --browser${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo ""
