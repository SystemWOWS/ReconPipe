#!/bin/bash
#  ReconPipe Installer
#  Installs all dependencies for reconpipe.py on Kali/Debian/Ubuntu

set -e

# Colors
RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

log()     { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} ${CYAN}[*]${RESET} $1"; }
success() { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} ${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} ${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} ${RED}[-]${RESET} $1"; }
header()  { echo -e "\n${CYAN}${BOLD}── $1 ──────────────────────────────────────────${RESET}"; }

# Banner
echo -e "${CYAN}${BOLD}"
echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗██████╗ ███████╗"
echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║██╔══██╗██╔════╝"
echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝██║██████╔╝█████╗  "
echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔═══╝ ██║██╔═══╝ ██╔══╝  "
echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ██║██║     ███████╗"
echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝     ╚══════╝"
echo -e "${RESET}${DIM}  Installer — Kali Linux / Debian / Ubuntu${RESET}"
echo ""

#  Root check
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. Some installs may require sudo."
    SUDO="sudo"
else
    SUDO=""
fi

# Detect OS 
if ! command -v apt-get &>/dev/null; then
    error "apt-get not found. This installer supports Debian/Ubuntu/Kali only."
    exit 1
fi


header "STEP 1: System packages"

log "Updating apt..."
$SUDO apt-get update -qq

log "Installing base dependencies..."
$SUDO apt-get install -y -qq \
    curl wget git python3 python3-pip golang-go \
    chromium chromium-driver \
    build-essential unzip 2>/dev/null || \
$SUDO apt-get install -y -qq \
    curl wget git python3 python3-pip golang-go \
    chromium-browser \
    build-essential unzip

success "System packages installed"


header "STEP 2: Go environment"

# Ensure GOPATH/GOBIN is in PATH
export GOPATH="$HOME/go"
export GOBIN="$HOME/go/bin"
export PATH="$PATH:$GOBIN"

# Add to shell rc files permanently
for RC in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [[ -f "$RC" ]]; then
        if ! grep -q "GOBIN" "$RC"; then
            echo '' >> "$RC"
            echo '# Go binaries' >> "$RC"
            echo 'export GOPATH="$HOME/go"' >> "$RC"
            echo 'export GOBIN="$HOME/go/bin"' >> "$RC"
            echo 'export PATH="$PATH:$GOBIN"' >> "$RC"
            success "Added Go env to $RC"
        fi
    fi
done

GO_VERSION=$(go version 2>/dev/null | awk '{print $3}')
success "Go: $GO_VERSION"


header "STEP 3: Python dependencies"

install_pip() {
    local pkg=$1
    log "pip install $pkg..."
    if pip3 install "$pkg" -q 2>/dev/null; then
        success "$pkg installed"
    elif pip3 install "$pkg" -q --break-system-packages 2>/dev/null; then
        success "$pkg installed (--break-system-packages)"
    else
        warn "$pkg failed — try: pip3 install $pkg --break-system-packages"
    fi
}

install_pip aiohttp
install_pip waymore


header "STEP 4: ProjectDiscovery tools (Go)"

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

install_go_tool "chaos"      "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
install_go_tool "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "katana"     "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "dnsx"       "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

header "STEP 5: Community tools (Go)"

install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "gospider"     "github.com/jaeles-project/gospider@latest"
install_go_tool "waybackurls"  "github.com/tomnomnom/waybackurls@latest"
install_go_tool "anew"         "github.com/tomnomnom/anew@latest"

# jsluice (optional - enhances katana JS analysis)
log "Installing jsluice (optional katana enhancement)..."
if go install github.com/BishopFox/jsluice/cmd/jsluice@latest 2>/dev/null; then
    success "jsluice installed"
else
    warn "jsluice failed (optional — katana works without it)"
fi

header "STEP 6: TruffleHog"
if command -v trufflehog &>/dev/null; then
    success "trufflehog already installed"
else
    log "Installing TruffleHog..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | $SUDO sh -s -- -b /usr/local/bin 2>/dev/null; then
        success "TruffleHog installed → /usr/local/bin/trufflehog"
    else
        warn "TruffleHog curl install failed — trying Go install..."
        if go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null; then
            success "TruffleHog installed via Go"
        else
            error "TruffleHog failed. Manual: https://github.com/trufflesecurity/trufflehog#installation"
        fi
    fi
fi

header "STEP 7: Verify installs"
echo ""
TOOLS=(chaos httpx katana subfinder dnsx gau gospider waybackurls jsluice trufflehog anew waymore)
ALL_OK=true

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        VER=$(("$tool" --version 2>/dev/null || "$tool" -version 2>/dev/null || echo "found") | head -1)
        echo -e "  ${GREEN}✓${RESET} ${BOLD}$tool${RESET}  ${DIM}$VER${RESET}"
    else
        echo -e "  ${YELLOW}✗${RESET} ${BOLD}$tool${RESET}  ${DIM}not found${RESET}"
        ALL_OK=false
    fi
done

header "STEP 8: ProjectDiscovery API key"
echo ""
if [[ -z "$PDCP_API_KEY" && -z "$CHAOS_KEY" ]]; then
    warn "No Chaos/PDCP API key found."
    echo -e "  Get your free key at: ${CYAN}https://cloud.projectdiscovery.io${RESET}"
    echo -e "  Then add to your shell:"
    echo -e "  ${DIM}echo 'export PDCP_API_KEY=your_key' >> ~/.bashrc && source ~/.bashrc${RESET}"
else
    success "API key detected in environment"
fi

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
echo -e "  Reload your shell:  ${CYAN}source ~/.bashrc${RESET}"
echo -e "  Run the pipeline:   ${CYAN}python3 reconpipe.py -d target.com${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo ""