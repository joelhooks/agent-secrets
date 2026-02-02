#!/usr/bin/env bash
#
# agent-secrets installer
# Works on: macOS, Linux, WSL
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/joelhooks/agent-secrets/main/install.sh | bash
#   # or
#   ./install.sh
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}==>${NC} $1"; }
success() { echo -e "${GREEN}==>${NC} $1"; }
warn() { echo -e "${YELLOW}==>${NC} $1"; }
error() { echo -e "${RED}==>${NC} $1"; exit 1; }

# Detect OS and architecture
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *) error "Unsupported OS: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac

    # Detect WSL
    if [[ "$os" == "linux" ]] && grep -qi microsoft /proc/version 2>/dev/null; then
        info "Detected WSL environment"
    fi

    echo "${os}_${arch}"
}

# Find install directory
get_install_dir() {
    # Prefer /usr/local/bin if writable, else ~/.local/bin
    if [[ -w /usr/local/bin ]]; then
        echo "/usr/local/bin"
    elif [[ -d "$HOME/.local/bin" ]] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
        echo "$HOME/.local/bin"
    else
        error "Cannot find writable install directory. Try running with sudo."
    fi
}

# Check if Go is installed
has_go() {
    command -v go &>/dev/null
}

# Install via go install (preferred if Go available)
install_with_go() {
    info "Installing with 'go install'..."
    go install github.com/joelhooks/agent-secrets/cmd/secrets@latest

    # Find where go installed it
    local gobin="${GOBIN:-$(go env GOPATH)/bin}"
    if [[ -f "$gobin/secrets" ]]; then
        success "Installed to $gobin/secrets"
        echo ""
        warn "Make sure $gobin is in your PATH"
        return 0
    fi
    return 1
}

# Install from source
install_from_source() {
    local install_dir="$1"
    local tmp_dir

    # Check for Go
    if ! has_go; then
        error "Go is required to build from source. Install Go from https://go.dev/dl/ or use Homebrew: brew install go"
    fi

    info "Building from source..."

    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    cd "$tmp_dir"

    info "Cloning repository..."
    git clone --depth 1 https://github.com/joelhooks/agent-secrets.git
    cd agent-secrets

    info "Building..."
    go build -o secrets ./cmd/secrets

    info "Installing to $install_dir..."
    if [[ -w "$install_dir" ]]; then
        mv secrets "$install_dir/"
    else
        sudo mv secrets "$install_dir/"
    fi

    success "Installed to $install_dir/secrets"
}

# Get latest release version from GitHub
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/joelhooks/agent-secrets/releases/latest" 2>/dev/null | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo ""
}

# Download pre-built binary
install_from_release() {
    local install_dir="$1"
    local platform="$2"
    local version="${3:-}"
    local tmp_dir

    # Get latest version if not specified
    if [[ -z "$version" ]]; then
        info "Checking for latest release..."
        version=$(get_latest_version)
    fi

    if [[ -z "$version" ]]; then
        warn "No releases found, building from source..."
        install_from_source "$install_dir"
        return
    fi

    local version_num="${version#v}"  # Remove 'v' prefix for filename
    local filename="agent-secrets_${version_num}_${platform}.tar.gz"
    local url="https://github.com/joelhooks/agent-secrets/releases/download/${version}/${filename}"

    info "Downloading ${version}..."

    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    if curl -fsSL "$url" -o "$tmp_dir/release.tar.gz" 2>/dev/null; then
        cd "$tmp_dir"
        tar -xzf release.tar.gz

        info "Installing to $install_dir..."
        if [[ -w "$install_dir" ]]; then
            mv secrets "$install_dir/"
        else
            sudo mv secrets "$install_dir/"
        fi

        success "Installed $version to $install_dir/secrets"
    else
        warn "Failed to download release, building from source..."
        install_from_source "$install_dir"
    fi
}

# Verify installation
verify_install() {
    if command -v secrets &>/dev/null; then
        success "Installation verified: $(command -v secrets)"
        secrets --help | head -5
        return 0
    else
        warn "Installation complete but 'secrets' not found in PATH"
        echo ""
        echo "Add the install directory to your PATH:"
        echo '  export PATH="$HOME/.local/bin:$PATH"'
        echo ""
        echo "Add this line to your ~/.bashrc or ~/.zshrc"
        return 1
    fi
}

# Optional: initialize secrets store
maybe_init() {
    echo ""
    read -p "Initialize secrets store now? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Initializing secrets store..."
        secrets init
        success "Secrets store initialized at ~/.agent-secrets/"
    else
        echo ""
        echo "Run 'secrets init' when ready to set up the encrypted store."
    fi
}

# Main
main() {
    echo ""
    echo "  █████╗  ██████╗ ███████╗███╗   ██╗████████╗"
    echo " ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝"
    echo " ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   "
    echo " ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   "
    echo " ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   "
    echo " ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   "
    echo "        ███████╗███████╗ ██████╗██████╗ ███████╗████████╗███████╗"
    echo "        ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝"
    echo "        ███████╗█████╗  ██║     ██████╔╝█████╗     ██║   ███████╗"
    echo "        ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   ╚════██║"
    echo "        ███████║███████╗╚██████╗██║  ██║███████╗   ██║   ███████║"
    echo "        ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝"
    echo ""
    echo "  Portable credential management for AI agents"
    echo ""

    local platform install_dir

    platform=$(detect_platform)
    info "Detected platform: $platform"

    install_dir=$(get_install_dir)
    info "Install directory: $install_dir"

    # Install method priority:
    # 1. Pre-built release (when available)
    # 2. go install (if Go available and user wants)
    # 3. Build from source

    if has_go; then
        echo ""
        read -p "Go detected. Use 'go install' (faster) or build from source? [go/source] " -r choice
        case "$choice" in
            go|Go|GO)
                install_with_go && verify_install && maybe_init
                exit 0
                ;;
            *)
                install_from_source "$install_dir"
                ;;
        esac
    else
        install_from_release "$install_dir" "$platform"
    fi

    verify_install
    maybe_init

    echo ""
    success "Done! Run 'secrets --help' to get started."
}

main "$@"
