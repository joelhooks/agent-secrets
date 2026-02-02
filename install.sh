#!/usr/bin/env bash
# Install agent-secrets from GitHub releases
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/joelhooks/agent-secrets/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/joelhooks/agent-secrets/main/install.sh | bash -s -- --global
#   curl -fsSL https://raw.githubusercontent.com/joelhooks/agent-secrets/main/install.sh | bash -s -- --version v0.1.0
#   curl -fsSL https://raw.githubusercontent.com/joelhooks/agent-secrets/main/install.sh | bash -s -- --human
#
# Options:
#   --global      Install to /usr/local/bin (requires sudo)
#   --version V   Install specific version (default: latest)
#   --human       Human-readable output (default: JSON for agents)

set -euo pipefail

REPO="joelhooks/agent-secrets"
BINARY_NAME="secrets"
DEFAULT_INSTALL_DIR="${HOME}/.local/bin"
GLOBAL_INSTALL_DIR="/usr/local/bin"

# Defaults
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
VERSION=""
OUTPUT_MODE="json"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --global)
            INSTALL_DIR="$GLOBAL_INSTALL_DIR"
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --human)
            OUTPUT_MODE="human"
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Logging functions
log_json() {
    local level="$1"
    local message="$2"
    if [[ "$OUTPUT_MODE" == "json" ]]; then
        echo "{\"level\":\"$level\",\"message\":\"$message\"}" >&2
    fi
}

log_human() {
    if [[ "$OUTPUT_MODE" == "human" ]]; then
        echo "$1" >&2
    fi
}

error_exit() {
    local message="$1"
    if [[ "$OUTPUT_MODE" == "json" ]]; then
        echo "{\"success\":false,\"error\":\"$message\"}"
    else
        echo "Error: $message" >&2
    fi
    exit 1
}

# Detect platform
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        *)       error_exit "Unsupported OS: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)      arch="amd64" ;;
        arm64|aarch64)     arch="arm64" ;;
        *)                 error_exit "Unsupported architecture: $(uname -m)" ;;
    esac

    echo "${os}_${arch}"
}

# Get latest version from GitHub API
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/' || echo ""
}

# Download and install binary
install_binary() {
    local platform="$1"
    local version="$2"
    local install_dir="$3"

    # Get version if not specified
    if [[ -z "$version" ]]; then
        log_json "info" "Fetching latest version"
        log_human "Fetching latest version..."
        version=$(get_latest_version)
        if [[ -z "$version" ]]; then
            error_exit "Failed to fetch latest version from GitHub"
        fi
    fi

    local version_num="${version#v}"
    local filename="agent-secrets_${version_num}_${platform}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${version}/${filename}"

    log_json "info" "Downloading ${version} for ${platform}"
    log_human "Downloading ${version}..."

    # Create temp directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    # Download release
    if ! curl -fsSL "$url" -o "$tmp_dir/release.tar.gz" 2>/dev/null; then
        error_exit "Failed to download release from $url"
    fi

    # Extract
    cd "$tmp_dir"
    if ! tar -xzf release.tar.gz 2>/dev/null; then
        error_exit "Failed to extract release archive"
    fi

    # Ensure install directory exists
    if [[ ! -d "$install_dir" ]]; then
        if ! mkdir -p "$install_dir" 2>/dev/null; then
            error_exit "Cannot create install directory: $install_dir"
        fi
    fi

    # Install binary
    log_json "info" "Installing to $install_dir"
    log_human "Installing to $install_dir..."

    if [[ -w "$install_dir" ]]; then
        mv "$BINARY_NAME" "$install_dir/"
    else
        if ! sudo mv "$BINARY_NAME" "$install_dir/" 2>/dev/null; then
            error_exit "Failed to install binary (permission denied)"
        fi
    fi

    chmod +x "$install_dir/$BINARY_NAME"

    echo "$version"
}

# Check if binary is in PATH
check_path() {
    local install_dir="$1"
    if command -v "$BINARY_NAME" &>/dev/null; then
        echo "true"
    elif [[ ":$PATH:" == *":$install_dir:"* ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# Main installation logic
main() {
    local platform version_installed in_path

    platform=$(detect_platform)
    log_json "info" "Detected platform: $platform"
    log_human "Platform: $platform"

    version_installed=$(install_binary "$platform" "$VERSION" "$INSTALL_DIR")

    in_path=$(check_path "$INSTALL_DIR")

    # Generate output
    if [[ "$OUTPUT_MODE" == "json" ]]; then
        # JSON output for agents
        cat <<EOF
{
  "success": true,
  "message": "Installed agent-secrets ${version_installed}",
  "data": {
    "version": "${version_installed}",
    "path": "${INSTALL_DIR}/${BINARY_NAME}",
    "in_path": ${in_path}
  },
  "actions": [
    {
      "name": "init",
      "description": "Initialize secrets store",
      "command": "secrets init"
    },
    {
      "name": "add_secret",
      "description": "Add a secret",
      "command": "secrets add <name>"
    },
    {
      "name": "lease_secret",
      "description": "Get time-bounded lease",
      "command": "secrets lease <name> --ttl 1h"
    }
$(if [[ "$in_path" == "false" ]]; then
cat <<INNER
    ,{
      "name": "add_to_path",
      "description": "Add to PATH",
      "command": "export PATH=\"${INSTALL_DIR}:\$PATH\""
    }
INNER
fi)
  ]
}
EOF
    else
        # Human-readable output
        echo ""
        echo "✓ Installed agent-secrets ${version_installed} to ${INSTALL_DIR}/${BINARY_NAME}"
        echo ""

        if [[ "$in_path" == "false" ]]; then
            echo "Add to your PATH:"
            echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            echo ""
            echo "Add this line to your ~/.bashrc or ~/.zshrc"
            echo ""
        fi

        echo "Next steps:"
        echo "  secrets init              # Initialize encrypted store"
        echo "  secrets add <name>        # Add a secret"
        echo "  secrets lease <name>      # Get time-bounded lease"
        echo ""
        echo "Run 'secrets --help' for more commands"
    fi
}

main "$@"
