#!/usr/bin/env bash
# claude-guardrails installer
# Downloads and installs the Rust binary to ~/.claude/guardrails

set -euo pipefail

REPO="leegonzales/claude-guardrails"
TARGET_DIR="${HOME}/.claude/guardrails"
SETTINGS_FILE="${HOME}/.claude/settings.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Detect platform
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64) ARCH="x86_64" ;;
        arm64|aarch64) ARCH="aarch64" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac

    case "$OS" in
        darwin) TARGET="${ARCH}-apple-darwin" ;;
        linux) TARGET="${ARCH}-unknown-linux-gnu" ;;
        *) error "Unsupported OS: $OS" ;;
    esac

    echo "$TARGET"
}

# Check for required tools
check_requirements() {
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
    fi

    if ! command -v jq &> /dev/null; then
        warn "jq not found - settings.json won't be automatically configured"
        warn "Install with: brew install jq (macOS) or apt install jq (Linux)"
        HAS_JQ=false
    else
        HAS_JQ=true
    fi
}

# Download from GitHub releases
download_binary() {
    local target=$1
    local version=${2:-latest}

    step "Detecting latest version..."

    if [[ "$version" == "latest" ]]; then
        version=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ -z "$version" ]]; then
            warn "Could not detect latest version, trying local build..."
            return 1
        fi
    fi

    info "Version: $version"

    local url="https://github.com/$REPO/releases/download/$version/claude-guardrails-$target"

    step "Downloading binary..."
    if curl -fsSL "$url" -o "${TARGET_DIR}/claude-guardrails" 2>/dev/null; then
        chmod +x "${TARGET_DIR}/claude-guardrails"
        info "Downloaded from GitHub releases"
        return 0
    else
        warn "Could not download from releases, trying local build..."
        return 1
    fi
}

# Build locally with cargo
build_locally() {
    step "Building from source..."

    if ! command -v cargo &> /dev/null; then
        error "cargo not found. Install Rust from https://rustup.rs/"
    fi

    # Check if we're in the project directory
    if [[ -f "Cargo.toml" ]]; then
        cargo build --release
        cp target/release/claude-guardrails "${TARGET_DIR}/"
        chmod +x "${TARGET_DIR}/claude-guardrails"
        info "Built from source successfully"
    else
        error "Not in project directory and could not download binary"
    fi
}

# Configure settings.json
configure_hook() {
    if [[ "$HAS_JQ" != "true" ]]; then
        warn "Skipping settings.json configuration (jq not installed)"
        echo ""
        echo "Add this to your ~/.claude/settings.json manually:"
        cat << 'EOF'
{
  "hooks": {
    "PreToolUse": [{
      "type": "command",
      "command": "~/.claude/guardrails/claude-guardrails",
      "timeout": 5000,
      "tools": ["Bash", "Read", "Edit", "Write"]
    }]
  }
}
EOF
        return
    fi

    step "Configuring Claude Code hook..."

    # Hook configuration
    local HOOK_ENTRY='{
        "type": "command",
        "command": "~/.claude/guardrails/claude-guardrails",
        "timeout": 5000,
        "tools": ["Bash", "Read", "Edit", "Write"]
    }'

    if [[ -f "$SETTINGS_FILE" ]]; then
        local EXISTING
        EXISTING=$(cat "$SETTINGS_FILE")

        # Check if hooks.PreToolUse exists
        if echo "$EXISTING" | jq -e '.hooks.PreToolUse' > /dev/null 2>&1; then
            # Check if our hook is already there
            if echo "$EXISTING" | jq -e '.hooks.PreToolUse[] | select(.command | contains("claude-guardrails"))' > /dev/null 2>&1; then
                info "Guardrails hook already configured"
            else
                # Add our hook to existing PreToolUse array
                local MERGED
                MERGED=$(echo "$EXISTING" | jq --argjson hook "$HOOK_ENTRY" '.hooks.PreToolUse += [$hook]')
                echo "$MERGED" > "$SETTINGS_FILE"
                info "Added guardrails hook to existing PreToolUse"
            fi
        elif echo "$EXISTING" | jq -e '.hooks' > /dev/null 2>&1; then
            # hooks exists but not PreToolUse
            local MERGED
            MERGED=$(echo "$EXISTING" | jq --argjson hook "$HOOK_ENTRY" '.hooks.PreToolUse = [$hook]')
            echo "$MERGED" > "$SETTINGS_FILE"
            info "Added PreToolUse hooks"
        else
            # No hooks at all
            local MERGED
            MERGED=$(echo "$EXISTING" | jq --argjson hook "$HOOK_ENTRY" '. + {hooks: {PreToolUse: [$hook]}}')
            echo "$MERGED" > "$SETTINGS_FILE"
            info "Added hooks configuration"
        fi
    else
        # Create new settings file
        echo "$HOOK_ENTRY" | jq '{hooks: {PreToolUse: [.]}}' > "$SETTINGS_FILE"
        info "Created settings.json with hook"
    fi
}

# Create default config
create_default_config() {
    if [[ ! -f "${TARGET_DIR}/config.toml" ]]; then
        step "Creating default configuration..."
        cat > "${TARGET_DIR}/config.toml" << 'EOF'
# claude-guardrails configuration
# See: https://github.com/leegonzales/claude-guardrails

[general]
# Safety level: critical | high | strict
safety_level = "high"

# Enable audit logging
audit_log = true

# Path to audit log file
audit_path = "~/.claude/guardrails/audit.jsonl"

[overrides]
# Path to user allowlist file (create to add exceptions)
allowlist_file = "~/.claude/guardrails/allow.toml"

[bash]
# Block variable-based command execution ($cmd, $(cmd), `cmd`)
block_variable_commands = true

# Block dangerous pipe targets (| sh, | bash)
block_pipe_to_shell = true
EOF
        info "Created config.toml"
    fi
}

# Main installation
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           claude-guardrails installer                     ║"
    echo "║     Security guardrails for Claude Code YOLO mode         ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    check_requirements

    # Create target directory
    step "Creating ${TARGET_DIR}..."
    mkdir -p "${TARGET_DIR}"

    # Try to download, fall back to local build
    local TARGET
    TARGET=$(detect_platform)
    info "Platform: $TARGET"

    if ! download_binary "$TARGET"; then
        build_locally
    fi

    # Create default config
    create_default_config

    # Configure hook
    configure_hook

    # Verify installation
    step "Verifying installation..."
    if [[ -x "${TARGET_DIR}/claude-guardrails" ]]; then
        local VERSION
        VERSION=$("${TARGET_DIR}/claude-guardrails" --version 2>/dev/null || echo "unknown")
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        info "Installation complete!"
        echo ""
        echo "  Binary:    ${TARGET_DIR}/claude-guardrails"
        echo "  Config:    ${TARGET_DIR}/config.toml"
        echo "  Audit log: ${TARGET_DIR}/audit.jsonl"
        echo "  Version:   $VERSION"
        echo ""
        echo "  Test with: echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}' | ${TARGET_DIR}/claude-guardrails"
        echo ""
        echo "  To disable temporarily: GUARDRAILS_DISABLED=1 claude"
        echo "  To warn only:           GUARDRAILS_WARN_ONLY=1 claude"
        echo ""
        echo "═══════════════════════════════════════════════════════════"
    else
        error "Installation verification failed"
    fi
}

main "$@"
