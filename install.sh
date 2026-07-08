#!/bin/sh
# wardn installer — https://vibeguard.io
# Usage: curl -sSf https://install.vibeguard.io | sh
set -e

REPO="rohansx/wardn"
INSTALL_DIR="${WARDN_INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        *)
            echo "error: unsupported OS: $OS" >&2
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            echo "error: unsupported architecture: $ARCH" >&2
            exit 1
            ;;
    esac

    echo "${OS}-${ARCH}"
}

# Get latest release tag from GitHub API
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//'
    else
        echo "error: curl or wget required" >&2
        exit 1
    fi
}

# Download a file
download() {
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$1" -O "$2"
    fi
}

# Verify the downloaded archive against the .sha256 the release workflow
# publishes alongside it. Fails closed: a missing/mismatched checksum aborts
# the install rather than silently trusting an unverified binary.
verify_checksum() {
    archive="$1"
    checksum_file="$2"

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$(dirname "$archive")" && sha256sum -c "$(basename "$checksum_file")") >/dev/null 2>&1
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$(dirname "$archive")" && shasum -a 256 -c "$(basename "$checksum_file")") >/dev/null 2>&1
    else
        echo "warning: no sha256sum/shasum found — skipping checksum verification" >&2
        return 0
    fi
}

main() {
    echo "installing wardn..."

    PLATFORM="$(detect_platform)"
    VERSION="$(get_latest_version)"

    if [ -z "$VERSION" ]; then
        echo "error: could not determine latest version" >&2
        echo "try: cargo install wardn" >&2
        exit 1
    fi

    ARTIFACT="wardn-${PLATFORM}"
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    URL="${BASE_URL}/${ARTIFACT}.tar.gz"
    CHECKSUM_URL="${BASE_URL}/${ARTIFACT}.tar.gz.sha256"

    echo "  version:  ${VERSION}"
    echo "  platform: ${PLATFORM}"
    echo "  target:   ${INSTALL_DIR}/wardn"
    echo ""

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    echo "downloading ${URL}..."
    download "$URL" "${TMPDIR}/${ARTIFACT}.tar.gz"
    download "$CHECKSUM_URL" "${TMPDIR}/${ARTIFACT}.tar.gz.sha256"

    if [ -s "${TMPDIR}/${ARTIFACT}.tar.gz.sha256" ]; then
        echo "verifying checksum..."
        if ! verify_checksum "${TMPDIR}/${ARTIFACT}.tar.gz" "${TMPDIR}/${ARTIFACT}.tar.gz.sha256"; then
            echo "error: checksum verification failed — the download may be corrupted or tampered with" >&2
            echo "aborting install." >&2
            exit 1
        fi
    else
        echo "warning: could not fetch checksum file — proceeding without verification" >&2
    fi

    tar xzf "${TMPDIR}/${ARTIFACT}.tar.gz" -C "$TMPDIR"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/wardn" "${INSTALL_DIR}/wardn"
    else
        echo "installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "${TMPDIR}/wardn" "${INSTALL_DIR}/wardn"
    fi

    chmod +x "${INSTALL_DIR}/wardn"

    echo ""
    if ! "${INSTALL_DIR}/wardn" --version >/dev/null 2>&1; then
        echo "warning: installed binary did not run cleanly — check ${INSTALL_DIR}/wardn manually" >&2
    fi

    echo "wardn ${VERSION} installed to ${INSTALL_DIR}/wardn"
    echo ""
    echo "get started:"
    echo "  wardn vault create"
    echo "  wardn vault set ANTHROPIC_KEY --domain api.anthropic.com"
    echo "  wardn setup claude-code --alias   # or: wardn run --agent claude-code -- claude"
    echo ""
    echo "  wardn setup claude-code registers the MCP server; --alias also makes"
    echo "  plain \`claude\` transparently route through the wardn proxy, so the"
    echo "  real API key never enters Claude Code's process or context window."
}

main
