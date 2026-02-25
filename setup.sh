#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# SecureP2P — Quick Setup Script
# Installs dependencies, builds the project, and runs tests.
# ═══════════════════════════════════════════════════════════
set -euo pipefail

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
RESET='\033[0m'

LIBOQS_VERSION="0.12.0"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

# ─── Check for a command ───────────────────
require() {
    command -v "$1" &>/dev/null || return 1
}

# ─── Detect package manager ───────────────
detect_pkg_manager() {
    if require apt-get; then echo "apt"
    elif require dnf;     then echo "dnf"
    elif require pacman;  then echo "pacman"
    elif require brew;    then echo "brew"
    else echo "unknown"; fi
}

# ═══════════════════════════════════════════
# Step 1: System dependencies
# ═══════════════════════════════════════════
install_system_deps() {
    info "Checking system dependencies..."

    local missing=()
    require g++       || require clang++ || missing+=("c++ compiler")
    require cmake     || missing+=("cmake")
    require pkg-config|| missing+=("pkg-config")
    require ninja     || require make    || missing+=("build tool (make or ninja)")

    # Check for OpenSSL dev headers
    if ! pkg-config --exists openssl 2>/dev/null; then
        missing+=("openssl dev")
    fi

    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "All system dependencies found."
        return 0
    fi

    warn "Missing: ${missing[*]}"
    info "Attempting to install system packages..."

    local pm
    pm=$(detect_pkg_manager)

    case "$pm" in
        apt)
            sudo apt-get update -qq
            sudo apt-get install -y build-essential cmake pkg-config libssl-dev ninja-build
            ;;
        dnf)
            sudo dnf install -y gcc-c++ cmake pkgconf-pkg-config openssl-devel ninja-build
            ;;
        pacman)
            sudo pacman -Sy --noconfirm base-devel cmake pkgconf openssl ninja
            ;;
        brew)
            brew install cmake pkg-config openssl ninja
            ;;
        *)
            fail "Unknown package manager. Please install manually: ${missing[*]}"
            ;;
    esac

    ok "System dependencies installed."
}

# ═══════════════════════════════════════════
# Step 2: liboqs
# ═══════════════════════════════════════════
install_liboqs() {
    if pkg-config --exists liboqs 2>/dev/null; then
        local ver
        ver=$(pkg-config --modversion liboqs 2>/dev/null || echo "unknown")
        ok "liboqs already installed (version: $ver). Skipping."
        return 0
    fi

    info "Installing liboqs ${LIBOQS_VERSION}..."

    local build_tool="make"
    local generator="Unix Makefiles"
    if require ninja; then
        build_tool="ninja"
        generator="Ninja"
    fi

    local oqs_dir="${PROJECT_DIR}/_deps/liboqs"
    mkdir -p "${PROJECT_DIR}/_deps"

    if [[ -d "$oqs_dir" ]]; then
        warn "Found existing liboqs source at $oqs_dir, reusing."
    else
        git clone --depth 1 --branch "${LIBOQS_VERSION}" \
            https://github.com/open-quantum-safe/liboqs.git "$oqs_dir"
    fi

    mkdir -p "$oqs_dir/build" && cd "$oqs_dir/build"

    cmake -G"$generator" \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        ..

    "$build_tool" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
    sudo "$build_tool" install

    # Update linker cache on Linux
    if [[ "$(uname)" == "Linux" ]]; then
        sudo ldconfig
    fi

    cd "$PROJECT_DIR"
    ok "liboqs ${LIBOQS_VERSION} installed."
}

# ═══════════════════════════════════════════
# Step 3: Build SecureP2P
# ═══════════════════════════════════════════
build_project() {
    info "Building SecureP2P..."

    mkdir -p "$PROJECT_DIR/build" && cd "$PROJECT_DIR/build"

    cmake ..
    make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"

    if [[ ! -x "./secureP2P" ]]; then
        fail "Build failed — secureP2P binary not found."
    fi

    ok "Build successful."
    echo ""
    echo "  Binary:  $PROJECT_DIR/build/secureP2P"
    echo "  Tests:   $PROJECT_DIR/build/secureP2P_tests"
}

# ═══════════════════════════════════════════
# Step 4: Run tests
# ═══════════════════════════════════════════
run_tests() {
    info "Running test suite..."

    cd "$PROJECT_DIR/build"

    if [[ ! -x "./secureP2P_tests" ]]; then
        warn "Test binary not found, skipping."
        return 0
    fi

    if ./secureP2P_tests; then
        ok "All tests passed."
    else
        warn "Some tests failed. Check output above."
    fi
}

# ═══════════════════════════════════════════
# Main
# ═══════════════════════════════════════════
main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║    SecureP2P — Quick Setup Script         ║${RESET}"
    echo -e "${CYAN}╚═══════════════════════════════════════════╝${RESET}"
    echo ""

    install_system_deps
    echo ""
    install_liboqs
    echo ""
    build_project
    echo ""
    run_tests

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════${RESET}"
    echo -e "${GREEN}  Setup complete! Quick start:${RESET}"
    echo ""
    echo "  # Terminal 1 — listen for a peer:"
    echo "  cd $PROJECT_DIR/build"
    echo "  ./secureP2P listen"
    echo ""
    echo "  # Terminal 2 — connect to the listener:"
    echo "  cd $PROJECT_DIR/build"
    echo "  ./secureP2P connect 127.0.0.1"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════${RESET}"
}

main "$@"
