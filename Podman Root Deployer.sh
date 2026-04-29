#!/bin/bash
# T.I.E. Hardened Podman Root Deployer
# Architecture: Termux/NetHunter (EUID 0)

set -euo pipefail

# --- ANSI COLOR SCHEME ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- SIGNAL TRAP ---
trap 'echo -e "\n${RED}[!] INTERRUPT DETECTED. Cleaning up...${NC}"; exit 1' SIGINT SIGTERM

# --- LOGGING FUNCTION ---
log() { echo -e "${CYAN}[$(date +%T)]${NC} $1"; }
warn() { echo -e "${YELLOW}[!] WARNING:${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- PRE-FLIGHT CHECKS ---
log "Initiating Pre-flight checks..."

# Check for Root (EUID 0)
if [[ $EUID -ne 0 ]]; then
    error "This script REQUIRES Magisk/Root access. Run with 'sudo' or as root user."
fi

# Check Dependencies
DEPS=("podman" "sed" "grep" "mkdir")
for tool in "${DEPS[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || error "Dependency missing: $tool"
done

# --- RUNTIME DYNAMIC CONFIGURATION ---
echo -e "${GREEN}--- CONFIGURATION PARAMETERS ---${NC}"
read -p "Enter Storage Root Path [/data/adb/podman]: " STORAGE_ROOT
STORAGE_ROOT=${STORAGE_ROOT:-/data/adb/podman}

read -p "Enter Run Root Path [/run/podman]: " RUN_ROOT
RUN_ROOT=${RUN_ROOT:-/run/podman}

read -p "Storage Driver [overlay]: " DRIVER
DRIVER=${DRIVER:-overlay}

read -p "Log Level (debug, info, warn, error) [info]: " LOG_LEVEL
LOG_LEVEL=${LOG_LEVEL:-info}

# --- EXECUTION ---

log "Creating tactical directory structure..."
mkdir -p "$STORAGE_ROOT" "$RUN_ROOT"

log "Configuring storage.conf for tactical overlay..."
# Define storage.conf path (Termux/NetHunter specific)
CONF_DIR="/etc/containers"
[[ -d "/data/data/com.termux/files/usr/etc/containers" ]] && CONF_DIR="/data/data/com.termux/files/usr/etc/containers"
mkdir -p "$CONF_DIR"

cat <<EOF > "$CONF_DIR/storage.conf"
[storage]
driver = "$DRIVER"
runroot = "$RUN_ROOT"
graphroot = "$STORAGE_ROOT"

[storage.options]
additionalimagestores = []

[storage.options.overlay]
mount_program = "$(command -v fuse-overlayfs || echo "/usr/bin/fuse-overlayfs")"
mountopt = "nodev,metacopy=on"
EOF

log "Verifying Engine Connectivity..."
if podman --log-level "$LOG_LEVEL" info > /dev/null 2>&1; then
    log "${GREEN}Podman Engine is RESPONSIVE.${NC}"
else
    warn "Engine check failed. Attempting verbose diagnostic..."
    podman --log-level debug info || error "Podman failed to initialize. Check dmesg for kernel overlay support."
fi

log "Deployment Complete."
echo -e "${YELLOW}Final Status:${NC}"
podman info | grep -E 'store|graphRoot|runRoot'