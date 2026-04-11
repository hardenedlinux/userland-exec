#!/usr/bin/env bash
# =============================================================================
# rce_demo/setup.sh — victim-side setup for the network RCE rce_demo
#
# Run this on the VICTIM machine before starting victim_server.
#
# What this script does:
#   1. Creates a tmpfs at /tmp/noexec_rce_demo with the 'noexec' flag
#   2. Makes the directory writable so recv_and_exec() can write the payload
#   3. Verifies that direct execution is blocked (proving noexec works)
#
# Usage:
#   sudo ./rce_demo/setup.sh            # set up noexec mount
#   sudo ./rce_demo/setup.sh cleanup    # tear down
#
# After setup:
#   Terminal 1 (victim):    ./build/rce_demo/victim_server
#   Terminal 2 (attacker):  python3 rce_demo/exploit.py --target <victim-ip>
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"
NOEXEC_DIR="/tmp/noexec_rce_demo"

info()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
error() { printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
die()   { error "$*"; exit 1; }

# ── cleanup mode ──────────────────────────────────────────────────────────────
if [[ "${1:-}" == "cleanup" ]]; then
    info "Cleaning up ..."
    if mountpoint -q "$NOEXEC_DIR" 2>/dev/null; then
        umount "$NOEXEC_DIR"
        info "Unmounted $NOEXEC_DIR."
    else
        warn "$NOEXEC_DIR is not a mount point."
    fi
    rmdir "$NOEXEC_DIR" 2>/dev/null && info "Removed $NOEXEC_DIR." || true
    exit 0
fi

# ── privilege check ───────────────────────────────────────────────────────────
[[ "$EUID" -eq 0 ]] || die "Requires root for mount(8).  Run: sudo $0"

# ── build check ───────────────────────────────────────────────────────────────
[[ -f "$BUILD_DIR/rce_demo/victim_server" ]] \
    || die "victim_server not found.  Build first:\n    mkdir -p build && cd build && cmake .. && make"

# ── create noexec tmpfs ───────────────────────────────────────────────────────
mkdir -p "$NOEXEC_DIR"
if mountpoint -q "$NOEXEC_DIR" 2>/dev/null; then
    warn "Already mounted — remounting."
    umount "$NOEXEC_DIR"
fi

mount -t tmpfs -o size=32M,noexec,nosuid,nodev tmpfs "$NOEXEC_DIR"
chmod 1777 "$NOEXEC_DIR"
info "Mounted tmpfs (noexec,nosuid,nodev) at $NOEXEC_DIR"

# ── verify noexec enforcement ─────────────────────────────────────────────────
echo ""
info "Verifying noexec ..."
cp /bin/true "$NOEXEC_DIR/test_exec" 2>/dev/null || cp /usr/bin/true "$NOEXEC_DIR/test_exec"
chmod +x "$NOEXEC_DIR/test_exec"

if "$NOEXEC_DIR/test_exec" 2>/dev/null; then
    warn "Direct execution SUCCEEDED — noexec NOT enforced!"
else
    info "Direct execution BLOCKED — noexec is working."
fi
rm -f "$NOEXEC_DIR/test_exec"

# ── instructions ──────────────────────────────────────────────────────────────
VICTIM_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "<this-ip>")
echo ""
echo "============================================================"
echo "  VICTIM setup complete."
echo ""
echo "  1. Start the server on THIS machine:"
echo "     ./build/rce_demo/victim_server"
echo ""
echo "  2. On the ATTACKER machine, run:"
echo "     python3 rce_demo/exploit.py --target $VICTIM_IP"
echo ""
echo "  Cleanup:"
echo "     sudo ./rce_demo/setup.sh cleanup"
echo "============================================================"
