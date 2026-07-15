#!/usr/bin/env sh
# AKA bootstrap installer — POSIX shell entrypoint.
#
# Ensures Node is present, then hands off to the Node installer (install.mjs),
# which does the real work (npm registry auth + global install). Usage:
#
#   sh tools/installer/install.sh                      # install the CLI (from a checkout)
#   curl -fsSL <raw>/install.sh | sh                   # install the CLI (one-liner)
#   curl -fsSL <raw>/install.sh | sh -s -- --plugin X  # install a plugin
#
# The shell layer ONLY bootstraps Node; all logic lives in install.mjs so both
# the shell and PowerShell entrypoints share one codepath.
set -eu

# Ref the one-liner fetches install.mjs from. Defaults to the stable `cli-latest`
# tag, which the release workflow points at the most recent published CLI release —
# NEVER the mutable `main` branch, so a mid-merge `main` cannot change what
# `curl | sh` runs. The tag only moves when a release is cut, and the checksum gate
# below still requires the fetched install.mjs to match the install.sh that fetched
# it. Pin an exact release with AKA_INSTALL_REF=cli-v<version>.
AKA_INSTALL_REF="${AKA_INSTALL_REF:-cli-latest}"
RAW_BASE="${AKA_INSTALL_RAW_BASE:-https://raw.githubusercontent.com/akasecurity/ai-tc/${AKA_INSTALL_REF}/tools/installer}"

# SHA-256 of the trusted install.mjs (committed alongside this script). The
# downloaded installer is verified against this before it runs, so a tampered
# install.mjs is rejected even if the pinned ref is somehow moved. Regenerate after
# editing install.mjs with:  shasum -a 256 tools/installer/install.mjs
# (node tools/installer/checksum-selfcheck.mjs verifies this pin in CI.)
EXPECTED_MJS_SHA256="83ae1559a0668ada357a5d327d5e1fab1443b0c03c3abfd6594ca7fc83fb2198"

if ! command -v node >/dev/null 2>&1; then
  echo "aka: Node.js 24+ is required but was not found." >&2
  echo "aka: install it from https://nodejs.org (or your version manager) and re-run." >&2
  exit 1
fi

# Prefer a sibling install.mjs (running from a checkout); otherwise download it
# (piped one-liner). $0 is unreliable under `curl | sh`, so guard existence.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")
LOCAL_MJS="${SCRIPT_DIR}/install.mjs"

if [ -n "$SCRIPT_DIR" ] && [ -f "$LOCAL_MJS" ]; then
  exec node "$LOCAL_MJS" "$@"
fi

# Download path. Use a private, randomly-named temp dir from mktemp ONLY — never a
# predictable /tmp/aka-install.mjs fallback, which is a symlink/TOCTOU race on a
# multi-user host. Fail closed if mktemp is unavailable.
TMP_DIR=$(mktemp -d 2>/dev/null) || {
  echo "aka: mktemp is required to download the installer securely; aborting." >&2
  exit 1
}
trap 'rm -rf "$TMP_DIR"' EXIT
TMP_MJS="${TMP_DIR}/install.mjs"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "${RAW_BASE}/install.mjs" -o "$TMP_MJS"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_MJS" "${RAW_BASE}/install.mjs"
else
  echo "aka: need curl or wget to download the installer." >&2
  exit 1
fi

# Verify the download against the pinned checksum before executing it.
if command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA256=$(shasum -a 256 "$TMP_MJS" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA256=$(sha256sum "$TMP_MJS" | awk '{print $1}')
else
  echo "aka: need shasum or sha256sum to verify the installer; aborting." >&2
  exit 1
fi
if [ "$ACTUAL_SHA256" != "$EXPECTED_MJS_SHA256" ]; then
  echo "aka: installer checksum mismatch — refusing to run the downloaded installer." >&2
  echo "aka: expected $EXPECTED_MJS_SHA256" >&2
  echo "aka: got      $ACTUAL_SHA256" >&2
  exit 1
fi

# Not exec, so the EXIT trap still cleans up the temp dir afterwards.
node "$TMP_MJS" "$@"
