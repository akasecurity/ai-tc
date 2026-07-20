#!/usr/bin/env sh
# AKA installer — downloads the self-contained `aka` binary. No Node.js required.
#
#   curl -fsSL <raw>/install.sh | sh                 # install the latest `aka`
#   AKA_INSTALL_REF=bin-v0.8.1 curl ... | sh          # pin an exact release
#
# The `aka` binary embeds its own runtime, so nothing else needs to be installed.
# Overrides: AKA_INSTALL_DIR (default ~/.local/share/aka), AKA_BIN_DIR (~/.local/bin),
# AKA_INSTALL_REF (bin-v<version>, default = latest bin-v* release),
# AKA_DOWNLOAD_BASE + AKA_VERSION (fetch archives from a local/mirror base — testing).
set -eu

REPO="${AKA_INSTALL_REPO:-akasecurity/ai-tc}"
INSTALL_DIR="${AKA_INSTALL_DIR:-${HOME}/.local/share/aka}"
BIN_DIR="${AKA_BIN_DIR:-${HOME}/.local/bin}"

# 1. Detect platform → target triple (must match the release asset names).
os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Darwin) plat=darwin ;;
  Linux) plat=linux ;;
  *) echo "aka: unsupported OS '$os'. On Windows use install.ps1." >&2; exit 1 ;;
esac
case "$arch" in
  arm64 | aarch64) cpu=arm64 ;;
  x86_64 | amd64) cpu=x64 ;;
  *) echo "aka: unsupported architecture '$arch'." >&2; exit 1 ;;
esac
triple="${plat}-${cpu}"
if [ "$triple" = "darwin-x64" ]; then
  echo "aka: Intel macOS is not supported (Apple Silicon only)." >&2
  exit 1
fi

# Download helpers (curl or wget).
dl() { # dl <url> <out-file>
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else echo "aka: need curl or wget to download." >&2; exit 1; fi
}
dl_stdout() { # dl_stdout <url>
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO - "$1"
  else echo "aka: need curl or wget to download." >&2; exit 1; fi
}

# 2. Resolve the version and the base URL for the assets.
if [ -n "${AKA_DOWNLOAD_BASE:-}" ]; then
  base="$AKA_DOWNLOAD_BASE"
  version="${AKA_VERSION:?set AKA_VERSION when using AKA_DOWNLOAD_BASE}"
else
  ref="${AKA_INSTALL_REF:-}"
  if [ -z "$ref" ]; then
    # /releases/latest excludes pre-releases (0.x is pre-release), so list and pick
    # the newest bin-v* tag.
    ref=$(dl_stdout "https://api.github.com/repos/${REPO}/releases?per_page=30" \
      | grep '"tag_name"' | grep -o 'bin-v[0-9][^"]*' | head -1) || true
    [ -n "$ref" ] || { echo "aka: could not find a bin-v* release for ${REPO}." >&2; exit 1; }
  fi
  version="${ref#bin-v}"
  base="https://github.com/${REPO}/releases/download/${ref}"
fi

archive="aka-${version}-${triple}.tar.gz"
tmp=$(mktemp -d) || { echo "aka: mktemp failed." >&2; exit 1; }
trap 'rm -rf "$tmp"' EXIT

# 3. Download the archive + checksums.
echo "aka: downloading ${archive}…"
dl "${base}/${archive}" "${tmp}/${archive}"
dl "${base}/SHA256SUMS" "${tmp}/SHA256SUMS"

# 4. Verify the archive against SHA256SUMS. Fail closed.
if command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "${tmp}/${archive}" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "${tmp}/${archive}" | awk '{print $1}')
else
  echo "aka: need shasum or sha256sum to verify the download." >&2; exit 1
fi
want=$(awk -v f="$archive" '$2 == f {print $1}' "${tmp}/SHA256SUMS")
[ -n "$want" ] || { echo "aka: ${archive} not listed in SHA256SUMS." >&2; exit 1; }
if [ "$got" != "$want" ]; then
  echo "aka: checksum mismatch for ${archive} — refusing to install." >&2
  echo "aka: expected ${want}" >&2
  echo "aka: got      ${got}" >&2
  exit 1
fi

# 5. Extract and link `aka` onto PATH.
dest="${INSTALL_DIR}/${version}"
rm -rf "$dest"
mkdir -p "$dest"
tar -xzf "${tmp}/${archive}" -C "$dest"
binroot="${dest}/aka-${triple}"
[ -x "${binroot}/aka" ] || { echo "aka: binary missing after extract." >&2; exit 1; }
mkdir -p "$BIN_DIR"
ln -sf "${binroot}/aka" "${BIN_DIR}/aka"
echo "aka: installed ${binroot}/aka"
echo "aka: linked ${BIN_DIR}/aka"

# 6. Confirm, and nudge PATH if the bin dir isn't on it.
"${binroot}/aka" --version >/dev/null 2>&1 && ver=$("${binroot}/aka" --version) || ver="?"
case ":${PATH}:" in
  *":${BIN_DIR}:"*)
    echo "aka: ${ver} ready — run 'aka init' to set up your local store." ;;
  *)
    echo "aka: ${ver} installed. Add ${BIN_DIR} to your PATH, then run 'aka init':"
    echo "     export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac
