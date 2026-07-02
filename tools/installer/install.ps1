# AKA bootstrap installer — Windows PowerShell entrypoint.
#
# Ensures Node is present, then hands off to the Node installer (install.mjs),
# which does the real work. Usage:
#
#   pwsh tools/installer/install.ps1                       # install the CLI (from a checkout)
#   irm <raw>/install.ps1 | iex                            # install the CLI (one-liner)
#   & ([scriptblock]::Create((irm <raw>/install.ps1))) --plugin X
#
# The shell layer ONLY bootstraps Node; all logic lives in install.mjs so the
# POSIX and PowerShell entrypoints share one codepath.
$ErrorActionPreference = 'Stop'

# Ref the one-liner fetches install.mjs from. Defaults to the stable `cli-latest`
# tag, which the release workflow points at the most recent published CLI release —
# NEVER the mutable `main` branch, so a mid-merge `main` cannot change what
# `irm | iex` runs. Pin an exact release with AKA_INSTALL_REF=cli-v<version>.
$AkaInstallRef = if ($env:AKA_INSTALL_REF) { $env:AKA_INSTALL_REF } else { 'cli-latest' }
$RawBase = if ($env:AKA_INSTALL_RAW_BASE) { $env:AKA_INSTALL_RAW_BASE } else {
  "https://raw.githubusercontent.com/akasecurity/ai-tc/$AkaInstallRef/tools/installer"
}

# SHA-256 of the trusted install.mjs; the download is verified against this before
# it runs. Regenerate after editing install.mjs:  shasum -a 256 tools/installer/install.mjs
# (node tools/installer/checksum-selfcheck.mjs verifies this pin in CI.)
# (Get-FileHash returns upper-case hex, but PowerShell string -ne is case-insensitive.)
$ExpectedMjsSha256 = 'd2b81f1ee46c6988cbf8b0586d542533a78ae9d24b445ad1ef1d2ab79ffb9314'

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Error 'aka: Node.js 26+ is required but was not found. Install it from https://nodejs.org and re-run.'
  exit 1
}

# Prefer a sibling install.mjs (running from a checkout); otherwise download it.
$LocalMjs = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'install.mjs' } else { $null }

if ($LocalMjs -and (Test-Path $LocalMjs)) {
  & node $LocalMjs @args
  exit $LASTEXITCODE
}

# Download path: a private, randomly-named temp dir (no predictable fixed name that
# invites a symlink/TOCTOU race), verified against the pinned checksum before exec.
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null
try {
  $TmpMjs = Join-Path $TmpDir 'install.mjs'
  Invoke-RestMethod -Uri "$RawBase/install.mjs" -OutFile $TmpMjs
  $actual = (Get-FileHash -Algorithm SHA256 -Path $TmpMjs).Hash
  if ($actual -ne $ExpectedMjsSha256) {
    Write-Error "aka: installer checksum mismatch — refusing to run the downloaded installer. Expected $ExpectedMjsSha256, got $actual."
    exit 1
  }
  & node $TmpMjs @args
  exit $LASTEXITCODE
} finally {
  Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
