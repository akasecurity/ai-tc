# AKA installer — downloads the self-contained `aka` binary. No Node.js required.
#
#   irm <raw>/install.ps1 | iex                                  # install the latest `aka`
#   $env:AKA_INSTALL_REF='bin-v0.8.1'; irm ... | iex             # pin an exact release
#
# The `aka` binary embeds its own runtime. Overrides: AKA_INSTALL_DIR
# (default %LOCALAPPDATA%\aka), AKA_INSTALL_REF (bin-v<version>, default = latest
# bin-v* release), AKA_DOWNLOAD_BASE + AKA_VERSION (fetch from a local/mirror base).
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 renders an Invoke-WebRequest progress bar that throttles large
# downloads (the ~46 MB archive crawls); silencing it restores full speed.
$ProgressPreference = 'SilentlyContinue'

$Repo = if ($env:AKA_INSTALL_REPO) { $env:AKA_INSTALL_REPO } else { 'akasecurity/ai-tc' }
$InstallDir = if ($env:AKA_INSTALL_DIR) { $env:AKA_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'aka' }

# 1. Detect arch → target triple. Only win32-x64 is built.
$archEnv = "$env:PROCESSOR_ARCHITECTURE"
switch ($archEnv) {
  'AMD64' { $triple = 'win32-x64' }
  default {
    Write-Error "aka: unsupported Windows architecture '$archEnv' (only x64 is built)."
    exit 1
  }
}

# 2. Resolve the version and the base URL for the assets.
if ($env:AKA_DOWNLOAD_BASE) {
  $base = $env:AKA_DOWNLOAD_BASE
  if (-not $env:AKA_VERSION) { Write-Error 'aka: set AKA_VERSION when using AKA_DOWNLOAD_BASE.'; exit 1 }
  $version = $env:AKA_VERSION
}
else {
  $ref = $env:AKA_INSTALL_REF
  if (-not $ref) {
    # /releases/latest excludes pre-releases (0.x), so list and pick the newest bin-v*.
    $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases?per_page=30"
    $ref = ($releases | Where-Object { $_.tag_name -like 'bin-v*' } | Select-Object -First 1).tag_name
    if (-not $ref) { Write-Error "aka: could not find a bin-v* release for $Repo."; exit 1 }
  }
  $version = $ref -replace '^bin-v', ''
  $base = "https://github.com/$Repo/releases/download/$ref"
}

$archive = "aka-$version-$triple.zip"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
  # 3. Download the archive + checksums.
  Write-Host "aka: downloading $archive…"
  Invoke-WebRequest -Uri "$base/$archive" -OutFile (Join-Path $tmp $archive)
  Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

  # 4. Verify against SHA256SUMS. Fail closed.
  $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $archive)).Hash.ToLower()
  $line = Select-String -Path (Join-Path $tmp 'SHA256SUMS') -Pattern ([regex]::Escape($archive)) | Select-Object -First 1
  if (-not $line) { Write-Error "aka: $archive not listed in SHA256SUMS."; exit 1 }
  $want = ($line.Line -split '\s+')[0].ToLower()
  if ($got -ne $want) {
    Write-Error "aka: checksum mismatch for $archive — refusing to install. expected $want, got $got."
    exit 1
  }

  # 5. Extract and put `aka` on PATH.
  $dest = Join-Path $InstallDir $version
  if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
  New-Item -ItemType Directory -Path $dest -Force | Out-Null
  Expand-Archive -Force -Path (Join-Path $tmp $archive) -DestinationPath $dest
  $binroot = Join-Path $dest "aka-$triple"
  $exe = Join-Path $binroot 'aka.exe'
  if (-not (Test-Path $exe)) { Write-Error 'aka: binary missing after extract.'; exit 1 }

  # Point a stable `current` junction at this version's binroot so the user PATH holds
  # ONE entry that survives upgrades (mirrors install.sh's ~/.local/bin/aka symlink).
  # process.execPath follows the junction, so the binary still resolves its sidecars.
  $current = Join-Path $InstallDir 'current'
  # Remove only the old junction link, never recurse into its target — on Windows
  # PowerShell 5.1 `Remove-Item -Recurse` on a junction can delete the target's contents.
  if (Test-Path $current) { [System.IO.Directory]::Delete($current) }
  New-Item -ItemType Junction -Path $current -Target $binroot | Out-Null

  # Rebuild the user PATH with exactly one aka entry: drop any prior entry under
  # $InstallDir (version-specific binroots leaked by earlier installs) and prepend the
  # stable junction. Without this, every upgrade left a dead binroot on PATH forever.
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  $kept = @($userPath -split ';' | Where-Object {
      $_ -and -not $_.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase)
    })
  $newPath = (@($current) + $kept) -join ';'
  if ($newPath -ne $userPath) {
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "aka: $current is on your PATH (open a new terminal to pick it up)."
  }
  $ver = (& (Join-Path $current 'aka.exe') --version)
  Write-Host "aka: $ver ready — run 'aka init' to set up your local store."
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
