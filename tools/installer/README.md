# AKA installer

Installs the self-contained `aka` binary. **No Node.js required** — the binary embeds
its own runtime.

## Usage

```bash
# macOS (Apple Silicon) / Linux (x64, arm64)
curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.sh | sh
```

```powershell
# Windows (x64, PowerShell)
irm https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.ps1 | iex
```

```sh
# From a checkout
sh tools/installer/install.sh
```

## What it does

1. Detects your OS + architecture and picks the matching release asset
   (`darwin-arm64`, `linux-x64`, `linux-arm64`, `win32-x64`).
2. Downloads the archive **and `SHA256SUMS`** from the latest `bin-v*` GitHub Release,
   and verifies the archive against the checksum — **fail closed** on any mismatch.
3. Extracts to `~/.local/share/aka/<version>` (macOS/Linux) or `%LOCALAPPDATA%\aka`
   (Windows) and links `aka` onto your `PATH` (`~/.local/bin` / a user-PATH entry).
4. Runs `aka --version` to confirm. Then run `aka init`.

## Supported targets

`darwin-arm64` (Apple Silicon), `linux-x64`, `linux-arm64`, `win32-x64`. Intel macOS
(`darwin-x64`) is not built. Plugins install through the CLI once it is on your PATH
(`aka plugins install <agent>`) or, for Claude Code, the plugin marketplace.

## Trust chain

- The one-liner fetches `install.sh` / `install.ps1` from the **`bin-latest` tag** over
  HTTPS, never `main`. The release workflow points `bin-latest` at each published
  binary release, so the tag only moves when a release is cut.
- The script downloads the archive and `SHA256SUMS` from that release and verifies the
  archive before extracting it. Both come from the same release over TLS.
- Pin an exact release with `AKA_INSTALL_REF=bin-v<version>`.

## Overrides

| Variable                            | Default              | Purpose                                                              |
| ----------------------------------- | -------------------- | -------------------------------------------------------------------- |
| `AKA_INSTALL_REF`                   | latest `bin-v*`      | Pin a specific release (`bin-v0.8.1`).                               |
| `AKA_INSTALL_DIR`                   | `~/.local/share/aka` | Where versions are extracted.                                        |
| `AKA_BIN_DIR`                       | `~/.local/bin`       | Where the `aka` symlink is placed (POSIX).                           |
| `AKA_DOWNLOAD_BASE` + `AKA_VERSION` | —                    | Fetch the archive + `SHA256SUMS` from a local/mirror base (testing). |
