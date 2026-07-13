# AKA bootstrap installer

A thin, cross-platform bootstrap for the `aka` CLI (and, later, agent plugins).
The shell entrypoints only ensure Node is present; the real work lives in one Node
script (`install.mjs`) so every path shares a single codepath.

## Usage

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.ps1 | iex

# From a checkout
sh tools/installer/install.sh
node tools/installer/install.mjs                       # install the CLI
node tools/installer/install.mjs --plugin claude-code  # prints the marketplace path
```

## Trust chain

- The one-liner fetches `install.sh`/`install.ps1` from the **`cli-latest` tag**,
  never `main`. The release workflow points `cli-latest` at each published CLI
  release, so the tag only moves when a release is cut — a mid-merge `main` can
  never change what `curl | sh` runs. (Until the first public CLI release cuts
  `cli-v*` and `cli-latest`, the URL 404s: fail-closed, not insecure.)
- The script then fetches `install.mjs` from the **same ref** and verifies it
  against a SHA-256 baked into the script before running it, so the pair always
  comes from one release commit. `node tools/installer/checksum-selfcheck.mjs`
  fails CI if the baked pin drifts from the committed `install.mjs`.
- To pin an exact release instead of following `cli-latest`, set
  `AKA_INSTALL_REF=cli-v<version>` (both in the one-liner URL and the env var);
  point at a local copy with `AKA_INSTALL_RAW_BASE=<url>`.

## What it does

1. **Ensures Node 24+** (the shell layer checks `node` exists; `install.mjs` checks the version).
2. **Cleans up `~/.npmrc` if needed** — the packages install from the **public npm
   registry** with no auth and no registry override; if an earlier installer release
   left an `@akasecurity` → `npm.pkg.github.com` scope mapping in `~/.npmrc`, it is
   removed (it would 401 installs from public npm). Nothing else in the file is touched.
3. **Installs** the global CLI (`npm i -g @akasecurity/cli`) or, with `--plugin <id>`, an agent plugin.

## Bidirectional

This is invoked **both** directions, sharing one codepath:

- **Plugin → CLI**: the Claude Code plugin's `/aka:setup` opt-in runs it to add the CLI + dashboard.
- **CLI → plugin**: `aka plugins install <agent>` runs it (or its own channel) to add a plugin.

## Notes

- **Registry:** packages are public on npm under the `@akasecurity` scope — no
  token or registry configuration is required.
- Claude Code installs from the **plugin marketplace**, not npm — `--plugin
claude-code` prints that path.
