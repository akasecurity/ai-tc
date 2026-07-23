# @akasecurity/cli — `aka`

[![npm](https://img.shields.io/npm/v/@akasecurity/cli?style=flat-square&labelColor=232F3E&color=00E0B8)](https://www.npmjs.com/package/@akasecurity/cli)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-232F3E?style=flat-square)](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)

**AKA Security — We secure agent harnesses at the source.**

The `aka` command-line tool for **[AI Traffic Control](https://github.com/akasecurity/ai-tc)** (`ai-tc`) — an open-source, local-first control plane for coding agents. It inspects and governs the traffic of an agent session (prompts, tool calls, responses, file reads), scans each event against your rule packs, and records everything to a local SQLite store at `~/.aka/data/aka.db`.

Everything runs on your machine. There's no account, no backend, and nothing leaves your computer to be scanned.

## Install

```bash
npm install -g @akasecurity/cli
```

Or use the bootstrap installer (downloads the self-contained binary — no Node.js required):

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.ps1 | iex
```

Requires **Node.js 24+** (the CLI uses the built-in `node:sqlite`).

## Quick start

```bash
aka init         # scaffold the local store at ~/.aka
aka dashboard    # open the local web dashboard over your store
```

## What it does

| Command          | What it does                                                     |
| ---------------- | ---------------------------------------------------------------- |
| `aka init`       | Create the local store and settings under `~/.aka`.              |
| `aka dashboard`  | Launch the local web dashboard (findings, policies, exceptions). |
| `aka scan`       | Scan working-tree source files for security flaws.               |
| `aka detections` | List installed detection packs and available updates.            |
| `aka exception`  | Manage exact-value exceptions that let a specific match through. |
| `aka stats`      | Show detection activity and token/cost summaries from the store. |
| `aka plugins`    | Optional hub to install agent plugins (e.g. Claude Code).        |

Run `aka --help` for the full command list.

## The Claude Code plugin

The CLI gives you the dashboard, store, and scanning. To actually **intercept** a Claude Code session you also need the AKA plugin, which installs from the Claude Code plugin marketplace (not npm). With the CLI installed:

```bash
aka plugins install claude-code
```

This drives Claude Code to add the plugin for you (or prints the `/plugin` commands to run). See the [installation guide](https://akasecurity.github.io/ai-tc-docs/getting-started/installation/) for both components.

## Docs

Full documentation, architecture, and the built-in detection catalog live at **[akasecurity.github.io/ai-tc-docs](https://akasecurity.github.io/ai-tc-docs/)**.

## License

[Apache-2.0](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)
