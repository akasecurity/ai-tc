# @akasecurity/cli — `aka`

[![npm](https://img.shields.io/npm/v/@akasecurity/cli?style=flat-square&labelColor=232F3E&color=00E0B8)](https://www.npmjs.com/package/@akasecurity/cli)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-232F3E?style=flat-square)](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)

**AKA Security — We secure agent harnesses at the source.**

The `aka` command-line tool for **[AI Traffic Control](https://github.com/akasecurity/ai-tc)** (`ai-tc`) — an open-source, local-first control plane for coding agents. It inspects and governs the traffic of an agent session (prompts, tool calls, responses, file reads), scans each event against your rule packs, and records everything to a local SQLite store at `~/.aka/data/aka.db`.

Detection, enforcement, and your store run on your machine. There's no account and no backend, and nothing leaves your computer to be scanned. Two narrow paths do reach the network and neither carries your data: the version check that runs after a command, and the `npm`/`claude` installs that `aka plugins` drives.[^egress]

[^egress]: Scanning, enforcement and your store are local — there's no AKA server, no account, and no built-in network client (the source uses no `fetch`). Two narrow paths do reach the network, both through child processes and neither carrying the content of your prompts, tool calls or findings. The **update notice** runs `npm view` on this package after a command when stdout is a terminal, so the registry — and whatever proxy your npm configuration points at — learns the package name and that it is installed here; it is on by default, and `--no-update-check` skips it for a single invocation. And the commands that install or update software — `aka plugins install`, `aka update` and `aka check-updates` — shell out to `npm` and `claude`, which reaches the network the way those tools normally do. `aka detections` is not one of them: it lists packs and applies pack updates from your local store, and opens no connection of its own. Separately, and not one of the two: `aka <name>` dispatches git-style to an `aka-<name>` program from your own `PATH` (POSIX only; a built-in always wins). That program is yours, not ours — `ai-tc` does not bundle, pin or verify it — so whether it reaches the network is its business, not something this project can describe. The one path that does carry your own data belongs to the Claude Code plugin rather than to this CLI: its **opt-in** `/aka:setup` calibration sends what an initial history scan finds to the model API to be rated, behind two separate opt-ins, and the [plugin README](https://github.com/akasecurity/ai-tc/blob/main/plugins/claude-code/README.md) states that payload field by field.

The local store keeps your prompts and tool calls verbatim apart from the spans a rule masks, and file permissions — not encryption — are all that protect it. See [Data at rest](https://github.com/akasecurity/ai-tc/blob/main/SECURITY.md#data-at-rest) for which files it spans and what holds on Windows.

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
| `aka extension`  | Install the browser-extension bridge (`install` / `status`).     |

Run `aka --help` for the full command list.

### External subcommands

Any other command dispatches, git-style, to an executable named `aka-<command>` on your PATH (POSIX only; built-ins always win). For example, with [aka-claude-tools](https://github.com/akasecurity/claude-tools) installed, `aka claude` launches the hardened Claude Code profile via its `aka-claude` launcher.

## The Claude Code plugin

The CLI gives you the dashboard, store, and scanning. To actually **intercept** a Claude Code session you also need the AKA plugin, which installs from the Claude Code plugin marketplace (not npm). With the CLI installed:

```bash
aka plugins install claude-code
```

This drives Claude Code to add the plugin for you (or prints the `/plugin` commands to run). See the [installation guide](https://akasecurity.github.io/ai-tc-docs/getting-started/installation/) for both components.

## The browser extension (ChatGPT + Claude.ai web chat)

The CLI also ships a Chrome extension that scans messages in ChatGPT and
Claude.ai web chat before they are sent, recording into the same local store
over Chrome's native messaging (no server, no open port). Set it up with:

```bash
aka extension install   # registers the native-messaging host with Chrome
aka extension status    # verify the wiring
```

Then load the extension in Chrome: open `chrome://extensions`, enable
Developer mode, click "Load unpacked", and select the directory the install
command prints. The native host needs a Node.js runtime on the machine.

## Docs

Full documentation, architecture, and the built-in detection catalog live at **[akasecurity.github.io/ai-tc-docs](https://akasecurity.github.io/ai-tc-docs/)**.

## License

[Apache-2.0](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)
