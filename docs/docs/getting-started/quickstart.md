# Quickstart

This guide takes you from zero to a working AI Traffic Control installation: the
`aka` CLI installed, the Claude Code plugin active and capturing your sessions, and
findings visible in the local web dashboard. Everything runs on your machine — no
server, no database, no account.

## Prerequisites

- **Node.js 26+** — the CLI and plugin hooks use the built-in `node:sqlite` (no native
  dependency), and `node` must be on your `PATH` (the hooks invoke it). Check with
  `node --version`.
- **Claude Code** installed and signed in.

## 1. Install the `aka` CLI

```bash
npm install -g @akasecurity/cli
aka --version
```

See the [CLI guide](cli.md) for the bootstrap installer and Windows instructions.

## 2. Set up your local AKA home

```bash
aka init
```

This scaffolds `~/.aka` (owner-only): your preferences
(`~/.aka/settings/settings.json`) and the local SQLite store
(`~/.aka/data/aka.db`, created, migrated, and seeded with the default per-detection
policies). `aka init` is idempotent — run it as often as you like.

## 3. Install the Claude Code plugin

```bash
aka plugins install claude-code
```

This adds the AKA marketplace and installs the plugin by delegating to the `claude`
CLI's plugin manager. Restart Claude Code afterwards to load it. (You can also install
it from inside Claude Code — see the [Claude Code plugin](../plugin/claude-code.md)
page.)

## 4. Capture a session

Start a Claude Code session and submit a prompt containing a fake secret, e.g.:

```
My AWS key is AKIAIOSFODNN7EXAMPLE, can you check this config?
```

By default every detection is **Monitor** (log-only), so the prompt passes through but
the match is recorded. Inside the session, `/aka:findings` and `/aka:health` show the
recorded detection. Raise the `secrets` detection to **Block** on the dashboard's
Detections page (step 6) to have the same prompt blocked.

You can also exercise a hook directly, without a live session:

```bash
echo '{"prompt":"My SSN is 123-45-6789 and AWS key AKIAIOSFODNN7EXAMPLE"}' \
  | node ~/.claude/plugins/**/aka/scripts/user-prompt-submit.js
# → no output = allow (Monitor default); or a block decision once secrets = Block
```

## 5. Scan files for already-leaked secrets

The CLI scans the working tree (or any path) with the same detection engine the hooks
use:

```bash
aka scan .                 # scan a directory (skips node_modules, dot-dirs, build output)
aka scan ~/.aws/credentials # scan a single file (no skip rules)
aka stats                  # findings, enforcement, token usage & cost
```

Raw secrets never touch disk — the store keeps only a masked preview and a redacted
copy of the content.

## 6. Open the dashboard

```bash
aka dashboard
```

This launches the OSS web-ui against your `~/.aka` store and opens your browser at
`http://localhost:4319/security` (bound to `127.0.0.1` only). From here you can review
findings, set per-detection enforcement policy, and manage your inventory — the full
CLI feature set is also available in the browser.

## What's next

- [Configure your local setup](configuration.md)
- [Write your first detection rule](../rules/writing-rules.md)
- [Learn the full CLI](cli.md)
- [Install the plugin for a teammate](../plugin/claude-code.md)
