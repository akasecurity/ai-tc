# AI Traffic Control

An AI traffic control plane by [AKA Security](https://github.com/akasecurity) — intercept, inspect, and govern prompts and responses from AI coding tools. Built as a Claude Code plugin plus a local-first `aka` CLI — detection and storage run entirely on your machine.

> **Status:** Alpha — APIs may change; the local store schema is migrated automatically on upgrade.

> **Naming:** the product is **AI Traffic Control** (`ai-tc`). The CLI binary, the plugin id, and the `~/.aka` home directory are named `aka` after AKA Security, the company behind the project.

---

## 100% local — and verifiably so

- **No account, no server, no telemetry.** There is no backend to stand up and nothing leaves your machine.
- **No network calls in the codebase.** CI fails the build if a `fetch()` enters the OSS surface — see [`scripts/check-oss-boundaries.mjs`](scripts/check-oss-boundaries.mjs) (`pnpm check:boundaries`).
- **Your data is one SQLite file you own:** `~/.aka/data/aka.db`, readable with any SQLite client. Delete `~/.aka` and every trace is gone.
- **Raw values never hit disk.** Findings and audit records store masked or hashed representations only — if you ever see a raw secret or PII value reach disk or the network, that is a vulnerability we want reported: see [SECURITY.md](SECURITY.md).

---

## What it does

- **Intercepts** prompts and responses in Claude Code (and later Claude Desktop, Cursor, …) via hooks
- **Scans** for PII, credentials, financial data, and OWASP code findings using a declarative rule engine
- **Takes action** — warn, redact, or block — before content reaches the LLM
- **Logs** every event to a local SQLite store at `~/.aka/data/aka.db` — no backend required
- **Surfaces** findings as formatted slash-command output (`/aka:health`, `/aka:findings`, …), and optionally in a local web dashboard

---

## Quick start

**Claude Code plugin (default):** in the Claude Code terminal CLI, run `/plugin marketplace add akasecurity/ai-tc` then `/plugin install aka@ai-tc`, then `/aka:setup` to choose your installation type and redaction handling. Detection runs locally and persists to `~/.aka/data/aka.db`; view it with the `/aka:health`, `/aka:findings`, `/aka:recommend`, and `/aka:audit` slash commands, or `/aka:dashboard` to open the full web dashboard in your browser.

**Full local dashboard (opt-in):** the `aka` CLI ships an OSS web dashboard over the
_same_ `~/.aka/data/aka.db` — no backend, no Docker, no auth. See
[The `aka` CLI](#the-aka-cli-local-first-no-docker) below.

**Dev environment (one command):**

```bash
git clone https://github.com/akasecurity/ai-tc.git
cd ai-tc
pnpm setup          # install dependencies + git hooks
pnpm dev            # turbo watch across the workspaces
```

---

## The `aka` CLI (local-first, no Docker)

The `aka` CLI runs detection, the local store, and the dashboard **entirely on your
machine** — it reads/writes the same `~/.aka/data/aka.db` the plugin uses.

**Requirements:** Node.js 24 or newer (the store uses the built-in `node:sqlite` — no
native dependency).

```bash
# 1. Install the CLI.
npm install -g @akasecurity/cli

# 2. Set up your machine + scan.
aka init                 # scaffold ~/.aka (settings + local SQLite store)
aka scan .               # scan for secrets / sensitive data (raw secrets never hit disk)
aka stats                # findings + enforcement aggregates

# 3. Open the local dashboard, or install an agent plugin.
aka dashboard            # local web UI at http://localhost:4319/security (no backend, no auth)
aka tui                  # interactive terminal dashboard
aka plugins install claude-code   # prints how to add the ai-tc marketplace in Claude Code
```

Or use the bootstrap one-liner, which checks your Node version and installs `aka`
from the public npm registry:

```bash
curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.sh | sh
# Windows: irm https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.ps1 | iex
```

Full guide — machine setup and every command:
[**docs → Getting Started → CLI (aka)**](docs/docs/getting-started/cli.md).

---

## Repo layout

```
packages/
  eslint-config/    Shared flat ESLint config (strict type-checked, boundary rules)
  schema/           Zod contracts + Drizzle-defined SQLite local store + rule registry — THE source of truth
  persistence/      Local SQLite adapter for the ~/.aka store + read/view ports (node:sqlite)
  detections/       Pure detection engine: scan() / redact(), rule registry
  extract/          Content extraction helpers (CSV, …)
  local-ops/        Shared CLI/web-ui operations: scan pipeline, update/apply, plugin registry
  dashboard-ui/     Bundler-agnostic presentational dashboard views (props-driven)
  ui-kit/           AKA design system components
  plugin-sdk/       Shared plugin engine: local SQLite store, capture orchestration, action resolution, onboarding
  plugin-runtime/   Hook runtime built on the plugin SDK
  scanner/          Worktree source scanner (node:fs)

cli/                The `aka` CLI — bundles the web-ui for `aka dashboard`
web-ui/             OSS Next.js dashboard (reads the local SQLite store)
plugins/
  claude-code/      Claude Code hooks adapter

rules/              Declarative detection rule packs (core-pii, secrets, …)
tools/
  installer/        CLI install scripts
skills/             Claude Skills for AI-assisted development on this repo
docs/               MkDocs documentation site (public user-facing docs)
```

---

## Development

```bash
pnpm install        # install all workspaces
pnpm dev            # turbo: watch mode across the workspaces
pnpm lint           # ESLint across all workspaces
pnpm typecheck      # tsc --noEmit across all workspaces
pnpm test           # Vitest across all workspaces
pnpm build          # production build (CLI + web-ui + plugin)
```

Lint, typecheck, and format run automatically on staged files via Lefthook pre-commit hooks.

---

## Contributing detection rules

Rules live in `rules/<pack-name>/`. Each rule requires labelled positive **and** negative fixtures — CI rejects rule PRs without them. See [skills/write-detection-rule/SKILL.md](skills/write-detection-rule/SKILL.md) for the full rule format and contribution contract, and [CONTRIBUTING.md](CONTRIBUTING.md) for the general contribution guide.

---

## Architecture

See the [architecture overview](docs/docs/architecture/overview.md) and [detection engine](docs/docs/architecture/detection-engine.md) docs for the design: detection engine extensibility, the plugin SDK, and the local store.
