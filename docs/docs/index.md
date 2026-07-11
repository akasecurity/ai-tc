# AI Traffic Control

**AI Traffic Control** (`ai-tc`) is an open-source, local-first control plane that
sits between you and your AI coding tools — intercepting prompts and tool calls,
scanning for sensitive data, enforcing policy inline, and giving you full visibility
into what's being shared with AI models. Everything runs on your machine: no account,
no server, nothing leaves the box. The CLI and plugin ship under the short name
`aka`.

## What it does

```
You ──► Claude Code Plugin ──► Detection Engine ──► AI Model
                                     │
                             (scan / redact)
                                     │
                             Policy Resolution
                             (allow / warn / redact / block)
                                     │
                             Local SQLite store (~/.aka/data/aka.db)
                             (events, findings, audit log)
                                     │
                             aka CLI · web dashboard (read the store directly)
```

Every prompt, tool call, and tool output that flows through a Claude Code session is
captured by the plugin, scanned against your rule packs, and recorded to a local
SQLite store — before the AI sees it or after it responds. The `aka` CLI and the OSS
web dashboard read that same store directly.

## Key concepts

| Term          | Description                                                                      |
| ------------- | -------------------------------------------------------------------------------- |
| **Event**     | A prompt, response, or code change captured from a Claude Code session           |
| **Finding**   | A rule match produced by the detection engine against an event                   |
| **Rule**      | A JSON file describing what to detect: keyword list, regex pattern, or validator |
| **Rule Pack** | A directory of rules + mandatory fixtures with a `manifest.json`                 |
| **Policy**    | A per-detection decision: what action to take when a rule fires                  |
| **Plugin**    | The Claude Code extension (hooks) that intercepts sessions                       |

## Architecture at a glance

The open-source stack is a TypeScript-strict pnpm monorepo. The keep-set:

| Package / app             | Role                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `cli`                     | The `aka` CLI — scan, stats, detections, dashboard, plugin management                                                     |
| `web-ui`                  | OSS Next.js dashboard — reads the local SQLite store in Server Components                                                 |
| `plugins/claude-code`     | Claude Code hooks — captures prompts/tool calls, fail-open                                                                |
| `packages/detections`     | Pure detection engine — scan + redact, no I/O                                                                             |
| `packages/schema`         | Zod contracts + the local-store schema — single source of truth                                                           |
| `packages/persistence`    | Local SQLite store adapter (`node:sqlite`) + `~/.aka` file I/O                                                            |
| `packages/local-ops`      | Shared CLI/web-ui operations — scan pipeline, updates, plugin registry                                                    |
| `packages/dashboard-ui`   | Presentational React views shared by the dashboard                                                                        |
| `packages/plugin-sdk`     | Plugin adapter interface + runtime lifecycle                                                                              |
| `packages/plugin-runtime` | Shared hook runtime the Claude Code plugin scripts are built on                                                           |
| `packages/scanner`        | Working-tree source scan behind the plugin's `/aka:scan`                                                                  |
| `packages/ui-kit`         | Base React UI primitives (Tailwind + Radix)                                                                               |
| `rules/`                  | Detection rule packs (7 packs: secrets, secrets-infra, core-pii, core-phi, core-financial, core-code-context, code-flaws) |

## Quick start

The plugin and the `aka` CLI write a local SQLite store (`~/.aka/data/aka.db`) and
the web dashboard reads it directly — no backend, no Postgres, no account.

```bash
# Install the CLI (see the CLI guide for the full instructions)
npm install -g @akasecurity/cli

# Set up your local AKA home
aka init

# Install the Claude Code plugin
aka plugins install claude-code

# Browse your findings and posture in the web dashboard
aka dashboard
```

See the [Quickstart](getting-started/quickstart.md) for a complete first-run
walkthrough, and the [CLI guide](getting-started/cli.md) for every command.

## Project status

AI Traffic Control is in **active alpha**. The schema contracts, hook interface, and
rule format are stable enough to build on.

!!! warning "Alpha software"

    Breaking changes may occur between releases. Pin the version in production.
