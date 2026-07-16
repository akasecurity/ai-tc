# @akasecurity/ai-tc-claude-code — the `aka` plugin for Claude Code

[![npm](https://img.shields.io/npm/v/@akasecurity/ai-tc-claude-code?style=flat-square&labelColor=232F3E&color=00E0B8)](https://www.npmjs.com/package/@akasecurity/ai-tc-claude-code)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-232F3E?style=flat-square)](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)

The Claude Code plugin for **[AI Traffic Control](https://github.com/akasecurity/ai-tc)** (`ai-tc`). It hooks into a Claude Code session and inspects its traffic — prompts, tool calls, tool results, file reads — scanning each event against your rule packs and applying inline **warn / redact / block** policies. Every event is recorded to a local SQLite store at `~/.aka/data/aka.db`.

Detection runs entirely on your machine. There's no account and no backend — nothing leaves your computer to be scanned.

## Install

This package is distributed through the **Claude Code plugin marketplace**, not `npm install`. Add the marketplace and install the plugin from inside Claude Code:

```text
/plugin marketplace add akasecurity/marketplace
/plugin install ai-tc@akasecurity
```

Or let the `aka` CLI install the plugin for you:

```bash
npm install -g @akasecurity/cli
aka plugins install claude-code
```

Either way, finish onboarding by running `/aka:setup` from inside Claude Code:

```text
/aka:setup
```

If you installed via the CLI, `aka init` scaffolds the local store and `aka dashboard` views findings.

## What it registers

The plugin installs Claude Code hooks that run locally with no `node_modules`, and fail open (a hook error never breaks your session):

- **SessionStart** — snapshot the session context.
- **UserPromptSubmit** — scan prompts before they reach the model.
- **PreToolUse** — scan tool inputs (Bash, Edit, Write, MultiEdit, NotebookEdit, WebFetch, Task, and
  any `mcp__*` tool) before they run. Sensitive content in text a tool merely stores is masked in
  place; in text a tool acts on — a shell command, a URL, an MCP argument — masking would change what
  runs, so the call is blocked instead.
- **PostToolUse** — scan tool outputs and file reads (Bash, Read, WebFetch) after they return.
- **Stop** — reconcile token usage and finalize the session record.

It also adds slash commands for reports and setup (`/aka:health`, `/aka:findings`, `/aka:dashboard`, and more).

## Docs

Full documentation and the built-in detection catalog live at **[akasecurity.github.io/ai-tc-docs](https://akasecurity.github.io/ai-tc-docs/)**.

## License

[Apache-2.0](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)
