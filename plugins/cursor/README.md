# @akasecurity/ai-tc-cursor — the `aka` plugin for Cursor

**Not released yet.** This package is private in the workspace and is not on npm.

The Cursor plugin for **[AI Traffic Control](https://github.com/akasecurity/ai-tc)** (`ai-tc`). It registers user-level Cursor agent hooks that record each session's start, prompts, tool calls and tool results to the local SQLite store at `~/.aka/data/aka.db`, scanning each one against your rule packs. It can stop a prompt or a tool call before it runs.

Detection runs on your machine, against your local rule packs, with no account and no backend. What can leave the machine, and when, is set out in [SECURITY.md](https://github.com/akasecurity/ai-tc/blob/main/SECURITY.md#data-in-transit).

## What it does on each event

Every row is built from Cursor's published hooks reference. None has been verified against a live Cursor install yet.

| Event                | Captured                                   | Enforcement                                                                                         |
| -------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `sessionStart`       | the session, its project and the harness   | none                                                                                                |
| `beforeSubmitPrompt` | the prompt, always                         | `block` stops the prompt (`continue: false`); a prompt too large to scan in time is stopped too     |
| `preToolUse`         | Shell commands, file writes, MCP arguments | `block` denies the call; a field too large to scan in time is denied too                            |
| `postToolUse`        | the tool output, when a rule matches       | none: the tool has already run, so a finding is recorded and the output reaches the model unchanged |

- **Nothing is rewritten.** Cursor documents an input rewrite on `preToolUse` and none on prompts; this plugin uses neither, so a `redact` policy resolves to the workspace's `redactFallback` (warn by default).
- **A warn is shown only in Cursor's Hooks output channel**, on stderr. A deny or a stopped prompt carries its own message.
- **It never emits an allow.** A clean call writes nothing, and Cursor's own permission settings decide as they would without AKA.
- **It fails open.** A crash, a timeout or an unreadable store lets the action through and exits 0. The one exception is a field too large to scan in time, which is refused rather than passed unscanned.

## Install (from a checkout)

```sh
pnpm --filter @akasecurity/ai-tc-cursor build
node plugins/cursor/scripts/install.js
aka init
```

`install.js` adds one entry per event to `~/.cursor/hooks.json`, pointing at the `scripts/` directory it was run from and at the node binary that ran it. Your own hooks in that file are kept. Restart Cursor after installing. To remove the entries:

```sh
node plugins/cursor/scripts/install.js --uninstall
```

## License

[Apache-2.0](https://github.com/akasecurity/ai-tc/blob/main/LICENSE)
