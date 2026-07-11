# Configuration

AI Traffic Control is **local-first**: the `aka` CLI, the web dashboard, and
the Claude Code plugin all run on your machine against a local SQLite store. There is
no server to configure, no database URL, and no account. Most configuration is either
a file under `~/.aka` or a small number of optional environment variables the plugin
reads directly at session start.

## Where configuration lives

| What        | Where                           | Written by                          |
| ----------- | ------------------------------- | ----------------------------------- |
| Local store | `~/.aka/data/aka.db`            | `aka init`, the plugin, `aka scan`  |
| Preferences | `~/.aka/settings/settings.json` | `/aka:setup`, `aka init`, dashboard |

The local store is a SQLite database managed through `@akasecurity/persistence` (Node's
built-in `node:sqlite` — no native dependency). It holds events, findings, policies,
and the audit timeline. Nothing in the open-source surface writes anywhere else.

## Preferences (`settings.json`)

`aka init` and the plugin's `/aka:setup` wizard record your preferences to
`~/.aka/settings/settings.json` (created `0600`, owner-only):

```json
{
  "specVersion": 2,
  "runMode": "standalone",
  "policy": "redact",
  "historicalAccess": "session-only",
  "onboardedAt": "2026-06-18T..."
}
```

- **`runMode`** — `standalone` (default): read/write the local SQLite store, nothing
  leaves the machine.
- **`policy`** — `redact` (replace sensitive values in place where the host allows) or
  `warn` (surface a warning, never modify content).
- **`historicalAccess`** — `session-only` (default) or `full`: consent for scanning
  pre-install surfaces (scratch files, prior transcripts) for already-leaked secrets.

The file is **versioned** (`specVersion`): an older file still parses, with any missing
key taking its default. The plugin re-reads it on every hook, so a change made in the
dashboard's **Settings** page (`aka dashboard` → `/settings`) takes effect on the next
capture with no restart. See
[Claude Code plugin → Configuration](../plugin/claude-code.md#configuration).

## Environment variables

The CLI and plugin need **no environment variables** to run in the default
standalone mode. The variables below are optional and are the only ones the
open-source surface reads.

### Provider resolution (SessionStart snapshot)

At `SessionStart` the plugin resolves the machine's AI-provider context (which model
provider a session is running against) to attribute captured activity. This is the one
place the plugin consults the environment, read from the host process at session start
only — standard provider variables such as `ANTHROPIC_API_KEY` / `CLAUDE_API_KEY` are
read for **presence and provider identity**, never stored. No provider key is required
for detection to work; absence just leaves the provider attribution unknown.

## Resetting

Everything the open-source surface owns lives under `~/.aka`. To start over, remove the
directory and re-initialise:

```bash
rm -rf ~/.aka
aka init
```
