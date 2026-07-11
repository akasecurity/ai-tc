# Local / Single-Node

AKA's open-source surface runs entirely on one machine with **no server, no Docker, and
no Postgres**. The Claude Code plugin and the `aka` CLI write a local SQLite store at
`~/.aka/data/aka.db` via `@akasecurity/persistence` (Node's built-in `node:sqlite` — no native
dependency), and the OSS web dashboard reads that same store directly in Server
Components. Nothing leaves the machine; there is no account, no network, and no database
server.

## Running it

```bash
# Install the CLI and set up your local home
npm install -g @akasecurity/cli
aka init

# Install the Claude Code plugin (it writes ~/.aka/data/aka.db during sessions)
aka plugins install claude-code

# Browse your findings / health / posture in the web dashboard
aka dashboard          # launches the Next.js web-ui over ~/.aka/data
# or a terminal view:
aka tui
```

See the [CLI guide](../getting-started/cli.md) and the
[Claude Code plugin](../plugin/claude-code.md) page for the full command set and hook
behaviour. This is the recommended — and only — way to run the open-source surface.

## Where things live

Everything AKA owns lives under `~/.aka`:

| Path                            | What                                                      |
| ------------------------------- | --------------------------------------------------------- |
| `~/.aka/settings/settings.json` | Your preferences (run mode, redaction policy)             |
| `~/.aka/data/aka.db`            | The local SQLite store (events, findings, policies)       |
| `~/.aka/data/exception.key`     | The machine-local HMAC key for detection-exception grants |

Exclude `exception.key` from shared backups: anyone holding both the store and the
key can test candidate values against the exception fingerprints in the DB. If the
data directory was exposed, rotate the key with `aka exception rotate-key`
(`rotateFingerprintKey`) — rotation invalidates every existing grant.

To start over, remove `~/.aka` and run `aka init` again.

## Running the docs

```bash
pip install -r docs/requirements.txt
pnpm --filter @akasecurity/docs dev
```

Navigate to `http://localhost:8000`.
