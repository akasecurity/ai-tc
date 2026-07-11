# The `aka` CLI

`aka` is the local-first command-line tool for AI Traffic Control. It runs **entirely on your
machine** — detection, the local store, and the dashboard all work with **no backend
and no Docker**. It reads and writes the same local SQLite store (`~/.aka/data/aka.db`)
that the Claude Code plugin uses, so the CLI and the plugin share one view of your
findings.

What you get:

- `aka init` — set up your local AKA home
- `aka scan` — scan files/directories for secrets & sensitive data
- `aka stats` — print findings/enforcement aggregates + token usage & estimated cost
- `aka detections` — list installed detection packs + apply updates (manual)
- `aka dashboard` — open the local web dashboard
- `aka tui` — an interactive terminal dashboard
- `aka exception` — manage detection exceptions (see [Detection Exceptions](../cli/exceptions.md))
- `aka plugins` — install/manage agent plugins (Claude Code, …)
- `aka completion` — print the shell tab-completion script (zsh/bash)
- `aka check-updates` — see whether the CLI or your plugins have updates
- `aka update` — update the CLI and/or plugins to the latest version
- `aka --version` — print the installed CLI version

---

## Prerequisites

- **Node.js 26+** — the CLI uses the built-in `node:sqlite` (no native dependency).
  Install from [nodejs.org](https://nodejs.org) or a version manager (`fnm`, `nvm`,
  `volta`). Check with `node --version`.

The packages are published to the **public npm registry** under the `@akasecurity`
scope — no account, token, or registry configuration is needed to install.

---

## Install (recommended: the bootstrap installer)

The one-liner **requires Node 26+** — it checks for it and tells you to install it if
it's missing; it does **not** install Node for you — then installs the global `aka`
CLI from the public npm registry:

=== "macOS / Linux"

    ```bash
    curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.sh | sh
    ```

=== "Windows (PowerShell)"

    ```powershell
    irm https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.ps1 | iex
    ```

> **Note — installer integrity:** the one-liner fetches the installer from the
> `cli-latest` tag of the `akasecurity/ai-tc` repo — never the mutable `main`
> branch — and verifies the downloaded installer script (`install.mjs`) against a
> SHA-256 baked into the entry script at the same tag before running it; on a
> mismatch it refuses to run. `cli-latest` moves only when a release is cut, always
> to a published `cli-v*` release. To pin an exact release instead, set
> `AKA_INSTALL_REF=cli-v<version>` in the environment before running the one-liner —
> the `cli-v*` release tags are immutable.

The installer also removes a stale `@akasecurity:registry=https://npm.pkg.github.com`
override from your `~/.npmrc` if one exists — the packages live on the public npm
registry, and a leftover override would break the install. Nothing else in the file
is touched.

Then verify:

```bash
aka --help
```

### Manual install (if you'd rather not use the one-liner)

```bash
npm install -g @akasecurity/cli
```

---

## Set up your machine

```bash
aka init
```

This scaffolds your local AKA home (owner-only `~/.aka`):

- `~/.aka/settings/settings.json` — your preferences (run mode, redaction policy).
  Re-running `aka init` **never overwrites** an existing settings file.
- `~/.aka/data/aka.db` — the local SQLite store (created, migrated, and seeded with the
  default per-category detection policies).

`aka init` is idempotent — run it as often as you like.

---

## Scan for secrets & sensitive data

```bash
# Scan a directory (skips node_modules, ANY dot-directory, build output, files > 1 MB)
aka scan .

# Scan a single file (no skip rules — works even for dot-dirs like ~/.aws, ~/.ssh)
aka scan path/to/file.env
aka scan ~/.aws/credentials
```

A recursive `aka scan .` skips **every hidden (dot-)directory** — `.git`, but also
`.github`, `.aws`, `.ssh`, `.config`, … — so it won't descend into them. To sweep a
dot-directory, point `aka scan` **directly** at the file or folder (the single-path
form has no skip rules).

Findings are recorded into the local store. **Raw secrets never touch disk** — the
store keeps only a masked preview of the match and a redacted copy of the file
content.

```bash
aka stats              # findings, enforcement, token usage & cost, latest findings
aka stats --range 7d   # windows the enforcement + token-usage sections
```

`--range` accepts `7d | 30d | 3m | 6m` and scopes the enforcement aggregates **and** the
token-usage block — findings-by-severity and the latest findings are always all-time. An
unrecognized value silently falls back to `30d` (it doesn't error).

The **token-usage** block rolls up your `llm_call` history (reconciled from Claude Code
transcripts by the plugin) per provider/model, with an **estimated** USD cost derived at
read time. Token counts are exact; a `—` means unknown pricing (a local or non-Anthropic
model), so a `≥` total is a lower bound, never an understatement. The same rollup powers
the TUI's Health screen (`aka tui`) and the web-ui **Activity** page — token reporting has
no dedicated surface of its own.

---

## Manage detection packs

```bash
aka detections                    # list installed packs + available updates
aka detections update --all       # apply every pending update
aka detections update <pack-id>   # apply one (accepts `secrets` or `aka/secrets`)
```

`aka detections` prints one row per installed pack: installed version, the latest
version this CLI ships, rule count, enabled state, assigned enforcement policy,
and whether an update is available.

Detection updates are **manual by design**. Upgrading the CLI or plugin only
records what's newly _available_ — the packs you have installed keep running
unchanged (same rules, same versions) until you apply the update yourself with
`aka detections update` or the dashboard's **Update** button. `aka init` and the
plugin's session hooks install packs you don't have yet (new packs arrive
enabled under the log-only _monitor_ policy), but they **never modify** an
installed pack; your enabled/disabled choices and policy assignments always
survive an update.

---

## Open the dashboard from the CLI

```bash
aka dashboard
```

This launches the local web dashboard (the OSS Next.js app) against your `~/.aka`
store and opens your browser at `http://localhost:4319/security`. It reads the local
store directly — **no backend, no auth, nothing leaves your machine** (the server
binds to `127.0.0.1` only).

Launching the dashboard also refreshes the detection-pack **update status**: the CLI
records what this binary ships before the server starts, so the Detections page shows
real installed-vs-available state even on a machine where no plugin hook has run.

```bash
aka dashboard --port 8080   # use a different port
aka dashboard --no-open     # start the server without opening a browser
```

The dashboard covers the full CLI feature set, so everything below can also be done
from the browser:

| Page          | What it does                                                      | CLI twin                     |
| ------------- | ----------------------------------------------------------------- | ---------------------------- |
| `/security`   | Posture cards + prioritized recommended actions                   | `aka stats` / `aka tui`      |
| `/findings`   | Grouped findings with filters and detail                          | `aka tui findings`           |
| `/exceptions` | List/approve/pre-authorize/revoke grants, rotate the key          | `aka exception …`            |
| `/scan`       | Run the installed detection rules over a local path               | `aka scan <path>`            |
| `/updates`    | Installed-vs-latest for CLI + plugins, apply updates and installs | `aka update` / `aka plugins` |
| `/settings`   | Edit the redact/warn policy and historical-access consent         | `/aka:setup` wizard          |

Prefer the terminal? Use the interactive Ink dashboard instead:

```bash
aka tui
```

---

## Install agent plugins

The CLI is an optional **hub** for installing agent plugins — but each plugin also
installs on its own, so the CLI is never required.

```bash
aka plugins list                 # show available agents, installed version, active state
aka plugins install claude-code  # install / set up an agent plugin
```

- **Claude Code** is distributed through the **AKA marketplace**, and
  `aka plugins install claude-code` installs it end-to-end: it adds the marketplace
  and installs the plugin by delegating to the `claude` CLI's plugin manager, then
  reminds you to restart Claude Code and run `aka init`. If the `claude` CLI isn't on
  your `PATH`, it falls back to printing the in-app `/plugin` commands to run instead.
- Other agents (Cursor, GitHub Copilot, …) appear as **coming soon** until they ship.

`aka plugins list` is read-only — it will **not** create a local store if you haven't
run `aka init` yet.

---

## Keeping up to date

The CLI and your installed plugins are versioned independently. Two commands keep
them current:

```bash
aka check-updates   # read-only: show installed vs latest for the CLI + each plugin
aka update          # update everything that's behind (asks before applying)
aka update cli      # update just the CLI
aka update claude-code   # update just one plugin
```

- `aka check-updates` changes nothing — it just reports what's available. Latest
  versions are resolved with `npm view` against the public npm registry; if the
  registry is unreachable, "Latest" shows as **unknown** and nothing is flagged.
- `aka update` shows what would change and **prompts for confirmation** before
  applying. Pass `--yes` (or `-y`) to skip the prompt (required when there's no
  interactive terminal, e.g. in a script). The CLI updates itself with
  `npm install -g @akasecurity/cli@latest`; plugins update through the `claude` plugin
  manager (**restart Claude Code afterwards** to load the new version).
- After other commands, the CLI prints a one-line **notice** when an update — or a
  newly available plugin — is waiting, with the exact command to run. It's computed
  from a once-a-day cached check (refreshed in the background, never blocking), is
  suppressed when output isn't a terminal, and can be turned off per run with
  `--no-update-check`.

---

## Shell tab-completion

Turn on `<TAB>` completion for `aka` — type `aka exc<TAB>` and your shell fills in
`aka exception`.

```bash
# zsh (macOS default)
echo 'source <(aka completion zsh)' >> ~/.zshrc

# bash
echo 'source <(aka completion bash)' >> ~/.bashrc
```

Open a new terminal (or `source` the same line now) and `aka <TAB>` completes
commands, subcommand verbs (`aka exception <TAB>` → `approve add list …`),
`aka scan` file paths, and global flags. `aka completion <zsh|bash>` just prints the
script — you load it into your shell, you don't read it.

---

## Where things live

| Path                            | What                                                |
| ------------------------------- | --------------------------------------------------- |
| `~/.aka/settings/settings.json` | Your preferences (run mode, redaction policy)       |
| `~/.aka/data/aka.db`            | The local SQLite store (events, findings, policies) |

Everything is local. To start over, remove `~/.aka` and run `aka init` again.
