---
description: Set up the AKA Control Plane plugin — sensitive-data handling and historical access
---

# AKA setup wizard

You are onboarding the AKA Control Plane plugin for this machine. AKA works
fully locally with **zero backend and zero Docker**: detection runs in-process
and findings persist to a local SQLite store at `~/.aka/data/aka.db`. This
wizard records two preferences. Ask the questions in order, then save once.

## 0. Show the intro card

Run the intro script and show the user its output **exactly as printed** — it is a
space-aligned monospace card (name, repository, version, what AKA adds). The script
already prints it inside a Markdown code fence; reproduce that verbatim and do
**not** add another code fence, strip the fence, or reformat it (unfenced, Markdown
collapses the indentation and mangles the `●` line). Then continue with the two
questions below.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/intro.js" "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json"
```

## 1. Ask the two questions

Use the **AskUserQuestion** tool — Claude Code's built-in interactive picker — to
ask both questions. The plugin can't draw its own selectable UI (it can't
capture keystrokes), so do **not** print a fake option list or ask the user to
"reply with a number"; let the picker collect the answers.

Ask these two questions (a single AskUserQuestion call with both is fine):

**Sensitive-data handling** — "When AKA detects sensitive data on its way to a model, it should:"

List **Warn only** as the first (top) option:

- **Warn only** → `warn` _(recommended)_ — flag the request and let the user
  decide; nothing is modified automatically.
- **Actively redact** → `redact` — replace secrets with safe placeholders before
  the request is sent. Redaction rewrites the real payload, so opt in only when
  you want that. (Either mode can be changed per-project later.)

**Historical & memory access** — "Secrets often leak before AKA is installed. May I also review your temp files, agent memory & prior conversation transcripts?"

List **Grant full review** as the first (top) option:

- **Grant full review** → `full` — scan scratch/temp files, agent memory & prior
  transcripts for leaked secrets (deepest coverage · one-time consent, revocable
  under Policies).
- **Current session only** → `session-only` — decline historical access; AKA
  reviews only what this session already touches. Even if declined, AKA can still
  review: the **working tree** (all source, config & dotfiles in the repo), **this
  session** (prompts, tool calls & files Claude reads or writes now), **git
  history** (commits reachable from HEAD, incl. removed-but-tracked secrets), and
  **pointed scans** (any path you explicitly hand AKA during a run).

Map the picked labels to the flag values shown above (`redact`/`warn`,
`full`/`session-only`).

## 2. Save the answers

Run the onboarding writer with the chosen values. Omit a flag to keep its
default. This validates and persists to `~/.aka/settings/settings.json` (created
`0600`, owner-only) and stamps the machine as onboarded:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --policy <redact|warn> --historical <full|session-only>
```

## 2.5 Scan history (only if they granted full review)

**Only when the user picked "Grant full review" (`historical=full`)**, run the
backfill. It sweeps prior Claude Code transcripts (last 30 days, all projects)
for secrets that leaked before AKA was installed and records them into the local
store, so they show up in the first-run summary and `/findings`. The scan is
idempotent — it skips messages already recorded — so re-running `/aka:setup` is
safe and never duplicates findings. Show its output **exactly as printed** (it
self-fences; do not add another fence or reformat). Skip this step entirely when
they chose `session-only`.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/backfill.js"
```

## 3. Show the first-run summary

Run the first-run script and show its output **exactly as printed** (the
install-complete summary with live findings/recommendation counts and the health
score). The script already prints it inside a Markdown code fence; reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it (it
is space-aligned monospace that Markdown would otherwise collapse).

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/firstrun.js"
```

## 3.5 Offer the AKA CLI + local dashboard (opt-in)

Now that the plugin is set up, offer the optional **AKA CLI + local dashboard** —
a richer, still-fully-local surface over the same `~/.aka` store this plugin
writes. The plugin works completely on its own; this is additive (and the path to
future multi-agent support). Use **AskUserQuestion**:

**Add the AKA CLI + dashboard?** — "Install the `aka` CLI for a local web +
terminal dashboard and on-demand scans? Everything stays on your machine."

- **Yes, install it** _(recommended)_ — adds the `aka` binary: `aka stats`,
  `aka tui` (terminal dashboard), `aka dashboard` (local web UI), `aka scan`.
- **Not now** — skip; it can be added anytime with the one-liner below.

If they choose **Yes**, run the bootstrap installer (it ensures Node is available
and installs the global CLI from the public npm registry). **Ask permission
before running it**, then run the line for their OS:

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.ps1 | iex
```

The one-liner pins to the stable release **tag** (`cli-latest`), never `main` —
each release points that tag at its published `cli-v*` version, and the bootstrap
scripts it fetches hold the installer's pinned ref + checksum, so fetching them
from a mutable branch would defeat the integrity gate. To pin an exact version
instead, set `AKA_INSTALL_REF=cli-v<version>` before running the line. Until the
first release is published the one-liner 404s (fail-closed).

After it completes, point them at `aka init` then `aka dashboard`. If they chose
**Not now**, show the one-liner once so they can add it later, and move on —
declining keeps the plugin fully functional standalone.

**Fail open.** This install is optional, so it must never derail the session. If
the installer fails for any reason — Node missing, network/registry error, a
non-zero exit, or the checksum check rejecting a bad download — briefly report
what happened, show the one-liner so they can retry later, and continue the
wizard normally. The plugin is already fully set up and works on its own; a
failed CLI install changes nothing about that.

## 4. Report the result

- The first-run summary already confirms the saved handling and points at
  `/health`. Add at most one short sentence: detection runs locally and nothing
  leaves the machine.
