---
description: Set up the AKA Control Plane plugin — evidence-first detection posture and historical access
---

# AKA setup wizard

You are onboarding the AKA Control Plane plugin for this machine. AKA works
fully locally with **zero backend and zero Docker**: detection runs in-process
and findings persist to a local SQLite store at `~/.aka/data/aka.db`.

This wizard is **evidence-first**: instead of asking you to guess a global
redact/warn setting up front, it looks at your _actual_ history for real
leaked findings, triages them (silently filtering the routine false-positive
noise regex rules produce), and recommends a detection **posture per
category** (`secret`, `pii`, `financial`, `phi`, `code_context`, `code_flaw`,
`config`, `custom`) — shown to you with its reasoning — before anything is
written. If there isn't enough history to judge, or you decline the
historical review, it falls back to a conservative severity-derived floor
instead of guessing.

The false-positive/severity judgment itself runs in a **separate, transient
subprocess that writes no transcript** — the raw (unmasked) finding values are
never read into this conversation or your scannable history. You act only on the
raw-free plan that subprocess prints back.

Follow the steps below **in order**. Nothing is written to the policy store
until step 5 (or the floor branch in step 2).

## 0. Show the intro card

Run the intro script and show the user its output **exactly as printed** — it is a
space-aligned monospace card (name, repository, version, what AKA adds). The script
already prints it inside a Markdown code fence; reproduce that verbatim and do
**not** add another code fence, strip the fence, or reformat it (unfenced, Markdown
collapses the indentation and mangles the `●` line).

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/intro.js" "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json"
```

## 1. Ask historical-review consent

Ask this **before** anything about detection posture — the posture
recommendation in step 4 is _derived from_ the answer to this question, so it
has to come first. Use the **AskUserQuestion** tool — Claude Code's built-in
interactive picker. The plugin can't draw its own selectable UI (it can't
capture keystrokes), so do **not** print a fake option list or ask the user to
"reply with a number"; let the picker collect the answer.

**Historical & memory access** — "Secrets often leak before AKA is installed. May I also review your temp files, agent memory & prior conversation transcripts?"

List **Grant full review** as the first (top) option:

- **Grant full review** → `full` — scan scratch/temp files, agent memory & prior
  transcripts for leaked secrets (deepest coverage · one-time consent, revocable
  under Policies). This is what lets AKA recommend a posture backed by your
  real findings instead of a generic default.
- **Current session only** → `session-only` — decline historical access. AKA
  starts in a conservative observe-first posture instead (step 2) and can
  still review: the **working tree** (all source, config & dotfiles in the
  repo), **this session** (prompts, tool calls & files Claude reads or writes
  now), **git history** (commits reachable from HEAD, incl.
  removed-but-tracked secrets), and **pointed scans** (any path you explicitly
  hand AKA during a run).

Map the picked label to the flag value shown above (`full`/`session-only`).

## 2. Save the historical answer, then branch

Run the onboarding writer with the answer from step 1. This must happen
**before** the backfill (step 3), because the backfill script reads
`historicalAccess` from the saved settings to decide whether it's allowed to
run. Omitting `--policy` is deliberate — the old global redact/warn toggle no
longer drives enforcement (posture is per-category now); its field is kept
for backward compatibility but this wizard doesn't ask about it.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --historical <full|session-only>
```

**Branch on the historical answer:**

- **If the user chose "Current session only" (`session-only`)** — there is no
  history to calibrate a posture from. Write the severity-derived floor
  immediately and skip straight to step 6 (first-run summary); steps 3–5 do
  not run:

  ```bash
  node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --floor
  ```

  Briefly tell the user why: without evidence, AKA starts every high-impact
  category (`secret`/`pii`/`financial`/`phi`/`code_flaw`/`custom`) at `warn`
  so nothing is under-watched, and low-value/observe-only categories
  (`code_context`/`config`) at `monitor` — conservative, no guessing. This can
  be revisited any time via `/aka:setup` or Policies.

- **If the user chose "Grant full review" (`full`)** — continue to step 3.

## 3. Run the evidence triage — isolated judgment, nothing written yet

Pipe the backfill's triage stream straight into the `apply-suppressions`
adapter in **PREVIEW** mode (no `--confirmed`):

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/backfill.js" --triage | node "${CLAUDE_PLUGIN_ROOT}/scripts/apply-suppressions.js"
```

The backfill sweeps prior Claude Code transcripts (last 30 days, all projects)
and streams one masked-plus-raw triage hit per line; masked findings are
recorded to the local store as a side effect. The adapter runs the
false-positive/severity **judgment in a separate transient subprocess** (no
transcript), then prints back a **raw-free plan** you can safely show the user:
the per-category posture it would apply, the masked false positives it would
suppress, any categories it skipped, and its notes.

The preview also **persists that exact raw-free plan to a temp file and prints
its path** — a line beginning `Plan saved to: <path>`. Capture that path: step 5
applies **this saved plan verbatim**, so the confirm step performs no second scan
and no second judgment. (The plan file carries only masked/fingerprint/enum data;
it is deleted after a successful apply.)

Everything you show the user in step 4 comes from **this command's output**. You
never read the raw finding values yourself — do not echo, quote, or reconstruct
them; by design they stay inside the isolated subprocess.

**Failed or truncated triage — never proceed silently (fallback).** If this
command exits non-zero, or the adapter reports a truncated / sentinel-less
stream, the calibration could **not** complete. Do not guess a posture and do
not leave setup half-applied. Apply the conservative severity floor, **tell the
user it happened**, and continue to step 6:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --floor
```

Say plainly: the historical scan couldn't finish, so AKA is starting from the
conservative severity floor (high-impact categories at `warn`, observe-only at
`monitor`) instead of a calibrated posture, and it can be re-run any time with
`/aka:setup`.

**Nothing to calibrate.** If the adapter reports there were no triage hits to
review (an empty or intentionally-skipped scan), there's no evidence to
calibrate from: take the same floor branch (`onboard.js --floor`), tell the
user the scan found nothing to calibrate from, and skip to step 6.

Otherwise continue to step 4.

## 4. Show the calibration and get explicit confirmation — before any write

The preview output is raw-free and has three parts. Show the user **all** of
them.

**Known limitation — the showcase is a first-run artifact.** The backfill records
each masked finding to the local store as a side effect, so a second `/aka:setup`
over the _same_ history dedups those already-recorded findings to zero triage hits
and the showcase comes back empty (the adapter reports "no triage hits to
review"). That is expected, not a failure: a re-run recalibrates **only if there
is genuinely new history** since the last run. The **first run's** showcase is the
one that matters — it is not reconstructed from the store on a re-run (the raw
values it needs are deliberately never persisted). If a re-run shows nothing to
calibrate, take the floor branch as usual and tell the user the scan found no new
history.

1. **The per-category posture plan.** The action
   (`monitor`/`warn`/`redact`/`block`) the writeback would set for every
   category present in the evidence. Show it in full.
   - **Surface every downgrade — this is not optional.** The preview flags any
     category whose action would be **LOWERED** from a stronger existing setting
     (e.g. an existing `block`/`redact` dropping to `warn`/`monitor`) and prints
     a `WARNING` line summarizing them. Call these out prominently: a user who
     hardened a category must **explicitly approve weakening it**. Never let an
     enforcement downgrade through on the "apply as recommended" path without the
     user having seen it.
   - A category the adapter had to **skip** for its suppressions can still carry
     a posture change; it appears in this plan too, so the user sees any posture
     change even on a skipped category.
2. **The intelligence showcase.** The masked-only per-category reasoning and
   notes the judgment produced. Frame it as "look what it caught — and correctly
   dismissed": the false-positive discard is as much the pitch as the catch (a
   plain regex scanner would scream "161 CRITICAL secrets!"; AKA says "…all
   placeholders — `warn` is enough"). Keep the framing neutral — no "sloppy" or
   "bad practice".
3. **The false positives to be suppressed (the human gate).** The masked value,
   rule, and masked context for each detection the writeback would suppress.
   This is the checkpoint that stops a genuine secret being silenced: the user
   reads the masked evidence and approves it.

Then use **AskUserQuestion** (the real picker, never a printed numbered list) to
confirm:

**Apply this calibration?** — "Apply this detection posture and suppress the
false positives shown above?"

- **Yes, apply** _(recommended)_ — write the posture and suppressions exactly as
  previewed.
- **Let me adjust a category** — override one or more categories before saving
  (for example, keep a category the plan would lower).

If they choose to adjust, ask a follow-up **AskUserQuestion** per category,
offering the four actions with honest semantics so they choose with full
information: `monitor` logs only; `warn` flags the request and lets them decide;
`redact` strips the value from **tool I/O** but is a **no-op on the
prompt/conversation channel** (a secret pasted into chat still reaches the
model); `block` refuses the action outright. Collect the overrides as a
`{category: action}` map. Do **not** proceed to step 5 until the user has
explicitly confirmed.

## 5. Write the posture and suppressions

On confirmation, run the adapter again with `--confirmed --plan <path>`, passing
the **plan-file path the preview printed in step 3** (`Plan saved to: <path>`). It
reads that saved plan back and applies it **exactly as previewed** — it overwrites
the per-category posture and writes one 30-day suppression per confirmed false
positive **without re-running the backfill or the judge**. There is deliberately
**no `backfill.js` pipe here**: re-scanning and re-judging would produce a fresh,
non-deterministic plan and silently defeat the human gate the user just approved.

The posture overwrite and the suppression writes are applied as a **single
all-or-nothing transaction**: a mid-batch failure rolls back the posture change
too, so the store is never left half-applied. That is why the floor fallback below
is safe — a non-zero exit means **nothing** persisted, so re-applying the
conservative floor cannot collide with a partially-written posture.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/apply-suppressions.js" --confirmed --plan <path>
```

If `--plan` is missing or the file is unreadable/invalid, the adapter **fails loud
(non-zero) and writes nothing** — it never falls back to a re-judge. Treat that
like the `--confirmed` failure below: tell the user the write did not complete,
fall back to the floor, and continue to step 6.

If the user chose to **adjust** categories in step 4, apply their overrides on
top afterwards. `onboard.js --posture` overwrites only the categories in the map
it's given, leaving the rest as written by the adapter:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --posture '{"secret":"block"}'
```

(The JSON is illustrative — pass only the categories the user changed, values
one of `monitor`/`warn`/`redact`/`block`.) This is the only point in the wizard
where a posture is persisted.

If the `--confirmed` run exits non-zero, tell the user the write did not
complete, fall back to the floor (`onboard.js --floor`), and continue to step 6
so setup still finishes.

## 6. Show the first-run summary

Run the first-run script and show its output **exactly as printed** (the
install-complete summary with live findings/recommendation counts, the health
score, and — now — the per-category posture just written or floored). The
script already prints it inside a Markdown code fence; reproduce that
verbatim and do **not** add another code fence, strip the fence, or reformat it (it
is space-aligned monospace that Markdown would otherwise collapse).

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/firstrun.js"
```

## 7. Offer the AKA CLI + local dashboard (opt-in)

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

## 8. Report the result

- The first-run summary already confirms the saved posture and points at
  `/health`. Add at most one short sentence: detection runs locally and nothing
  leaves the machine.
