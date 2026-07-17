---
description: Set up the AKA Control Plane plugin — evidence-first detection posture and historical access
---

# AKA setup wizard

You are onboarding the AKA Control Plane plugin for this machine. AKA works
fully locally with **zero backend and zero Docker**: detection runs in-process
and findings persist to a local SQLite store at `~/.aka/data/aka.db`.

This wizard tells a **calibration story**: introduce AKA → show what it does →
offer one retroactive scan → report the real numbers it found and the posture it
recommends → apply on confirmation → show the installed summary → hand off to the
dashboard. Everything the user sees is derived from their _actual_ history — never
a fabricated or demo number. When there isn't enough history to judge, the wizard
falls back to a conservative severity-derived floor instead of guessing.

The false-positive/severity judgment itself runs in a **separate, transient
subprocess that writes no transcript** — the raw (unmasked) finding values are
never read into this conversation or your scannable history. You act only on the
raw-free plan that subprocess prints back.

Follow the steps below **in order**. Nothing is written to the policy store
until step 5 (or a floor fallback in step 3 if the calibration can't complete).

## 0. Show the kickoff and 'what I do' cards

Run the intro script and show the user its output **exactly as printed**. It
prints two space-aligned monospace cards — the kickoff card (name, repository,
version, what AKA adds) and the "what I do" card — each inside its own Markdown
code fence. Reproduce both fences verbatim and do **not** add another code fence,
strip a fence, or reformat them (unfenced, Markdown collapses the indentation and
mangles the `●` lines).

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/intro.js" "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json"
```

## 1. Offer the retroactive scan

Ask this **before** anything about detection posture — the posture
recommendation in step 4 is _derived from_ the answer to this question, so it
has to come first. Use the **AskUserQuestion** tool — Claude Code's built-in
interactive picker. The plugin can't draw its own selectable UI (it can't
capture keystrokes), so do **not** print a fake option list or ask the user to
"reply with a number"; let the picker collect the answer.

**Want me to look at what Claude's been up to?** — "A retroactive scan of recent activity — transcripts, temp files, agent memory — tunes the notifications we'll review next."

Offer exactly two options:

- **Yes, scan** — "calibrate my notifications to your real activity"
- **Not now** — "start light and learn as we go"

Choosing **Yes, scan** records the same historical-review consent the wizard has
always recorded — the identical scope, the one-time grant, and the
revocable-under-Policies semantics — so the simpler question broadens nothing
about what AKA may access. Those granular scope and revocation details stay
inspectable on request and in the dashboard.

## 2. Save the answer, then branch

Branch on the answer from step 1. On the **Yes, scan** path the onboarding
writer runs, and it must run **before** the backfill (step 3), because the
backfill script reads `historicalAccess` from the saved settings to decide
whether it's allowed to run. Omitting `--policy` is deliberate — the old global
redact/warn toggle no longer drives enforcement (posture is per-category now);
its field is kept for backward compatibility but this wizard doesn't ask about
it.

**Branch on the choice:**

- **If the user chose "Yes, scan"** — record the historical-review consent and
  continue to step 3 (which runs the scan and leads to the calibrated result in
  step 4). "Yes, scan" maps to the existing full historical-review path — no
  access is granted beyond what that path already granted:

  ```bash
  node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --historical full
  ```

- **If the user chose "Not now"** — the start-light path that learns as it goes
  is not built yet. Until it is, do **not** read any history and do **not** write
  a posture. End setup gracefully: tell the user nothing was scanned and nothing
  was changed, and that they can re-run `/aka:setup` anytime to calibrate or set
  a posture. Do **not** run `onboard.js`, the backfill, or any other script —
  steps 3–8 do not run.

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
the calibrated-result card (the real-count headline and the recommended posture),
the per-category reasoning, the masked false positives it would suppress, any
categories it skipped, and its notes.

The preview also **persists that exact raw-free plan to a temp file and prints
its path** — a line beginning `Plan saved to: <path>`. Capture that path: step 5
applies **this saved plan verbatim**, so the confirm step performs no second scan
and no second judgment. (The plan file carries only masked/fingerprint/enum data;
it is deleted after a successful apply.)

Alongside the human copy, the preview also emits a **machine-readable calibration
frame** — a single JSON block delimited by `<<<AKA_FRAME_JSON` … `AKA_FRAME_JSON>>>`
carrying the raw-free calibration counts and categories. Do **not** show this block
to the user (it is additive to the human copy above). Capture its `counts.important`
value — the **surfaced count** — and pass it to the first-run summary in step 6 as
`--surfaced <count>`. If the calibration could not complete (either fallback branch
below), no frame block is emitted and there is no surfaced count to carry over.

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

## 4. Show the calibrated result and get explicit confirmation — before any write

The preview output is raw-free. Lead with the **calibrated-result card** it
printed and show it in full:

1. **The calibrated headline.** The `Calibrated. N notifications, M important…`
   line — every count templated over the real scan (surfaced findings are the
   `M important` that matter; the rest are routine noise a plain scanner would
   have screamed about). Show it verbatim; never substitute a demo number.
2. **The recommended posture.** The condensed one-row-per-pack recommended view
   the card printed — the level AKA would set for each category. Show it in full.
   - **Surface every downgrade — this is not optional.** The preview flags any
     category whose action would be **LOWERED** from a stronger existing setting
     (e.g. an existing `block`/`redact` dropping to `warn`/`monitor`) and prints
     a `WARNING` line summarizing them. Call these out prominently: a user who
     hardened a category must **explicitly approve weakening it** before applying.
     Never let an enforcement downgrade through without the user having seen it.
3. **The false positives to be suppressed (the human gate).** The masked value,
   rule, and masked context for each detection the writeback would suppress —
   the routine noise being dismissed. This is the checkpoint that stops a genuine
   secret being silenced: the user reads the masked evidence and approves it.

Then use **AskUserQuestion** (the real picker, never a printed numbered list) to
confirm:

**Apply this calibration?** — "Apply this detection posture and suppress the
false positives shown above?"

- **Yes, apply** _(recommended)_ — write the posture and suppressions exactly as
  previewed.

Offer **only** the "Yes, apply" option for now. An "Adjust a category" option —
an override loop over the recommended posture — arrives in a follow-up; until
then a user who wants a different posture re-runs `/aka:setup` or edits it in the
dashboard. Do **not** proceed to step 5 until the user has explicitly confirmed.

## 5. Write the posture and suppressions

On confirmation, run the adapter again with `--confirmed --plan <path>`, passing
the **plan-file path the preview printed in step 3** (`Plan saved to: <path>`). It
reads that saved plan back and applies it **exactly as previewed** — establishing
the **full 8-pack posture** the recommended view showed (the reviewed
evidence packs overwrite; the conservative severity floor fill-gaps the remaining
packs, so a pack the user had already hardened out of band is never downgraded) and
writing one 30-day suppression per confirmed false positive **without re-running the
backfill or the judge**. There is deliberately **no `backfill.js` pipe here**:
re-scanning and re-judging would produce a fresh, non-deterministic plan and
silently defeat the human gate the user just approved.

The posture overwrite and the suppression writes are applied as a **single
all-or-nothing transaction**: a mid-batch failure rolls back the posture change
too, so the store is never left half-applied. That is why the floor fallback below
is safe — a non-zero exit means **nothing** persisted, so re-applying the
conservative floor cannot collide with a partially-written posture.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/apply-suppressions.js" --confirmed --plan <path>
```

The script prints the applying confirmation — `✓ K categories tuned ·
✓ N routine dismissed · Ready: …` — with both counts threaded from the real write.
Show that line to the user.

If `--plan` is missing or the file is unreadable/invalid, the adapter **fails loud
(non-zero) and writes nothing** — it never falls back to a re-judge. Treat that
like the `--confirmed` failure below: tell the user the write did not complete,
fall back to the floor, and continue to step 6.

If the `--confirmed` run exits non-zero, tell the user the write did not
complete, fall back to the floor (`onboard.js --floor`), and continue to step 6
so setup still finishes.

## 6. Show the installed summary and hand off to the dashboard

Run the first-run script and show its **install-complete summary** exactly as
printed (live findings/recommendation counts, the health score, and the
per-category posture just written or floored). The script prints that summary
inside a Markdown code fence; reproduce the fenced card verbatim and do **not**
add another code fence, strip the fence, or reformat it (it is space-aligned
monospace that Markdown would otherwise collapse).

Pass the **surfaced count** captured from step 3's calibration frame
(`counts.important`) as `--surfaced <count>` — this is the 'N worth a look' figure
the script emits in its own machine-readable handoff payload. If the
calibration fell back to the floor (no frame was emitted in step 3), **omit
`--surfaced` entirely** — the script then withholds that payload rather than
fabricating a count.

When `--surfaced` is passed, the script appends that handoff payload as a single
JSON block delimited by `<<<AKA_FRAME_JSON` … `AKA_FRAME_JSON>>>` after the fenced
card. Like step 3's calibration frame, do **not** show this block to the user — it
is additive and machine-only; only the fenced install summary above is
user-facing.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/firstrun.js" --surfaced <count>
```

**Then hand off to the dashboard.** When the payload carries a positive
`worthALook` count, issue an explicit **AskUserQuestion** (the real picker, never a
printed list) using that count for `N`:

**N worth a look — see them in the browser?**

- **Open dashboard** — open the local web dashboard on the surfaced findings.
- **Not now** — stay here; they can open it anytime.

Use the payload's `worthALook` value for `N` verbatim — do not invent or round it.
If the payload was withheld (the floor fallback, or nothing surfaced), skip this
handoff question rather than inventing a count.

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
