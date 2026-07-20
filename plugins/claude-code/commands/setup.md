---
description: Set up AKA Security — calibrate notifications and detection posture from Claude's real activity.
---

# AKA setup wizard

You are onboarding the AKA Security plugin for this machine. AKA works
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

- **If the user chose "Not now"** — take the **start-light** path.
  This path takes **zero historical access**: do **not** read any history, do
  **not** run the backfill, and do **not** record consent — nothing about the
  machine's past is touched.
  Instead present the start-light posture card, write the posture the user picks
  (this write **is** the applying frame — it stands in for step 5, which never
  runs here because there is no scan plan to apply), and rejoin the spine at the
  installed summary (step 6). **Skip steps 3, 4, and 5 entirely** — there is no
  scan to triage, no calibrated result to confirm, and no suppression plan to
  write. Do the following in order:

  1. **Show the start-light card.** Run the start-light script and reproduce its
     fenced card **exactly as printed** — the `Start light — set your packs`
     heading, the full 8-pack × 4-level default posture table, the per-pack rationale, and the
     re-tune hint. It reads no history and writes nothing; it only prints the card
     (the severity-floor default map — secret, pii, financial, phi, code_flaw, custom at
     `warn`; code_context, config at `monitor`).

     ```bash
     node "${CLAUDE_PLUGIN_ROOT}/scripts/start-light.js"
     ```

  2. **Confirm or adjust.** Use **AskUserQuestion** — Claude Code's built-in
     picker — to let the user keep the recommended defaults or tune individual
     packs. The plugin can't draw its own selectable UI, so do **not** print a
     fake option list or ask the user to "reply with a number"; let the picker
     collect the answer.

     **Set your packs** — "Keep the recommended defaults, or adjust individual packs?"

     - **Keep defaults** _(recommended)_ — "the conservative default posture shown above"
     - **Adjust packs** — "change one or more pack levels; keep the rest as recommended"

     If they choose **Adjust packs**, use AskUserQuestion again to collect the new
     level (monitor/warn/redact/block) for each pack they want to change, then
     merge those overrides over the severity-floor defaults to form the full 8-pack map.

  3. **Write the chosen posture.** The default map is the severity floor,
     so when the user keeps the defaults, write the floor directly; when they
     adjusted packs, write the merged 8-pack map:

     ```bash
     # Kept the recommended defaults
     node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --floor

     # Adjusted one or more packs — <json> is the merged 8-pack map
     node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --posture '<json>'
     ```

     Either write prints only `✓ K categories tuned` (the `--floor` write appends
     ` (severity floor)`) — which is the honest confirmation here, because nothing
     was scanned or suppressed. Show that line to the user; do **not** invent a
     dismissed count or any calibration counts.

  4. **Rejoin the spine at the installed summary (step 6).** Continue to step 6
     to show the installed summary and hand off to the dashboard, using honest
     no-scan copy. No scan ran, so there is **no surfaced count** — call
     `firstrun.js` with **no `--surfaced` flag** (the same floor-fallback rule
     step 6 already follows when no calibration frame was emitted). Steps 7–8
     then run as written.

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
`--surfaced <count>` — but **only when the preview also printed a `Plan saved to:`
path** (a real calibrated plan to confirm in step 4). The `Plan saved to:` line is
the completion signal: a preview that omits it did not calibrate a plan you can
confirm. The fallback branches below carry no surfaced count; the scan-ran-clean
empty state (a scan that completed but surfaced nothing) emits a zero-count frame
but **no plan path**, so it too routes to the floor branch below rather than step 4.

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

**Nothing to calibrate.** A scan that **completes but surfaces nothing** prints
the honest **scan-ran-clean** card — `Calibrated. I looked at Claude's recent
activity — nothing needs your attention…` over the recommended posture — with a
zero-count calibration frame (its `counts.important` is `0`) and **no `Plan saved
to:` path**. An empty or intentionally-skipped scan instead prints `No triage hits
to review …`. In either case there's no evidence to calibrate from and no plan to
confirm: show the card the adapter printed, take the floor branch
(`onboard.js --floor`), tell the user the scan found nothing to calibrate from, and
skip to step 6 (with **no `--surfaced`**, the floor-fallback rule there — nothing
was surfaced to carry over). Do **not** continue to step 4.

Otherwise (the preview printed a `Plan saved to:` path) continue to step 4.

## 4. Show the calibrated result and get explicit confirmation — before any write

The preview output is raw-free. Lead with the **calibrated-result card** it
printed and show it in full:

1. **The calibrated headline.** The `Calibrated. N notifications, M important…`
   line — every count templated over the real scan (surfaced findings are the
   `M important` that matter; the rest are routine noise a plain scanner would
   have screamed about). Show it verbatim; never substitute a demo number.
2. **The recommended posture.** The condensed one-row-per-pack recommended view
   the card printed — the level AKA would set for each category. Show it in full.
   - **Surface the downgrades the preview flags — this is not optional.** For the
     recommended posture it is about to write, the preview compares each category
     against its stored setting and flags any that would be **LOWERED** from a
     stronger existing one (e.g. an existing `block`/`redact` dropping to
     `warn`/`monitor`), printing a `WARNING` line summarizing them. Call these out
     prominently: a user who hardened a category must **explicitly approve weakening
     it** before applying.
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
- **Adjust a category** — "change one or more pack levels first; keep the rest as
  recommended"

Do **not** proceed until the user picks one. On **Yes, apply**, continue to
step 5 and apply the previewed plan verbatim — that is the confirm spine,
unchanged. On **Adjust a category**, take the **adjust fork** (step 4b), which
applies within the fork and rejoins the spine at the installed summary (step 6).

## 4b. Adjust a category — the override fork

The **adjust base is the calibrated recommended posture the preview just
printed** — the condensed one-row-per-pack view from step 4, not the cold-start
severity floor. The user changes the packs they want and keeps the rest as
recommended.

1. **Collect the changes.** Use **AskUserQuestion** — the built-in picker — to
   ask which packs to change and to which level (monitor/warn/redact/block). The
   plugin can't draw its own selectable UI, so do **not** print a fake option list
   or ask the user to "reply with a number"; let the picker collect the answer.

2. **Show the adjust-confirm table.** Compose the merged 8-pack map — the
   recommended base with the user's picks overlaid — and render the adjust-confirm
   card by passing the calibrated recommended posture as `--recommended` and that
   merged map as `--posture`. Reproduce its
   fenced `category │ recommended │ yours` table **exactly as printed** (it is
   space-aligned monospace; do **not** add another code fence, strip the fence, or
   reformat it):

   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/start-light.js" --adjust-confirm --recommended '<recommended-json>' --posture '<merged-json>' --current '<current-json>'
   ```

   `<recommended-json>` is the calibrated recommended posture the preview printed
   (the adjust base) — so the `recommended` column shows each pack's calibrated
   level, and a pack calibration escalated above the floor never renders as a
   spurious change. `<merged-json>` is the full 8-pack map — that same recommended
   base with the user's overrides overlaid — so a changed pack reads as a different
   `yours` value and every untouched pack repeats its recommended level.
   `<current-json>` is the `current` object from the plan file at the path step 3
   printed (`Plan saved to: <path>`) — the store's per-category action at preview
   time, the baseline the downgrade check compares against. Pass it verbatim; do
   not retype or summarize it.

3. **Surface any downgrade — the card computes this, you do not.** With
   `--current` passed, the card itself appends the `WARNING: N categories … would
be LOWERED from a stronger existing setting` footer whenever a pick weakens
   enforcement — the same rule and the same wording as the confirm gate above,
   from the same code. Show the card in full, footer included, and when that
   footer is present get explicit approval before saving. Never let an enforcement
   downgrade through without the user having seen it.

4. **Save or back out.** Use **AskUserQuestion** with **N** the number of packs
   the user changed and **M** the number kept as recommended (`M = 8 − N`), both
   real — never a placeholder:

   **Save your adjustments?**

   - **Save adjusted — N changed, M as recommended** — apply with the adjusted
     posture.
   - **Back to recommended** — discard the changes and apply the recommended
     posture instead.

5. **On "Save adjusted" — produce the applying frame here, carrying the adjusted
   posture, then rejoin the spine at the installed summary (step 6).** This fork
   applies within itself and **stands in for step 5**, so step 5 never runs on
   this path. First apply the previewed plan with the **unchanged confirm spine**,
   so the reviewed false positives are dismissed and the recommended base is
   written (the reviewed evidence packs overwrite; the severity floor fill-gaps the
   rest, so a pack hardened out of band is never downgraded):

   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/apply-suppressions.js" --confirmed --plan <path>
   ```

   If that `--confirmed` run exits non-zero (or `--plan` is missing/unreadable),
   handle it exactly as step 5 does: tell the user the write did not complete, fall
   back to the floor (`onboard.js --floor`), and continue to step 6. Do **not** run
   the overlay below on a failed spine — nothing was written, so there is no
   recommended base to overlay the changes onto.

   Then overwrite **only the packs the user changed** with their chosen levels:

   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --posture '<changed-packs-json>'
   ```

   `<changed-packs-json>` carries **only** the packs the user adjusted (not the
   full 8-pack map), so the packs kept as recommended keep the fill-gaps-safe
   values the spine wrote and only the user's explicit, downgrade-approved changes
   overwrite.

   If that overlay exits non-zero, the spine already wrote the recommended base, so
   the store holds a valid posture — but **not** the user's overrides. Tell the user
   their adjustments did not save and the store holds the recommended posture, then
   continue to step 6. Do **not** report the adjusted posture as saved on a failed
   overlay.

   On success, present the applying-frame confirmation the **spine** printed —
   `✓ 8 categories tuned · ✓ N routine dismissed · Ready: …` — the store now holds
   the adjusted posture. The overlay's own smaller `✓ N categories tuned` line
   (the count of just the changed packs) is bookkeeping — **do not show it**; the
   applying frame reports the full 8-pack posture. Then continue to step 6.

   **On "Back to recommended"** — take the **Yes, apply** path instead: continue
   to step 5 and apply the previewed plan verbatim with no override.

Do **not** write anything until the user has explicitly confirmed at step 4
(Yes, apply) or saved at step 4b (Save adjusted).

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
the script emits in its own machine-readable handoff payload — but only when step 3
carried a surfaced count forward (it printed a `Plan saved to:` path). If the
calibration fell back to the floor (no plan path in step 3 — a fallback branch, or
the scan-ran-clean empty state whose zero-count frame carries nothing to look at),
**omit `--surfaced` entirely** — the script then withholds that payload rather than
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
