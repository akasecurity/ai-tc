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

## Execution contract (read before step 0)

Every script prints output in three region kinds. Your job for each is fixed:

- **`<<<AKA_SHOW … AKA_SHOW>>>`** — relay every AKA_SHOW region verbatim as your
  next message: paste the content _between_ the markers exactly — a card region
  carries its own code fence, a plain confirmation line does not, but either way
  you paste exactly what's between the markers — never the marker lines, never a
  paraphrase or summary.
- **`<<<AKA_FRAME_JSON … AKA_FRAME_JSON>>>`** — machine-only. Parse it if a step
  tells you to read a value from it; never display it.
- **Anything else on stdout** — status for you (paths like `Plan saved to:`,
  errors, exit signals). Act on it; never relay it.

Invariants:

- **Never write a confirmation or acknowledgement the wizard did not emit** — the
  script's AKA_SHOW line is the confirmation.
- **Each step's AKA_SHOW regions must be relayed before you advance.**
- **One picker per decision; never re-ask a decision already collected.**

## 0. Show the intro card

Run the intro script and relay its AKA_SHOW region per the execution contract:
paste the content between the markers verbatim, never the marker lines. It
prints a single space-aligned monospace card — identity and provenance, then
what AKA does — inside a Markdown code fence that is part of that pasted
content. Keep the fence as printed and do **not** add another code fence, strip
the fence, or reformat it (unfenced, Markdown collapses the indentation and
mangles the `●` lines).

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/intro.js" "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json"
```

## 0b. Repo-aware posture check — tighten-only, working-tree only

Before showing any recommended posture — the start-light default table in
step 2 or the calibrated posture in step 4 — look at the **current project's**
working tree yourself, with your own Read/Glob tools. There is no script for
this: it is your own reasoning over facts you read directly, not the isolated
triage subprocess's raw-free plan, and it needs no user interaction.

**In scope:** the manifest's declared frameworks/dependencies
(`package.json` or equivalent), payment or other third-party API SDKs among
them, CI config (`.github/workflows/`, etc.), and the **presence and names**
of `.env*`/config files as a signal that secrets live on disk here — never
their contents; a secret-bearing file's contents are exactly the kind of raw
value this wizard never reads. **Out of scope:** Claude's own history and the
local AKA store (that is the separate, consent-gated scan in steps 1/3) — no
historical read, and no AskUserQuestion or other consent interaction of any
kind.

The severity-floor default map (secret/pii/financial/phi/code_flaw/custom at
`warn`, code_context/config at `monitor` — the table step 2's start-light card
prints) is both the **floor** this check is measured against and its
**fallback**. From what you directly observe you may **tighten** individual
categories above that floor — raise the level, never lower one below it —
each tightened category carrying a one-line rationale naming the concrete
evidence you found, e.g.:

> Stripe + a `Customer` model here — financial → redact

Present the tightening on whichever recommended posture is about to render, the
same "recommended base + changed-packs overlay" shape step 4b's adjust fork
uses: the tightened categories raise, every other category keeps its existing
recommended level, each carrying its rationale line. Where you compose the view
yourself (the adjust fork, the calibrated result) this tightened recommendation
IS that view; where the view is a script's AKA_SHOW card (the step-2
start-light card, relayed per the execution contract), show the tightened
recommendation and its rationale lines adjacent to that card rather than
rewriting the card's own printed levels.

This tightening is a **display-time recommendation**: it shapes the recommended
posture the user reads, not a separate write. Persisting a tightened level happens
only where the wizard already writes a per-category override — the adjust fork's
`onboard.js --posture` write (step 4b), where the user picks each category's level
explicitly. The keep-defaults path writes the severity floor (`--floor`, step 2)
and the calibrated accept path applies the isolated subprocess's saved plan
verbatim (`--confirmed --plan`, step 5); neither carries the tightening on its
own, so a tightened level the user wants persisted is chosen through the adjust
fork. Do **not** bolt on an extra `onboard.js --posture` overlay to auto-re-persist
the tightening across the other paths: it would overwrite — and so could silently
**downgrade** — a category the user had hardened out of band (a tightening is only
guaranteed to raise above the severity floor, not above the user's stored level),
with no downgrade-approval gate. So the tightening is not auto-persisted across
those paths — a tightened level the user wants kept is set through the adjust fork.

**When nothing in the working tree is inferable, change nothing.** Render the
recommended posture exactly as the static frame already gives it — no rationale
line and no tightened category (fail-open).

## 1. Offer the retroactive scan

Ask this **before** anything about detection posture — the posture
recommendation in step 4 is _derived from_ the answer to this question, so it
has to come first. Use the **AskUserQuestion** tool — Claude Code's built-in
interactive picker. The plugin can't draw its own selectable UI (it can't
capture keystrokes), so do **not** print a fake option list or ask the user to
"reply with a number"; let the picker collect the answer.

**Want me to look over what Claude's been up to?** — "I'll review Claude's recent work — transcripts, temp files, agent memory — to tune what I bring to you next."

Offer exactly two options:

- **Yes, take a look** — "tune what I bring you, based on Claude's real work here"
- **Not now** — "start light and I'll learn as we go"

Choosing **Yes, take a look** records the same historical-review consent the wizard has
always recorded — the identical scope, the one-time grant, and the
revocable-under-Policies semantics — so the simpler question broadens nothing
about what AKA may access. Those granular scope and revocation details stay
inspectable on request and in the dashboard.

## 2. Save the answer, then branch

Branch on the answer from step 1. On the **Yes, take a look** path the onboarding
writer runs, and it must run **before** the backfill (step 3), because the
backfill script reads `historicalAccess` from the saved settings to decide
whether it's allowed to run. Omitting `--policy` is deliberate — the old global
redact/warn toggle no longer drives enforcement (posture is per-category now);
its field is kept for backward compatibility but this wizard doesn't ask about
it.

**Branch on the choice:**

- **If the user chose "Yes, take a look"** — record the historical-review consent and
  continue to step 3 (which runs the scan and leads to the calibrated result in
  step 4). "Yes, take a look" maps to the existing full historical-review path — no
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

  1. **Show the start-light card.** Run the start-light script and relay its
     AKA_SHOW card per the execution contract — the
     `● Starting light — your detection categories` heading, the full 8-pack ×
     4-level default posture table, the per-pack rationale, and the re-tune
     hint, pasted between the markers exactly as printed, fence included. It
     reads no history and writes nothing; it only prints the card
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

     **Set your detection categories** — "Keep the defaults I'd recommend, or adjust any of them?"

     - **Keep defaults** _(recommended)_ — "the careful defaults shown above"
     - **Adjust** — "change one or more levels, keep the rest as I recommend"

     If they choose **Adjust**, use AskUserQuestion again to collect the new
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

     Either write prints only `✓ Set all K detection categories` (the `--floor`
     write appends ` — safe defaults`) — which is the honest confirmation here,
     because nothing was scanned or suppressed. Show that line to the user; do
     **not** invent a dismissed count or any calibration counts.

  4. **Rejoin the spine at the installed summary (step 6).** Continue to step 6
     to show the installed summary and hand off to the dashboard, using honest
     no-scan copy. No scan ran, so there is **no surfaced count** — call
     `firstrun.js` with **no `--surfaced` flag** (the same floor-fallback rule
     step 6 already follows when no calibration frame was emitted). Step 7
     then runs as written.

## 3. Run the evidence triage — isolated judgment, nothing written yet

**Model-judge consent — a distinct opt-in, asked here before the pipe.** The
false-positive/severity judgment runs by sending each finding to the Anthropic
model API through `claude`. That is a separate egress from the historical-read
consent collected in step 1 (which only let AKA _read_ the local transcripts), so
it needs its own explicit grant. Before running the pipe, state plainly what
leaves the machine, then use **AskUserQuestion** — the built-in picker (never a
printed numbered list) — to collect the answer.

Say plainly, before the picker: to sort real leaks from routine noise, AKA sends
each finding's `rawMatch` (the raw detected value) plus a **masked** surrounding
context window to the model API via `claude`. The **`filePath` is not sent** and
the context window is **masked** — this is the minimized payload; nothing else
about the finding or the file leaves the machine.

**Send findings to the model to sort real leaks from noise?** — "I'll send each
detected value and a masked bit of surrounding context to the model to tell real
leaks from routine noise. The file path stays local."

- **Yes, send them** _(recommended)_ — "let the model triage what I found"
- **Not now** — "skip the model triage and start from the safe defaults"

**Branch on the choice:**

- **If the user chose "Yes, send them"** — record the model-judge consent, then
  run the pipe below:

  ```bash
  node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --model-judge-consent
  ```

- **If the user chose "Not now"** — do **not** run the pipe. The judge refuses
  to run without consent (it would only print a clean skip line), so there is no
  calibrated plan to confirm. Fall back to the conservative severity floor, tell
  the user the model triage was skipped, and continue to step 6:

  ```bash
  node "${CLAUDE_PLUGIN_ROOT}/scripts/onboard.js" --floor
  ```

  Say plainly: the model triage was declined, so AKA is starting from the
  conservative severity floor instead of a calibrated posture, and it can be
  re-run any time with `/aka:setup`. **Skip steps 4 and 5** — there is no plan to
  confirm — and rejoin the spine at step 6 with **no `--surfaced`** (the same
  floor-fallback rule step 6 already follows).

On the **Yes, send them** path, pipe the backfill's triage stream straight into
the `apply-suppressions` adapter in **PREVIEW** mode (no `--confirmed`):

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
carrying the raw-free calibration counts and categories, plus (when the scan
surfaced any) a `maskedFindings` array of raw-free secret-leak summaries. Do
**not** show this block to the user (it is additive to the human copy above).
Capture its `counts.important` value — the **surfaced count** — and pass it to the
first-run summary in step 6 as `--surfaced <count>` — but **only when the preview
also printed a `Plan saved to:` path** (a real calibrated plan to confirm in step
4). The `Plan saved to:` line is the completion signal: a preview that omits it did
not calibrate a plan you can confirm. The fallback branches below carry no
surfaced count; the scan-ran-clean empty state (a scan that completed but
surfaced nothing) emits a zero-count frame but **no plan path**, so it too routes
to the floor branch below rather than step 4.

Also **retain the block's full text verbatim** (not just the counts you read out
of it) — step 6's "Review leaked keys" branch feeds this same text to the
secret-leak remediation entry, which reads its own `maskedFindings` from it,
and step 4's finding narration and step 6's secret-leak narration (both below)
read the same `maskedFindings` array off it too. When present, the block's
`falsePositivePatterns` array is what step 4's fixture/exception offer (below)
names its pattern and count from — never invent either off-signal.

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
the honest **scan-ran-clean** card — `I looked over Claude's recent work —
nothing needs your attention right now. You're starting clean; here's what I'd
recommend:` over the recommended posture — with a zero-count calibration frame
(its `counts.important` is `0`) and **no `Plan saved to:` path**. An empty or
intentionally-skipped scan instead prints `I didn't find anything to review —
nothing to tune.`. In either case there's no evidence to calibrate from and no
plan to confirm: show the card the adapter printed, take the floor branch
(`onboard.js --floor`), tell the user the scan found nothing to calibrate from, and
skip to step 6 (with **no `--surfaced`**, the floor-fallback rule there — nothing
was surfaced to carry over). Do **not** continue to step 4.

Otherwise (the preview printed a `Plan saved to:` path) continue to step 4.

## 4. Show the calibrated result and get explicit confirmation — before any write

The preview output is raw-free. Lead with the **calibrated-result card** it
printed and show it in full:

1. **The calibrated headline.** The `I went through Claude's recent work — N
detections, M results worth a look.` line — every count templated over the
   real scan (surfaced findings are the `M results` worth a look; the rest are
   routine noise a plain scanner would have screamed about). Show it verbatim;
   never substitute a demo number.
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
4. **Explain what surfaced, in plain language.** When the frame carries
   `maskedFindings`, walk through them — what each one is, where it showed up,
   and why it matters — grounded entirely in that array: every count you speak
   equals the frame's own count for it (`counts.important`/`counts.total`, or
   a specific finding kind's count), and every value you reference appears
   masked, exactly as the frame gives it — never a raw value, never an
   invented one. This is an actual explanation of the known findings, not a
   restatement of the headline's counts. When the frame carries no
   `maskedFindings` (nothing surfaced, or a fallback floor ran), skip this —
   the calibrated-result card already said so; do not invent narration over a
   missing signal.
5. **Offer an exception for a grounded false-positive pattern.** When the
   frame carries `falsePositivePatterns`, name each group's pattern and count
   **strictly from that signal** — never invent a pattern name or fabricate a
   count. For each group, use **AskUserQuestion** to offer a pre-filled
   exception with a duration picker (the exception scope axis — `once` /
   `temporary` / `permanent`):

   **Make an exception for `<pattern>` (×N)?** — "This `<pattern>` looks like a
   test fixture — want me to set an exception so it stops popping up?"

   - **Once** — just this once — expires in 30 minutes
   - **Temporary** — for a set window, then I'll check it again
   - **Permanent** — stays until you revoke it
   - **Not now** — skip — I won't write anything

   **Temporary needs a concrete window.** `once` and `permanent` fully determine
   the scope on their own, but `temporary` does not — resolving it into the
   stored `{scope, expiresAt, maxUses}` triple requires an actual duration, and
   you must **never** invent or default one. When the user picks **Temporary**,
   follow up with a second **AskUserQuestion** that offers concrete windows only
   — `30m` / `1h` / `24h` (the exception scope resolver accepts `<n>m`/`<n>h`,
   capped at 24h; a longer bypass is a `permanent` grant, not a forgotten timer)
   — and resolve the exact chosen string through that resolver. **Once** and
   **Permanent** take no follow-up.

   Accepting surfaces the exact pre-filled exception — one **per distinct value
   identity** (`ruleId`/`valueFingerprint`/`keyVersion`) at the chosen
   `{scope, expiresAt, maxUses}` — for review, and the marked pattern is
   suppressed as part of the calibration plan confirmed below (the same store
   `/aka:exceptions` reads). A group whose displayed pattern covers more than one
   distinct value surfaces one exception per distinct value — never a single
   grant collapsing them — and a value missing its exact identity is not
   offered for. Declining surfaces nothing; this offer is separate from the
   calibration plan's suppressions confirmed below, so declining here changes
   nothing about that confirmation. When the frame carries no
   `falsePositivePatterns` (nothing was marked a likely false positive, or the
   scan was declined), skip this entirely — no offer, nothing invented
   (fail-open).

Then use **AskUserQuestion** (the real picker, never a printed numbered list) to
confirm:

**Want me to apply this?** — "I'll set these levels and suppress the false
positives above."

- **Yes, apply** _(recommended)_ — write the posture and suppressions exactly as
  previewed.
- **Adjust a category** — "change one or more first; keep the rest as I
  recommend"

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
   merged map as `--posture`. Relay its AKA_SHOW region per the execution
   contract — the fenced `category │ recommended │ yours` table, pasted between
   the markers exactly as printed (it is space-aligned monospace; do **not** add
   another code fence, strip the fence, or reformat it):

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
   `✓ Set all 8 detection categories · set aside N routine results · Ready: …` —
   the store now holds the adjusted posture. The overlay's own smaller
   `✓ Set all N detection categories` line (the count of just the changed packs)
   is bookkeeping — **do not show it**; the applying frame reports the full
   8-pack posture. Then continue to step 6.

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

The script prints the applying confirmation — `✓ Set all K detection categories
· set aside N routine results · Ready: …` — with both counts threaded from the
real write. Show that line to the user.

If `--plan` is missing or the file is unreadable/invalid, the adapter **fails loud
(non-zero) and writes nothing** — it never falls back to a re-judge. Treat that
like the `--confirmed` failure below: tell the user the write did not complete,
fall back to the floor, and continue to step 6.

If the `--confirmed` run exits non-zero, tell the user the write did not
complete, fall back to the floor (`onboard.js --floor`), and continue to step 6
so setup still finishes.

## 6. Show the installed summary and hand off to the dashboard

Run the first-run script and relay its **install-complete summary** AKA_SHOW
region per the execution contract (live findings/recommendation counts, the
health score, and the per-category posture just written or floored). The
script wraps that summary in a Markdown code fence; paste it between the
markers exactly as printed and do **not** add another code fence, strip the
fence, or reformat it (it is space-aligned monospace that Markdown would
otherwise collapse).

Pass the **surfaced count** captured from step 3's calibration frame
(`counts.important`) as `--surfaced <count>` — this is the 'N worth a look' figure
the script emits in its own machine-readable handoff payload — but only when step 3
carried a surfaced count forward (it printed a `Plan saved to:` path). If the
calibration fell back to the floor (no plan path in step 3 — a fallback branch, or
the scan-ran-clean empty state whose zero-count frame carries nothing to look at),
**omit `--surfaced` entirely** — the script then withholds that payload rather than
fabricating a count.

Alongside it, pass the **surfaced live-key count** — the number of surfaced
live-key secret findings, which is the length of the calibration frame's
`maskedFindings` array (absent ⇒ 0) — as `--live-keys <count>`. This is the
narrower secret subset of the surfaced count; it gates the remediation
chain-entry the handoff offers, so a calibration that surfaced only non-secret
findings passes `--live-keys 0` and offers no remediation.

When `--surfaced` is passed, the script appends that handoff payload as a single
JSON block delimited by `<<<AKA_FRAME_JSON` … `AKA_FRAME_JSON>>>` after the fenced
card. Like step 3's calibration frame, do **not** show this block to the user — it
is additive and machine-only; only the fenced install summary above is
user-facing.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/firstrun.js" --surfaced <count> --live-keys <count>
```

**Then hand off to the dashboard.** When the payload carries a positive
`worthALook` count, issue an explicit **AskUserQuestion** (the real picker, never a
printed list) using that count for `N`:

**N worth a look — want to see them in the browser?**

- **Review leaked keys** — "let's deal with the exposed keys I found" —
  _(offer this option first only when the payload's `options` include
  `enter-remediation`, i.e. `liveKeys > 0`)_; entering it starts the
  secret-leak remediation chain on the surfaced live keys. This composes with —
  never replaces — the dashboard handoff below, so both stay reachable.
- **Open dashboard** — "open the local dashboard on what I found"
- **Not now** — "stay here — you can open it anytime"

Use the payload's `worthALook` value for `N` verbatim — do not invent or round it.
Offer **Review leaked keys** exactly when the payload's `options` carry the
`enter-remediation` entry (never otherwise); the **Open dashboard** / **Not now**
handoff is always present. If the payload was withheld (the floor fallback, or
nothing surfaced), skip this handoff question rather than inventing a count.

**If they choose "Review leaked keys"** — run the secret-leak remediation entry's
**present** mode, feeding it the calibration frame block you captured in step 3
(the same text `maskedFindings` came from) on stdin:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/remediate.js" <<'AKA_FRAME'
<the <<<AKA_FRAME_JSON … AKA_FRAME_JSON>>> block captured in step 3, verbatim>
AKA_FRAME
```

It prints the decision as human-facing text, then a machine-readable block
delimited by `<<<AKA_FRAME_JSON` … `AKA_FRAME_JSON>>>` carrying the same decision
structured (do **not** show that block to the user). The human text has three
parts, all of which you **show to the user verbatim, in order**:

1. the templated count line ("I found N exposed secret keys sitting in old
   transcripts."),
2. the fenced finding table (provider, masked token, where, state), and
3. inside that same fence, a most-exposed-first recommendation line and a
   secret-scan chaining line.

This entire human-text block is the entry's AKA_SHOW region — relay it per the
execution contract, pasting it between the markers exactly as printed — do not
drop the recommendation or chaining lines, and do not paraphrase.

Alongside that fenced block, explain the findings in plain language grounded
in the same `maskedFindings` array the block came from — what each finding is
and why it matters, not a bare recital of the count line above it. The same
grounding discipline as step 4's narration applies here: every count you
speak matches the frame's own count, and every value you reference stays
masked. With no `maskedFindings` present there is nothing to narrate beyond
the count line and table already shown — do not invent an explanation.

Then issue an
**AskUserQuestion** offering exactly these four options, in order (each option's
label maps to the `--option` id shown in parentheses):

- **Redact + rotation checklist** (`redact-rotation-checklist`)
- **Redact only** (`redact-only`)
- **Set 'secret' to redact** (`set-secret-redact`)
- **Leave** (`leave`)

**If they chose "Redact + rotation checklist" or "Redact only"** — before running
the route, issue a second **AskUserQuestion** presenting the standing-posture
prompt, offering exactly these four options, in order (each option's label maps
to the `--posture` level in parentheses):

**Set the 'secret' detection level**

- **Redact** (`redact`)
- **Warn** (`warn`)
- **Block** (`block`)
- **Monitor** (`monitor`)

Then run the entry's **route** mode ONCE with the chosen redact option's id AND
the chosen posture level, feeding it the SAME calibration frame block again on
stdin:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/remediate.js" --option <id> --posture <level> <<'AKA_FRAME'
<the same block>
AKA_FRAME
```

Never run the route a second time for this choice — a repeat call would strike
the already-redacted keys again and corrupt the reported count. Show its printed
result verbatim, in order. For "Redact only" that is the redaction confirmation
then the standing-posture confirmation. For "Redact + rotation checklist" it is
the standing-posture confirmation then the resolved rotation-checklist summary —
which reports the redaction itself, so the script does not print a separate
redaction confirmation ahead of it.

**If they chose "Set 'secret' to redact" or "Leave"** — run the entry's **route**
mode with the chosen option's id (the id in parentheses above, e.g. **Leave** →
`leave`), feeding it the SAME calibration frame block again on stdin:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/remediate.js" --option <id> <<'AKA_FRAME'
<the same block>
AKA_FRAME
```

Show its printed result verbatim — a standing-posture confirmation, or (choosing
"Leave") a plain note that nothing changed. This entry reads its findings from the
calibration frame alone and holds no wizard state of its own, so it works
identically from any caller.

## 7. Offer the AKA CLI + local dashboard (opt-in)

Now that the plugin is set up, offer the optional **AKA CLI + local dashboard** —
a richer, still-fully-local surface over the same `~/.aka` store this plugin
writes. The plugin works completely on its own; this is additive (and the path to
future multi-agent support). Use **AskUserQuestion**:

**Want the AKA CLI + dashboard too?** — "The `aka` CLI adds a local user
interface + terminal dashboard and on-demand scans."

- **Yes, add it** _(recommended)_ — "adds the `aka` command: stats, a terminal
  dashboard, a local user interface, and on-demand scans"
- **Not now** — "skip — you can add it anytime with the one-liner below"

**Yes, add it** is the install authorization — run the bootstrap installer
directly, with no second picker (it downloads the self-contained `aka` binary for
their platform — no Node.js or npm required — and links it onto PATH). Run the
line for their OS:

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.ps1 | iex
```

The one-liner pins to the latest published binary release **tag** (`bin-latest`),
never `main` — each binary release (`bin-v*`) moves that tag to its commit, and
the installer verifies the downloaded binary against the release's `SHA256SUMS`
(fail-closed), so a corrupted or tampered download is refused. To pin an exact
version instead, set `AKA_INSTALL_REF=bin-v<version>` before running the line. If
no `bin-v*` release exists yet the one-liner fails closed rather than guessing.

After it completes, point them at `aka init` then `aka dashboard`. If they chose
**Not now**, show the one-liner once so they can add it later, and move on —
declining keeps the plugin fully functional standalone.

**Fail open.** This install is optional, so it must never derail the session. If
the installer fails for any reason — Node missing, network/registry error, a
non-zero exit, or the checksum check rejecting a bad download — briefly report
what happened, show the one-liner so they can retry later, and continue the
wizard normally. The plugin is already fully set up and works on its own; a
failed CLI install changes nothing about that.

**Close the wizard.** The first-run summary already confirmed the saved posture
and pointed at `/health`. Whichever way the CLI offer went — installed,
declined, or a failed install you already reported — end with one warm close:
"That's it — I'm watching out for Claude going forward."

Before you finish, confirm every AKA_SHOW region on the path you took was
relayed to the user. If you summarized one instead of pasting it, paste it now.
