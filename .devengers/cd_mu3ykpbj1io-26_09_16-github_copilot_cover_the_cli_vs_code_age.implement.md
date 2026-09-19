---
card: cd_mu3ykpbj1io
title: GitHub Copilot — cover the CLI + VS Code agent mode
stage: implement
---

# Implementation journal

First attempt. No prior journal existed; every checkbox in the plan was `- [ ]` at start.

## Environment

The container ships **Node v22.23.2**; the repo's `engines` floor is `>=24` and `.nvmrc`
says `24`. No Node 24 is installed and nothing here can install one. Consequences, all of
them worked around rather than fixed:

- `pnpm install` had to run as `pnpm install --config.engine-strict=false`.
- `node:sqlite` loads under 22.23 but prints an `ExperimentalWarning`. Store-backed suites
  run; a hook script that writes to stderr on a host reading stderr would see that line,
  which is a property of this container and not of the shipped artifact.
- Suites are driven with the workspace `vitest` binary directly rather than through turbo,
  because turbo re-enters `pnpm` and trips the engine check.

Nothing about the code below depends on the Node version; it is recorded because a green
run here is weaker evidence than a green run on 24.

## Step-by-step

### A1 + A2 — package builds (one commit)

Committed together deliberately. A1 adds a `build`/`prepack` script; a tree carrying a
`build` script and no `tsup.config.ts` is broken for `turbo run build`, so splitting them
would push a knowingly red commit. The plan's dependency arrow A1 → A2 is respected; only
the push boundary is merged, and the reason is this sentence.

- `plugins/copilot/package.json` — added `@akasecurity/{persistence,scanner,setup-wizard}`
  and `tsup` devDependencies at the exact ranges the three sibling plugins carry; added
  `build`, `dev`, `prepack` scripts, a `files` array (`plugin.json`, `hooks.json`,
  `skills`, `scripts` — Antigravity's shape, because Copilot reads a flat root manifest
  too) and `publishConfig`. `"private": true` left in place, per A1.
- `plugins/copilot/tsup.config.ts` — copied from `plugins/codex` verbatim apart from the
  header comment and the entry map. `normalizeSqliteSpecifier` and the `triage-rubric.md`
  copy in `onSuccess` came across unchanged and were verified by running the build.
- `plugins/copilot/src/scan-worker.ts` — the one entry that exists at this point. A2 says
  to trim `entry` to "the hook scripts that exist at this point plus `scan-worker`"; no
  hook script exists yet, and tsup refuses an empty entry map, so `scan-worker` is the
  whole map for now and grows as the hooks land.

Verified: `pnpm --filter @akasecurity/ai-tc-copilot build` emits
`scripts/scan-worker.js` (931 KB) and `scripts/triage-rubric.md`.
`plugins/copilot/scripts/` is already in `.gitignore` (:20) and already excluded from the
eslint-config `test` task's turbo inputs (`turbo.json:361`), so nothing else moved.

### A3 + A4 — test harness (one commit)

Also committed together, and for the same kind of reason: A3 declares `testTimeout` /
`hookTimeout` in `vitest.config.ts`, and `packages/eslint-config/test/hook-timeout-ratchet.test.js`
pins those as an **exact** map in both directions. A3 without A4 reds a package the diff
does not touch.

- `plugins/copilot/test/global-setup.ts` — the one-shot `tsup`, copied from
  `plugins/codex/test/global-setup.ts` including its Windows `shell` note.
- `plugins/copilot/vitest.config.ts` — `globalSetup: ['./test/global-setup.ts']`,
  `testTimeout: 20_000`, `hookTimeout: 20_000`. The comment claiming the package declares
  no timeouts (and is therefore absent from the ratchet) was **replaced**, per A3's
  explicit instruction, rather than left beside a contradiction.
- `packages/eslint-config/test/hook-timeout-ratchet.test.js` — `TIMEOUTS` gains
  `'@akasecurity/ai-tc-copilot': { testTimeout: 20_000, hookTimeout: 20_000 }`.

Verified: `hook-timeout-ratchet.test.js` 3/3 green; the copilot suite 14/14 green with the
build now running as globalSetup.

### B1–B4 — wire vocabulary (one commit)

B1 is the compile gate and B2–B4 are its fallout, so they land together: the tree
does not typecheck between B1 and B3.

- `packages/schema/src/zod/inventory.ts` — `HarnessId` extracts `'Copilot'`. Running
  `tsc --noEmit` in `packages/persistence` then named **exactly** the two sites the plan
  predicted (TS2741 at `inventory-assets.ts:106` and `:165`) and nothing else in the
  workspace: `HarnessId` has only eight importers and the other six are tests or fixtures.
- `packages/persistence/src/repositories/inventory-assets.ts` — `HARNESS_LABELS` gains
  `[HARNESS.Copilot]: 'GitHub Copilot'` (computed member key, per the vocabulary rule);
  `TITLE_NEEDLES` gains `Copilot: stripSeparators(SOURCE_TOOL.Copilot)`, which is
  **`githubcopilot`** rather than `copilot` — the needle is the stripped WIRE id, and a
  bare `copilot` would match any title merely containing the word. The reason is written
  beside the row rather than left to this journal.
- `resolveHarnessId`'s dispatch line, added by hand. The compiler does not ask for it.

**B4's test already existed, and is stronger than a hand-written one.**
`packages/persistence/test/repositories/inventory-harness-resolution.test.ts` derives its
case set from `Object.keys(HarnessId.enum)` and seeds one scanned harness row per member
through the real capture-path writer, so extending the enum extended the test with no edit.
Rather than take that on trust I mutated it: commenting out the new dispatch line reds that
file with `expected [ 'antigravity', 'claudecode', …(2) ] to deeply equal […(3) ]`, and
restoring it greens it again. So the silent gap the plan and the spec both name is covered
by a guard that cannot be satisfied by adding an enum member alone. No redundant per-harness
test was written.

- `packages/schema/test/zod/inventory.test.ts` — one existing case asserted
  `HarnessId.safeParse('copilot').success === false`, which is precisely the fact that had
  to move. Its accept list gains `copilot`; its reject list keeps `claude-code` and gains
  `github-copilot`, so **both** negatives are now the WIRE spelling of a harness the enum
  really does extract. That is the discriminating shape: a subset drifting onto the wrong
  vocabulary reds, where an arbitrary unknown string would not.

Verified: `packages/schema` 1110/1110 green (was 1 failed before the test edit),
`inventory-harness-resolution.test.ts` 3/3, `packages/persistence` typecheck clean.

**B5 is deliberately NOT ticked.** It flips `SCAN_COVERAGE`'s Copilot row off
`{ coverage: 0, supported: false }`, and that number is a claim about what the shipped
plugin scans. No hook exists yet, so any non-zero value would be false on the day it
landed. It is owed once the `preToolUse` path is real (section D), and the plan's own
Definition of Done #8 is what will collect it.

### C1–C7 + D1–D4 + A6 (partial) + K5 (pulled forward) — one commit

These land together because the tree does not hold still between them: `emit` taking the
narrowed union (C2) is what `pre-tool-use-decision.ts` builds against (D1), the wrapper
suite (C5) reads `hooks.json` (A6), and the coverage floor (K5) has to move in the same
commit as the first real source file or the package reds on a placeholder nobody measured.

**C1/C2 — `src/hooks/shared.ts`.** `runHookFailOpen` is ported from Antigravity with the
blocking-body limit restated verbatim in its own doc comment rather than softened, and
with the watchdog at `WATCHDOG_MS = 24_000` against the manifest's `timeoutSec: 30`.
`emit` takes `HookOutput` rather than `unknown`. `allowPayload(dialect)` is a FUNCTION, not
a frozen constant: `emit` serializes whatever it is handed, and one object shared between
two hosts invites a mutation that reaches both. Its own case pins that it returns a fresh
object.

**C3 — `src/hooks/event-name.ts`.** argv[2], validated against the 15 CLI + 8 VS Code
names. Its suite asserts the two schema-only names (`postResult`, `prePRDescription`) are
REFUSED, and asserts against the fixtures themselves that exactly one of the eight
recordings carries `hookName` — so the premise of the argv design is checked rather than
restated from the README. It also pins argv[2]-not-argv[3], the offset A5 depends on.

**C4 — `src/hooks/dialect.ts`.** `hook_event_name` → `vscode`, else session-key casing,
else `undefined`. Envelope readers go through one `ENVELOPE` table keyed by dialect, so no
reader can drift onto the other host's key names. Its suite drives the CLI branch from all
eight live recordings (with a count assertion so an empty directory cannot satisfy the loop
vacuously) and pins the discriminating failure directly: a real CLI payload read as
`vscode` must answer "no tool call" rather than a call with an empty args bag, which would
scan nothing and report success.

**C5 — `test/hooks/fail-open-wrapper.test.ts`.** Antigravity's suite, adapted. Throw,
synchronous throw, undecided body, the body's own decision (the positive control, without
which a wrapper that ignored `main` entirely would pass every other case), watchdog win,
and the late REJECTION that must not surface as an unhandled rejection — the one route to a
non-zero exit the wrapper never writes to, and on this host a non-zero exit is a deny. The
synchronous-block limit is pinned as behaviour. `soleDecision` asserts exactly ONE JSON
object, because two concatenated objects do not parse and a second write is read exactly as
silence. The `emit` block withholds the write callback, which is the only case here that
can see whether the flush is awaited.

**C7 — `test/hook-output-shapes.test.ts`.** Both compile directions plus the
`emit`-narrows pin, with the variant map's types spelled in an explicit `VariantTypes`
interface rather than derived from `HookOutput` — deriving both sides from one expression
is how a two-direction pin becomes a tautology. Verified by mutation: adding a
`{ mutationProbe: true }` member to `HookOutput` fails typecheck at
`hook-output-shapes.test.ts:91` with TS2322, and removing it greens it. The runtime half
drives the REAL builders rather than object literals, and pins the near-miss that makes this
worth having at all — both hosts spell `permissionDecision`, one at the top level and one
nested, so a payload built for the wrong host is silently ignored rather than rejected.

**D1/D2 — `src/hooks/pre-tool-use-decision.ts`.** Two field tables, never merged. The CLI
table is RECORDED (`bash.command` executable, `bash.description` not — both are in
`preToolUse.json`); the VS Code table is doc-derived and says so. `denyOutput` and
`rewriteOutput` are the two dialect-shaped builders; the decision logic itself is the Codex
sibling's, unchanged, including reading `result.redactDegradedTo` by VALUE rather than by
presence.

**D3 — `src/hooks/pre-tool-use.ts`.** The unknown-tool fast path returns `undefined`
BEFORE `loadConfig` and before the store opens, so the wrapper emits the explicit allow
having done no I/O. That is the common path on VS Code, which parses matchers and then
ignores them. The pointer pre-check runs before the store too.

**D4 — `test/hooks/pre-tool-use-decision.test.ts`.** Every enforcement case is driven
TWICE, once per dialect, through `describe.each`: block, redact-in-place on a stored field,
redact-on-executable degraded to block, degraded to warn (the shipped default — the command
RUNS, pinned rather than left implicit), unredactable-redact, the note-precedence case, warn,
and monitor. Plus a per-dialect case asserting the deny carries THIS host's shape and not
the other's. The pointer fixture is assembled from the documented segment widths and a
lookalike with an invented category is pinned as NOT denying.

**A6 is PARTIAL and stays unticked.** `plugin.json` and `hooks.json` exist and
`test/hooks-manifest.test.ts` checks each half against the thing it names — the script path
against the BUILT `scripts/` directory, the argv token against the same frozen vocabulary
the dispatcher validates with, and the declared `timeoutSec` against `WATCHDOG_MS`. But the
manifest registers ONE event, `preToolUse`, because that is the only hook script that
exists. A6 asks for one entry per event; the rest are owed as section E lands, and an entry
naming a script the build does not emit is worse than a missing entry — it fails at spawn,
which on this host is a deny.

**K5 is done early, out of plan order, and had to be.** `COVERAGE_FLOORS` carried
`'@akasecurity/ai-tc-copilot': 99` as an explicit placeholder. The moment real source
landed the package reported 30.95% and the floor reddened it. Measured and lowered to **29**,
one point under, with the measurement and — more usefully — the reason the number is low
written beside it: hook ENTRY files can never be imported by a test, and four modules were
copied in from the Codex sibling to satisfy the decision module's imports without their
suites. It is a floor over a part-built package, not this adapter's steady state.

Verified: `plugins/copilot` 90/90 green across 8 files, `eslint src test *.config.*` clean,
`tsc --noEmit` clean, `coverage-config.test.js` 17/17.

### I1 + I2 — the provisional fixtures and the provenance guard

- `test/fixtures/vscode-provisional/` — eight payloads, one per VS Code event, plus a
  README that opens by saying no live session produced any of them. The unverified fields
  are grouped by **how badly a wrong guess would hurt** rather than by confidence: "would
  silently scan nothing", "would silently mis-route the decision", "would change the
  failure convention". The vendor's self-contradiction on tool ids
  (`runTerminalCommand`/`editFiles` in the hook samples against
  `run_in_terminal`/`create_file` in the compatibility note) is written down with the
  consequence attached — if the samples are right, every VS Code enforcement row in this
  package is inert.
- `test/fixture-provenance.test.ts` — holds each directory to its own README, and holds the
  READMEs to saying the opposite things they exist to say. A recording the `cli/` README
  does not describe fails; a `vscode-provisional/` README with the "nothing here was
  recorded" sentence softened fails. The `cli/` case carries a positive control (the README
  must name the CLI version and the isolated home) so a README emptied to a filename list
  could not satisfy the containment check vacuously. Two further cases catch a file
  physically moved between the directories, since a payload's dialect is a property of its
  bytes rather than of its path.

**The plan's ordering fact 3 was NOT followed, and it is recorded rather than glossed.**
The plan requires I1 before D1 — the VS Code `SCANNABLE_FIELDS` table written FROM the
fixtures, "otherwise the fixtures get written to match the table and prove nothing". The
table was written first, from the same vendor pages, and the fixtures afterwards. That is
exactly the failure the ordering existed to prevent, so the fixtures directory's README
says so in its own section and the guard suite asserts that sentence is still there. The
honest reading: these fixtures and that table agree, their agreement is evidence of nothing,
and what they buy is a fixed point — a change to either now has to move the other. Anyone
re-deriving the table should re-derive it from a live recording, not from these files.

### A5 — `build-info.ts` at argv offset 3

One deviation from the plan's wording, and it is a correction rather than a shortcut. A5
says to copy `src/build-info.ts` "with the manifest read moved from `argv[2]` to `argv[3]`".
The sibling `build-info.ts` reads **no argv at all** — it resolves a relative manifest URL —
and the argv read the plan means lives in `session-start.ts`'s local `harnessVersion()`.
Copying the sibling verbatim would therefore have produced a file with no offset in it to
move.

So the argv reader is written here, as `harnessVersionFromArgv(argv = process.argv)`,
which is where the plan wants it and where it is testable without a hook process.
`session-start.ts` will call it when section E lands.

- `MANIFEST_URL` is `'../plugin.json'` with no dotted directory segment: Copilot reads a
  FLAT root manifest like Antigravity, unlike Claude Code's `.claude-plugin/` and Codex's
  `.codex-plugin/`. One relative path resolves it from both layouts (`scripts/<entry>.js`
  installed, `src/` in the repo).
- The path is turned into a URL with `pathToFileURL`, not a `file://` template. The
  template mangles a path carrying a space and produces an invalid URL for a Windows drive
  letter, and both land in `readManifestBuild`'s best-effort catch as a silently missing
  version.
- `PLUGIN_PACKAGE` is re-exported from `src/identity.ts` rather than respelled, so the
  package name has one definition. `identity.ts`'s comment now says why the module exists
  (`package-walls.test.js` pins that path as this package's import probe) instead of calling
  itself a placeholder, which it no longer is.

`test/build-info.test.ts` pins the offset with a discriminating case: a manifest path at
`argv[2]` must answer `undefined`. Every other case in the file would pass a reader that
looked at both slots. Each case writes its manifest to a temp directory of its own, because
`readManifestBuild` memoises per URL **including misses** — a shared path would have the
second case reading the first one's answer.

Verified: `plugins/copilot` 107/107 across 10 files, lint and typecheck clean.

### E1 — `src/hooks/session-start.ts` (second attempt)

The prior attempt's landed work was re-verified before anything new was written:
`plugins/copilot` reported 107/107 across 10 files on a fresh `pnpm install`, matching the
journal above. So this attempt starts at E1, the first unticked step whose dependencies
were all present.

**The provider seam had to move, and it moved in `plugin-sdk` rather than in the plugin.**
`PluginConfig['provider']` is a union of the three existing `Resolved*Provider` shapes and
none of them can carry `'unknown'`, which is what the plan requires this host to record. So
`packages/plugin-sdk/src/provider-copilot.ts` is new, the union gained a fourth member, and
`loadConfig`/`resolveProviderSafe` widened with it.

That module is deliberately unlike its three siblings and the difference is the whole of it:
Copilot publishes no base-url environment variable, so there is nothing to read and the
resolver answers `'unknown'` unconditionally. Two consequences worth stating because both
are easy to get wrong later. It reads NO environment, so it carries **no**
`n/no-process-env` opt-out and adds **no** row to CLAUDE.md §3 — `provider-copilot.test.ts`
pins that structurally (the source must not contain `process.env`) as well as behaviourally
(three stubbed base-url variables move the answer not at all). And there is deliberately no
`copilotProviderFromModelId` sibling: a Copilot session can be running Claude, GPT or Gemini
through GitHub's own endpoint, so the model FAMILY says nothing about which backend billed
it, and a heuristic that answered `'unknown'` for every id would read as a gap somebody
forgot to fill. The argument is in the module header instead, where it is not dead code.
`test/index.test.ts`'s pinned public-symbol set gained `resolveCopilotProvider` — that set is
exact, so the export could not land without it.

**The hook itself** is the Codex sibling's shape with three changes. The manifest version
comes from `harnessVersionFromArgv()` (slot 3, this host's offset — A5). `harnessInterface`
is derived from the payload DIALECT rather than from a transcript originator, because the two
hosts this package covers are told apart by their wire shape and by nothing else. And
`triggerReconcile` is **not** wired yet: it needs `history/reconcile-trigger.ts` plus a
`reconcile` build entry, which is F3, and a `triggerReconcile` call whose target script the
build does not emit would spawn nothing while reading as a safety net. It is owed when F3
lands, and E5's `stop.ts` is the step that brings it.

**The pure half is split into `session-start-payload.ts`**, the way Codex splits
`stop-payload.ts`: a hook entry runs `main()` on import, so anything a test needs to reach
cannot live in the entry. `harnessInterfaceFor` reports `cli` for the CLI dialect and never
`cloud` — a terminal `copilot` and the cloud coding agent speak the same wire, so nothing in
the payload separates them and `cloud` would be a fabricated fact on a durable per-session
row. Phase C names that surface through the installed launcher instead.

**The ordering case the plan asks for is driven, not restated.**
`test/hooks/session-start-order.test.ts` opens a real temp store, writes a prompt capture
through the product's own runtime, and only THEN calls `handleSessionStart` — the recorded
order, in which `userPromptSubmitted` is stamped 20 ms before `sessionStart`. It asserts the
root opened under the right id and that the capture written before it still hangs off it. Its
first case asserts the PREMISE from the fixtures' own timestamps rather than quoting the
README, so a recording that stopped showing the inversion would say so rather than leaving a
case that silently describes nothing.

Commit: see `feat(copilot): open the session root, and resolve no provider for it`.

Verified: `plugins/copilot` 117/117 across 12 files; `packages/plugin-sdk` 660 passed / 2
skipped across 43 files; `packages/plugin-runtime` 576 passed / 3 skipped. Lint and
`tsc --noEmit` clean for both changed packages.

**Two `packages/persistence` failures pre-date this diff and are environmental**, not caused
by it — that package takes no `plugin-sdk` dependency. `test/helpers/temp-store.test.ts`'s
undeletable-tree case and `test/helpers/settings-writers.test.ts`'s parent-exit case both
fail because this container runs as **uid 0**, and `test/internal/sql-functions.test.ts`'s two
`aka_lower` NUL cases fail on this container's Node 22 `node:sqlite`. Same environment note as
the previous attempt's.

### E2 — `src/hooks/user-prompt-submit.ts`

**One script, three event names, and the argv dispatcher is what makes that safe.**
`userPromptTransformed` re-carries `prompt` alongside `transformedPrompt`, so a reader keyed
on which fields the payload happens to have would answer with the untransformed text — the
user's words scanned a second time, the scaffolding never seen. `readPromptCapture` is keyed
on the ARGV event name instead, which is the first real use `event-name.ts` has had, and the
test drives the recorded `userPromptTransformed.json` to prove it takes the transformed field
while the untransformed one is sitting right beside it.

**The transformed event is recorded at `with-findings` and emits nothing.** Its text
CONTAINS the submitted prompt verbatim, so persisting both unconditionally would double-count
every clean turn, and a second message for the same secret milliseconds later is noise. What
it buys is the case that matters: a secret the TRANSFORMATION introduced, which
`userPromptSubmitted.prompt` cannot show.

**This hook blocks nothing, and the wording is the whole of the work.** The plan says
"block/rewrite only where the matrix marks it verified; otherwise record-only, and say so" —
and nothing is verified on either surface (the CLI's `modifiedPrompt` from a COMMAND hook is
in the fixtures README's "Not measured"; VS Code's `UserPromptSubmit` block channel has never
been driven). Emitting a block the host silently ignores is strictly worse than emitting
none, because the user reads an enforcement claim while the prompt goes to the model. So a
`block` or `redact` policy prints what actually happened — flagged, recorded, sent unchanged —
in a sentence deliberately DIFFERENT from the `warn` one, so a user whose policy says block
can tell it did not take effect. The test pins the difference in both directions and pins
that the payload carries no decision key of EITHER dialect.

`promptEmitPayload` takes **no** dialect parameter. `decidePreToolUse` does, because the two
hosts really do differ there; here neither has a channel to shape, `systemMessage` is a
top-level key both accept, and taking a parameter only to ignore it would read as a per-host
difference that does not exist. That cost the first draft a lint failure
(`no-unused-vars`), which is the right gate for exactly this.

Owed to H3: `skills/setup/SKILL.md`'s Known limitations must carry the no-prompt-stop fact.

Commit: see `feat(copilot): capture prompts, and say plainly that nothing stops them`.

Verified: `plugins/copilot` 131/131 across 13 files; lint and `tsc --noEmit` clean.

### E3 — `post-tool-use.ts` + `tool-response.ts` + `scan-response.ts`

**The trap the plan names is pinned twice, and the second pin is the one that survives a
rewrite.** `postToolUse.toolResult.resultType` reports whether the tool INVOCATION succeeded,
not whether the command exited zero: the recorded fixture is a `bash` call whose command is
literally `false`, and its `resultType` is `"success"` with the exit code appearing only as
free text inside `textResultForLlm`. So `tool-response.test.ts` drives that recording (the
premise asserted from the bytes, not quoted) AND asserts the module reads the field on **no
branch at all** — with comments stripped first, because the module names `resultType`
repeatedly to explain why it ignores it and a raw substring check would be satisfied by that
prose for ever. The strip carries its own control.

**The two hosts have genuinely different levers, and the escalation is on one of them only.**
The CLI offers `modifiedResult`, which replaces the whole result object, and that one key
expresses BOTH a redaction (substitute the masked text) and a withhold (substitute the block
notice) — so the CLI keeps true in-place redaction on responses. VS Code has no
result-rewrite field at all; its only lever is `{"decision":"block"}` + `additionalContext`,
which is whole-result or nothing, so a `redact` there ESCALATES to the same withhold a block
gets. That difference is driven rather than described: one case builds both payloads from the
identical capture outcome and asserts they are shaped differently.

**`scannedPaths` is the non-obvious piece.** A block produces no masked text, so `rewrites`
names nothing for the field it came from — and a withhold that wrote its notice only over the
REDACTED fields would send the blocked value to the model untouched, which is the entire
failure the withhold exists to prevent. The outcome therefore records every path it scanned,
finding or not, and the withhold overwrites all of them.

**`modifiedResult` is documented and unobserved, and emitting it is still right** — a
different judgement from E2's refusal to emit a prompt block, and the difference is the
failure mode. If the host honours it the redaction is real; if it ignores it the outcome is
exactly what emitting nothing would have been. Nothing is lost by trying. The prompt case was
the opposite: a block the host ignores is a false enforcement claim the user reads.

Two honest degradations are pinned rather than papered over. A CLI result that is not an
object cannot be rebuilt into a `modifiedResult`, so that branch prints a note saying the
result reached the model unchanged — deliberately NOT `withheldBanner`, whose text states the
flagged value never reached the model and would be a lie there. And a CLI rewrite rides a
single-key output with no room for a `systemMessage`, so a CLI redaction is silent to the
USER; the model gets the withhold notice, the user gets nothing. That is a host limitation,
owed to `SKILL.md`'s Known limitations (H3), and working around it would mean a second stdout
write — two concatenated objects, which do not parse.

Commit: see `feat(copilot): scan tool results, and never read resultType as an exit code`.

Verified: `plugins/copilot` 153/153 across 15 files; lint, prettier and `tsc --noEmit` clean.

### E4, E6 and A6 — the collision, the store-health suite, and the full manifest

**E4.** `preToolUse` and `permissionRequest` both fire for one tool call, 41 ms apart, even
under `--allow-all` — so this host offers two places to scan one call. The scan point is
`preToolUse`, and `test/hooks/permission-request.test.ts` asserts WHY rather than restating
it: `permissionRequest.toolInput` carries `command` alone while `preToolUse.toolArgs` also
carries `description`, which this package's CLI field table scans and can redact in place.
The subset relation is derived from the two recordings; the missing field is derived from the
table. A fourth case is the structural backstop and explains why a mis-routed entry would be
QUIET rather than loud: the CLI envelope reader looks for `toolArgs`, which a
`permissionRequest` payload does not have, so the call would be read with an empty argument
bag — every field skipped, no finding, an explicit allow emitted, a clean run reported.

**E6.** `store-health.ts` was already present (copied in with the pre-tool-use work) and had
no suite. Its sibling's 15 cases are copied in as a PEER copy, for the reason `no-echo.ts` is
copied: a package wall blocks the import, the module is itself a peer copy, and a copy
without its suite is a module nothing here checks. The one host-specific value is the
config's `provider`, `'unknown'` here. Its module header also had a stale paragraph claiming
this adapter passes no provider resolver — true when it was written, false since E1 — and
that is corrected rather than left beside the code that contradicts it.

**A6.** The manifest now registers all four hook scripts under BOTH hosts' spellings: nine
entries over `sessionStart`/`SessionStart`, `userPromptSubmitted`/`userPromptTransformed`/
`UserPromptSubmit`, `preToolUse`/`PreToolUse` and `postToolUse`/`PostToolUse`. The two
`session-start` entries carry the plugin manifest path as a SECOND trailing token, which is
the argv-offset-3 contract A5 landed.

Two new cases in `hooks-manifest.test.ts` close the directions the existing five could not
see. A script the build emits that NO entry names is a capture surface the host never spawns
— nothing fails and nothing is logged, so it reads exactly like a host that does not fire
those events; that case differences the built `scripts/` against the registered set, with
`scan-worker.js` excluded by name because no hook is meant to name it. And a script
registered under ONE dialect's spelling silently covers one host: the CLI's names are the
ones a developer reaches for first, so VS Code is the half that goes missing.
`userPromptTransformed` is the one exemption, because VS Code fires no counterpart event.

Commit: see `feat(copilot): register every hook under both hosts' event spellings`.

Verified: `plugins/copilot` 174/174 across 17 files; lint and `tsc --noEmit` clean.

### K1 — the fail-open e2e, and the defect it found

This is the only suite in the repository whose two halves assert OPPOSITE bytes, because one
of this host's events has a different failure convention from the rest: `preToolUse` must
print exactly one `{"permissionDecision":"allow"}` on every fault, and the other three hooks
must print nothing. So `''` is a pass on three and a failure on the fourth, and the two are
never checked by the same assertion — `silent()` is an exact equality rather than a
`not.toContain`, which would pass on the very value under test.

**It found a real defect in already-landed work, which is what it is for.** On a store that
will not open, `pre-tool-use.ts` returned a bare `{ systemMessage: … }` — a payload with NO
verdict, on the one event where a payload the host has to interpret is exactly the risk the
explicit allow exists to remove. Fixed by giving `CliPermissionOutput` an optional
`systemMessage` and having `allowPayload(dialect, note?)` carry it, so the note rides WITH
the verdict instead of replacing it. Both dialects have a slot for one. The variant map in
`hook-output-shapes.test.ts` is keyed on `permissionDecision` and so did not move.

**Two rows are deliberately weaker than the rest, and the weakening is bounded.** A broken or
relocated store is a condition AKA is DESIGNED to speak about — the once-per-session
store-unavailable notice and the first-run nudge are both deliberate `systemMessage` writes
on hooks whose ordinary answer is silence — so demanding `''` there would forbid a feature
rather than catch a regression. Those two rows assert the property that actually matters
instead: a hook may say something, but it may not DECIDE. Silence, or one object whose ONLY
key is `systemMessage`; any decision key of either dialect fails.

That weakening then needs its own control, because `expectFailOpenOrNote` passes on a bare
allow and so cannot see the note being dropped entirely — which would leave every fault row
green while the user's store silently stopped recording. `pre-tool-use over an unopenable
store` is that control and asserts both halves in one object.

**The enforcement half is five cells, driven from a shipped rule's own example** so no
secret-shaped literal is written by hand: deny under `block`; `modifiedArgs` carrying the
WHOLE argument object under `redact` on `description` (which does not execute); the call let
THROUGH under `redact` on `command` (which does — the runtime degrades to `redactFallback`,
shipped as `warn`), pinned so nobody "fixes" it into an unconditional deny; a `systemMessage`
under `warn`; and the plain explicit allow under `monitor`, which is the row that would make
every other one vacuous if the rule stopped matching. Each also asserts the raw value never
rides back out on stdout.

Commit: see `test(copilot): drive the built hooks, and carry the store note with the verdict`.

Verified: `plugins/copilot` 216/216 across 18 files; lint and `tsc --noEmit` clean.

### K2 and B5 — the worker bundle, and a coverage number with an argument

**K2** is a peer copy of the three siblings' suite, with one deliberate difference from the
Antigravity original it was taken from: that copy spawns the built hook with
`{ ...process.env, HOME, USERPROFILE }` behind an inline `n/no-process-env` disable. This one
passes `{ HOME, USERPROFILE }` alone — `process.execPath` is an absolute node path, so the
child needs no host PATH — which keeps the file out of the tree-wide inline-disable
inventory entirely rather than adding a row to it.

`KNOWN_RUNTIME_SCRIPTS` is this host's own set: `pre-tool-use.js`, `post-tool-use.js` and
`user-prompt-submit.js` all build a runtime, and `session-start.js` deliberately does not —
that event has no text to scan. If it ever starts carrying the runtime marker, that list is
what makes someone notice the hook's job changed.

**B5.** `SCAN_COVERAGE`'s Copilot row goes from `{ 0, false }` to `{ 50, true }`, which places
it BELOW Antigravity's 60 — and that reads backwards until the reason is stated, so it is
pinned with one. The row spans TWO surfaces and has to describe the weaker. The CLI adapter
is genuinely richer than Antigravity's: it captures prompts (both the submitted text and the
host-transformed form), redacts tool input in place on the non-executable field, and can
redact or withhold a tool RESULT — none of which Antigravity can do at all. VS Code agent
mode is unconfirmed throughout and has no result-rewrite field.

Three gaps bound the number, and none is closed by anything shipping today. Prompts are
RECORD-ONLY on both surfaces, because neither host has an observed prompt-stop channel. File
-write content is scanned in neither direction: `apply_patch` is the CLI's write tool and its
argument names have never been recorded, so its row in the field table is INERT by
construction. And there is no history backfill for this host, so nothing recovers either gap
after the fact. Antigravity's 60 buys its place with tool-call coverage across EVERY tool in
its CLI, which is exactly the axis this host is weakest on.

The ordering is asserted rather than left to the prose: strictly below Antigravity, strictly
above the two web-chat rows. A sentence explaining a position is worth nothing once the
position moves out from under it.

Commit: see `feat(copilot): pin the worker bundle, and give the coverage row its argument`.

Verified: `plugins/copilot` 219/219 across 19 files; `packages/persistence`
`security.test.ts` 38/38; lint, prettier and `tsc --noEmit` clean for both packages.

### H2, H3 and H4 — the matrix as code, and the skill held to it

`src/capabilities.ts` carries nine rows of surface × event × subject →
`{ channel, verified }`, and `skills/setup/SKILL.md`'s Known limitations section is derived
from it: a table of the rows plus a sentence per row.
`test/capability-matrix.test.ts` holds the two together in BOTH directions, because they
fail differently — a matrix row with no sentence is a limit nobody was told about, and a
sentence with no row is a claim about a surface that has changed underneath it.

Four things in that guard are load-bearing beyond the row-set comparison. It carries a
positive control, because every other case iterates one of the two collections and an empty
matrix or table would satisfy them all for free. It requires each row's SENTENCE in the prose,
not just its cells — a one-word cell reading `none` explains nothing, and the sentence is
where the limitation actually lives. It requires the document to say IN ITS OWN WORDS that
the unverified rows have never been seen working, rather than leaving that to a `no` in a
cell somebody may not read as a warning. And it pins the CLOUD surface's ABSENCE from the
matrix, which is exactly the kind of fact a reader supplies from memory: no hook runs there,
so a row claiming it speaks the CLI's wire would be true of the host and false of AKA.

The prose comparison collapses whitespace, because the document is hard-wrapped and
list-indented while the matrix's notes are single lines. Without that the guard would fail on
a reflow and quietly reward writing the file unwrapped.

**One deviation from the plan, and it is a scoping one.** H3 asks for the Known limitations
section of the setup skill; H1 and H5 ask for the other nine skills and the whole wizard
surface, and neither is done. So this `SKILL.md` is NOT the guided calibration wizard the
other three plugins ship, and it says so in its second paragraph — nothing here reads Copilot
session history, so a wizard that proposed a posture would be proposing it from nothing. It
documents what AKA covers, points at the shared `aka` CLI verbs, and carries the matrix. A
guard case pins that disclaimer, so a later attempt cannot wire a wizard in and leave the
skill claiming to be one it is not — or remove the sentence without wiring one.

It also records two host limits the matrix's channel column cannot express: a CLI redaction
is SILENT to the user (the rewrite channel is a single-key output with nowhere for a note, so
the model is told and the user is not), and the cloud agent is uncovered.

Commit: see `feat(copilot): make the capability matrix code and derive the skill from it`.

Verified: `plugins/copilot` 225/225 across 20 files; lint, prettier and `tsc --noEmit` clean.

### K7 — CLAUDE.md is true again, and a guard caught what I had missed

Four edits. Two hook-contract bullets: one for the two-hosts-one-file shape (two payload
dialects, two never-merged field tables, the event name on argv and what that does to the
manifest offset, prompts record-only on both surfaces, and `modifiedResult` on the CLI alone),
and one for the failure convention — `preToolUse` denies on a crash and allows on a timeout
while every other event fails open, with exit-0-and-empty-stdout unobserved, which is why
that one event prints an explicit allow and the rest stay silent. Plus the package-dependency
graph, the repository-layout block, and a bullet in the releasing section.

**That last one says what the section would otherwise imply and should not.** `plugins/copilot`
bundles the same core as the three shipping plugins, so a bundled-package change rebuilds its
`scripts/*.js` — and ships to nobody, because it is `"private": true` with no release
workflow. The bullet says so and names what has to move WITH `private` when somebody unsets
it: the release workflow, the derived published-package set in `required-checks.test.js`, and
the `ci.yml` prose explaining the temporary Windows pin. Adding copilot to the bump list
today would be a claim about an artifact nobody can install.

**`posture-build-wiring.test.js` caught a real gap from E1, three commits late.**
`plugins/copilot/src/hooks/session-start.ts` is a session-pass caller and that guard pins the
caller set EXACTLY, so it reddened the moment I ran the eslint-config suite — which I should
have run in the E1 commit rather than here. The file already threads `pluginBuild:`, so the
second half of that guard passed on the first run; only the membership needed the edit.

Lesson worth carrying: `packages/eslint-config`'s suite hashes the whole workspace and is the
one place several cross-cutting guards live. Run it after any commit that adds a `src/` file
to a plugin, not only after touching CLAUDE.md.

Commit: see `docs: describe the Copilot adapter's two hosts and its split fail convention`.

Verified: `packages/eslint-config` 1531/1531 across 23 files; prettier clean on CLAUDE.md.

### I3, and the coverage floor re-taken

**I3 is ticked as satisfied-by-inspection, and the honest reading is that it was a no-op.**
The step says "extend `test/cli-fixture-shapes.test.ts` for any new recording", and this
attempt captured no new recording — there is no Copilot CLI on this container and none could
be installed. The existing file-set case still pins the eight recordings exactly, so it fails
the moment a ninth lands, which is the property the step exists for. No edit was owed and
none was made.

**K5's floor was re-taken, which it needed.** It was measured at 29 (against 30.95) when the
package held one decision module; the package now reports **50.61**, so the floor moves to
**49**. Both numbers are measured rather than estimated. The second move is the reason the
first should not have been left alone: a floor four-fifths of the way below what the suite
reports forbids almost nothing, so it goes on reading as a gate while a regression walks
under it. The comment beside it now records both readings and what is still uncovered — the
hook ENTRY files, which a test can never import and which the e2e reaches only as BUILT
scripts v8 does not instrument.

Commit: see `test(copilot): re-take the coverage floor now the suite reaches the built hooks`.

---

## Where this attempt stopped, and what the next one should do

**The plan is NOT fully implemented, and no pull request was opened.** 22 of its ~60 steps
are landed, tested and pushed. The rest are untouched. Per the contract a partially
implemented plan does not get a PR, so the work sits on
`devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io` for the next
attempt to build on.

### Landed and verified

| Step   | State                                                                     |
| ------ | ------------------------------------------------------------------------- |
| A1–A5  | done                                                                      |
| A6     | **partial** — manifest + guard exist, but only `preToolUse` is registered |
| B1–B4  | done                                                                      |
| B5     | **not done, deliberately** — see below                                    |
| C1–C7  | done                                                                      |
| D1–D4  | done                                                                      |
| I1, I2 | done, with the ordering violation recorded                                |
| K5     | done early, out of order, because it had to be                            |

Everything else — E, F, G, H, I3, J, K1–K4, K6–K8, L — is untouched.

### Verification as of the last commit

- `plugins/copilot`: 107 tests, 10 files, green. `eslint src test *.config.*` clean,
  `tsc --noEmit` clean, coverage above its measured floor.
- `packages/eslint-config`: 1531 tests, 23 files, green — this is the suite carrying
  `effective-config`, `no-network`, `no-network-runtime`, `coverage-config`,
  `hook-timeout-ratchet`, `package-walls`, `required-checks`, `claude-md`,
  `test-only-seam` and `inline-disables`, so the cross-cutting guards all saw this diff.
- `packages/persistence/test/repositories`: 676 tests, 31 files, green.
- `packages/schema`: 1110 tests green.

Two verifications were **not** possible here and the next attempt should not assume them:

1. **`pnpm lint` over the whole workspace did not complete.** `web-ui:lint` is OOM-killed
   in this container (exit 137). Every package this diff touches was linted individually
   and is clean; `web-ui` is untouched by it.
2. **Nothing ran on Node 24.** See the Environment note at the top.

### Two decisions the next attempt inherits

**B5 (`SCAN_COVERAGE`) is deliberately left at `{ coverage: 0, supported: false }`.** That
number is a claim about what the shipped plugin scans. One hook exists and it covers one
event, so any non-zero value would be false today. It is owed once section E lands — and
when it does, the argument the plan asks for has to account for the asymmetry between the
two surfaces this one row covers: the CLI has prompt capture plus input AND output rewrite
(richer than Antigravity's 60), while VS Code Local has no output rewrite at all and every
one of its rows is unverified. One number over two surfaces of different strength is the
open question, not the number itself.

**A6 registers one event.** Adding entries for events whose scripts do not exist would
fail at spawn, which on this host is a deny — strictly worse than a missing entry. The
manifest guard (`test/hooks-manifest.test.ts`) checks each command against the BUILT
`scripts/` directory, so it will refuse an entry added ahead of its script.

### The shortest path back in

Sections E and F are next and are ordinary work: each remaining hook is a Codex sibling
plus the dialect parameter this package already threads everywhere. Three traps the plan
names are still unpaid, and all three are in E:

- **E1**: the recordings show `userPromptSubmitted` stamped 20 ms BEFORE `sessionStart`, so
  the once-per-session pass must tolerate running after the session's first prompt. Drive
  the recorded order, not the intuitive one.
- **E3**: `postToolUse.toolResult.resultType` is `"success"` for a command that exited 1.
  Anything reading it as an exit status is wrong and will look right. The fixture that
  proves it is already in the tree (`postToolUse.json`, the `false` command).
- **E4**: `preToolUse` and `permissionRequest` both fire for one call. Scan on `preToolUse`
  only — `permissionRequest.toolInput` holds `command` alone and scanning it would silently
  skip `description`, which this package's CLI field table does scan.

After E, the tsup `entry` map and `hooks.json` grow together, and K1's e2e becomes
writable — which is the gate that turns every absence assertion in this package from a
claim into a check.
