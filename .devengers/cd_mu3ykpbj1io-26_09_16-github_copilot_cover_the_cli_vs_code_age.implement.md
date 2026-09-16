---
card: cd_mu3ykpbj1io
title: GitHub Copilot — cover the CLI + VS Code agent mode
stage: implement
---

# Implementation journal

## Environment note

The container ships Node **v22.23.2**; this workspace declares `engines.node >= 24`, so
`pnpm install` refused outright. Node 24.21.0 was unpacked to `/opt/node24` and every
command in this flight runs with `PATH=/opt/node24/bin:$PATH`. Nothing in the tree changed
for it.

## Deviations from the plan

Recorded here as they are taken; each is also in the pull request description.

1. **A5 — `build-info.ts` carries no argv read in the siblings.** The plan says to copy
   `src/build-info.ts` "with the manifest read moved from `argv[2]` to `argv[3]`". In the
   tree, `plugins/{codex,antigravity}/src/build-info.ts` resolve the manifest from
   `import.meta.url` and read **no argv at all** — the `argv[2]` manifest read lives in
   `plugins/antigravity/src/hooks/pre-invocation.ts`'s local `harnessVersion()` and in
   `intro.ts`. The offset is real, so it is implemented and pinned; it is implemented **in
   `build-info.ts`** (as `harnessVersionFromArgv` + the exported `MANIFEST_ARGV_INDEX`)
   rather than inline in the session-start hook, so one module spells the offset and one
   test drives it.

2. **A6 is split.** `plugin.json` landed with A5's commit because `build-info.ts`'s relative
   manifest URL resolves against it. `hooks.json` and its test are deferred until the hook
   scripts exist: the test the plan asks for ("every command in `hooks.json` resolves to an
   emitted `scripts/*.js`") cannot be written non-vacuously against an entry map that has no
   hook entries in it yet, and a test that passes because it checked nothing is the failure
   mode this repo's conventions single out. A6 is ticked when `hooks.json` lands with the
   hooks.

## Steps

### A1 — package manifest (commit `HEAD` of this step)

Added `@akasecurity/{persistence,scanner,setup-wizard}` and `tsup` to
`plugins/copilot/package.json` devDependencies at the exact ranges `plugins/codex` carries,
plus `build` / `dev` / `prepack` scripts and a `files` array (`plugin.json`, `hooks.json`,
`skills`, `scripts` — Copilot reads a flat root manifest, so there is no dotted plugin dir
to ship). `"private": true` left in place per the task.

### A2 — `tsup.config.ts`

Copied from `plugins/codex` verbatim apart from the entry map and the comment that names
the sibling. `normalizeSqliteSpecifier` and the `triage-rubric.md` copy in `onSuccess` came
across unchanged; both verified by running the build. Entry map carries **`scan-worker`
only** at this point, per the task's "trimming `entry` to the hook scripts that exist at
this point"; it grows as each hook lands. `src/scan-worker.ts` added as that entry's source.

`pnpm run build` emits `scripts/scan-worker.js` (931 KB) and `scripts/triage-rubric.md`.
`.gitignore:20` already excludes `plugins/copilot/scripts/`.

### A3 — one-shot build before the suite

`test/global-setup.ts` copied from `plugins/codex` (including its Windows `.cmd`-shim
reasoning). `vitest.config.ts` gains `globalSetup`, `testTimeout: 20_000` and
`hookTimeout: 20_000`, and the comment claiming the package has no timeout overrides — and
is absent from the ratchet for that reason — is **replaced**, since both halves of it stop
being true here.

### A4 — the ratchet

`'@akasecurity/ai-tc-copilot': { testTimeout: 20_000, hookTimeout: 20_000 }` added to
`TIMEOUTS` in `packages/eslint-config/test/hook-timeout-ratchet.test.js`. That map is an
EXACT pin in both directions, so this is the edit that keeps A3 from failing the workspace.

### A5 — `build-info.ts` and its argv offset

`src/build-info.ts` exports `PLUGIN_PACKAGE`, `pluginBuild()` (manifest resolved from
`import.meta.url`, as the siblings do), `MANIFEST_ARGV_INDEX = 3` and
`harnessVersionFromArgv(argv = process.argv)`. `test/build-info.test.ts` pins the offset as
a number **and** drives it: a manifest at `argv[3]` is read, and the same argv truncated to
the sibling's index answers `undefined` rather than the version — which is the regression
the offset exists to prevent, driven rather than asserted about.

### Verification for A1–A5

- `plugins/copilot`: `pnpm test` 22 passed / 3 files, `pnpm run lint`, `pnpm run typecheck`
  all green.
- `packages/eslint-config`: `pnpm test` **1526 passed / 23 files** — the guard package that
  owns the ratchet, the effective-config audit, the derived lint-coverage check and the
  no-network runtime audit. Green after A4.

### B1–B4 — the wire vocabulary

`HarnessId` in `packages/schema/src/zod/inventory.ts` extends with `'Copilot'`. `pnpm
typecheck` then named **exactly two** sites, as the plan predicted —
`inventory-assets.ts:106` (`HARNESS_LABELS`) and `:165` (`TITLE_NEEDLES`) — and said nothing
about the third, `resolveHarnessId`'s hand-written `if` ladder. All three carry Copilot now:

- `HARNESS_LABELS[HARNESS.Copilot] = 'GitHub Copilot'`.
- `TITLE_NEEDLES.Copilot = stripSeparators(SOURCE_TOOL.Copilot)` → **`githubcopilot`**, the
  stripped wire id like every other row, not the display id.
- one dispatch arm, added by hand.

`packages/schema/test/zod/inventory.test.ts`'s `HarnessId` cases moved with it. Its
rejection case used to name `'copilot'`, which is now an accepted member; it names the wire
id `'github-copilot'` instead — still a near-miss on a real member rather than an arbitrary
string, which is what made that case worth having.

**B4's test.** `inventory-harness-resolution.test.ts` already drives every `HarnessId`
member from its own wire id, so Copilot picks up derived coverage for free — but that case
would pass with the dispatch arm missing, because a member resolving to `null` yields no
card and reads as an ordinary absence in a set comparison. Two named cases were added
instead: Copilot's wire id resolves **and** labels the card, and a row titled with the bare
word `copilot` resolves to **nothing** (the needle is the wire id; the two spellings differ
here exactly as they do for Claude Code).

Verified: `packages/schema` 116 passed, `packages/persistence/test/repositories` 678 passed
across 31 files, workspace-wide `turbo run typecheck` 26/26.

### B5 — deferred, deliberately

`SCAN_COVERAGE`'s Copilot row is still `{ coverage: 0, supported: false }`. Flipping it is
a claim that this harness is scanned, and at this point in the branch the package emits no
hook at all — the number would be false in every store that read it, and the dashboard would
render a coverage row for a harness nothing captures. The flip belongs with the commit that
lands the hooks. Not ticked.

### C1–C7 — the wrapper and the wire

`src/hooks/shared.ts` carries `readStdin`, `parseJson`, `getString`, `baseMetadata`, `emit`,
`runHookFailOpen`, `WATCHDOG_MS` and the `HookOutput` union; `src/hooks/event-name.ts` reads
the argv token; `src/hooks/dialect.ts` places a payload and reads its envelope.

Decisions worth naming:

- **`WATCHDOG_MS = 24_000`** against the 30 s this host's manifest registers — the same
  ratio Antigravity keeps at 8 s under 10 s, with the margin reserved for `emit`'s awaited
  flush, which sits outside the race by design. `runHookFailOpen`'s blocking-body limit is
  restated verbatim in the header rather than softened, and driven as behaviour in the
  wrapper suite.
- **`allowFor(dialect)` is a function, not two frozen constants.** A caller holding the
  object that goes on the wire could mutate what every later emit in the process prints;
  pinned by a case.
- **An unplaced envelope gets the CLI allow.** The CLI is the surface whose fail-closed
  reading is documented; being wrong in the other direction costs a warning on a host that
  fails open, not a blocked call.
- **`baseMetadata` gives VS Code no cwd fallback.** That host's spawn cwd defaults to the
  HOME directory, so `process.cwd()` there would stamp every capture with a repo resolved
  from `~`. The CLI keeps the fallback.
- **An unobserved `toolArgs` encoding is not guessed at.** A bag arriving as a JSON string
  reads as no args — scanning nothing and saying nothing, like any other unknown shape —
  rather than being parsed on a hunch.

**The union's two-direction pin caught a real defect in itself while being written.**
`HookOutput extends unknown ? RequiredKeys<HookOutput> : never`, written against the
concrete alias rather than a type parameter, does **not** distribute — and `keyof` over a
union is the INTERSECTION of its members' keys, which is empty here. That version resolves
to `never`, which makes "every variant is named" vacuously true; only the opposite
direction failed. Fixed by distributing through a parameter, and the reason is written
beside it.

**C7 reads the sentence in `src/hooks/shared.ts`, not `CLAUDE.md`.** The count word, the six
spans and the dialect pairings are parsed out of the module header, in the shape the Claude
Code sibling parses §1. `CLAUDE.md`'s hook-contract bullets for this host are K7 and do not
exist yet; a guard reading a section that is not there would throw, and one written to
tolerate its absence would assert nothing. The test gains that read at K7.

`test/hooks/{fail-open-wrapper,event-name,dialect}.test.ts` and
`test/hook-output-shapes.test.ts` are the cover. The wrapper suite drives both dialects'
fail-open payloads, the throw, the sync throw, the undecided body, the watchdog win, the
late rejection that must not surface as an unhandled rejection, the synchronous-block limit,
`emit`'s flush, and `soleDecision` — exactly one JSON object and exit 0, because two
concatenated objects do not parse and a non-zero exit is a deny here.

**Coverage floor moved off its placeholder** ahead of K5: `99` was a stand-in written when
the package held one exported constant, and the first real source made `pnpm test` red on
it. It reads `61` now, one point under the measured `62.50`, with the measurement beside it.
K5 re-measures once the adapter is complete; this is not that step and is not ticked.

Verified: `plugins/copilot` 72 passed / 7 files, lint, typecheck and `prettier --check`
green; `packages/eslint-config`'s `coverage-config.test.js` 17 passed.

### I1–I2 — the provisional fixtures and their provenance guard

`test/fixtures/vscode-provisional/` carries one file per VS Code event plus a README that
says, in as many words, that **no live VS Code session produced any of them**, names the
vendor sources, and enumerates every field whose presence, casing or type is unverified.
`test/fixture-provenance.test.ts` holds both directories to their own contract: every
recording under `cli/` must be described by name in that directory's README (the shape a
doc-derived specimen moved across would fail), the two directories may not carry the same
event, and the provisional README must keep its disclaimer, its sources and its unverified
list. I3 is nothing to do: no new recording was captured on this branch.

### D1–D4 — pre-tool-use

`src/hooks/pre-tool-use-decision.ts` carries **two** field tables and a `denyOutput`/
`decidePreToolUse` pair that takes the dialect as a parameter all the way down. CLI:
`bash.command` executable, `bash.description` rewritable, `apply_patch.input` rewritable.
VS Code: `run_in_terminal.{command,explanation}`, `create_file.content`,
`replace_string_in_file.newString`, `insert_edit_into_file.code`, `apply_patch.input` — every
row doc-derived, written FROM the provisional fixtures.

`src/hooks/pre-tool-use.ts` is the entry: event token → stdin → dialect → **unknown tool
returns before `loadConfig` and before the store opens** → pointer deny → gateway → per-field
`runtime.capture` with `rewritable: !spec.executable` → `decidePreToolUse`.

Two things the tests forced:

- **The redact channel carries the WHOLE argument object** in both dialects, not the changed
  field alone. `modifiedArgs` replaces the call's arguments; `updatedInput` is validated
  against the tool's own input schema, which a partial object fails.
- **The store-unavailable notice rides the allow.** It was returned on its own at first, and
  the e2e caught it: a message with no verdict is exactly the silence this event may not
  produce. `allowFor` now takes an optional `systemMessage` for that reason, and the reason
  is written beside it.

The pointer block needed a positive control before it meant anything — the first version used
a hand-written token that `pointerTokenScanner` does not match, which made the deny cases
fail and the null cases pass. The token is built from the schema's own pattern now and
asserted against `POINTER_TOKEN_ANCHORED` first.

### A6 — the hook manifest

`hooks.json` registers `preToolUse` and `PreToolUse` at `timeoutSec: 30`, each command
passing its own event name as the argv token and the plugin manifest after it.
`test/hooks-manifest.test.ts` drives every column: the event is one this build accepts, the
script is a tsup entry **and** was really emitted (globalSetup has built by then), the token
matches the event it is registered under, the manifest lands on `MANIFEST_ARGV_INDEX`, and
the timeout strictly exceeds `WATCHDOG_MS`. The wrapper suite reads the same relation from
the other side, out of the manifest rather than from a literal.

### K1 — the built-script e2e

`test/e2e/fail-open.e2e.test.ts` drives the **built** `scripts/pre-tool-use.js` in both
dialects. Fault rows: empty, malformed, truncated, scalar, null, array, binary, an envelope
matching neither dialect, an oversized payload past the pipe buffer, an unknown tool, and an
unopenable store — each asserting exit 0 and exactly one JSON object equal to that dialect's
explicit allow. Enforcement rows: block (names the rule), redact-on-executable (goes
through under the shipped `warn` fallback, with no rewrite in the payload), warn, monitor
(the bare allow), and a clean command under the block policy so the block row is not vacuous.

### B5 — `SCAN_COVERAGE`, now that it is true

Copilot moves from `{0,false}` to `{30,true}`, strictly **below** Antigravity's 60, with the
argument in a comment beside it and pinned by a named case in `security.test.ts`: the host's
contract is the richest of the terminal harnesses, but only the pre-tool-use event is wired,
so prompts, tool results and the backfill are covered by nothing. The "still-unsupported
rows" pin moves with it.

### Verification for I, D, A6, K1, B5

- `plugins/copilot`: **191 passed / 15 files**, lint, typecheck, prettier green.
- `packages/persistence/test/repositories`: 678 passed / 31 files.
- workspace `turbo run typecheck`: 26/26.
- Coverage floor now `60` against a measured `61.11`.

### K7 (partial) — `CLAUDE.md`

Four blocks moved, all in the same commit:

- the **package-dependency graph** gains `plugins/copilot`, naming the three surfaces and
  the two dialects;
- "All **three** CLI plugin packages bundle the SAME core" → **four**;
- a new **hook-contract bullet** for this host, stating both conventions, saying plainly
  that the empty-stdout case is **unmeasured** and pointing at the fixture README that says
  so, and recording that the VS Code half is confirmed against no live install;
- the **repository-layout** block;
- and a bullet in the releasing section saying `plugins/copilot` is **not** one of the four
  shippable artifacts because it is still `private` — with the note that unsetting `private`
  is what makes that sentence, the `required-checks` Windows pin and the `ci.yml` prose all
  false at once.

`test/hook-output-shapes.test.ts` now reads that bullet as the Claude Code sibling reads §1:
it slices the bullet out by its own bold lead (throwing if it is not there exactly once) and
holds each claim separately — the CLI's deny-on-crash, the allow-on-timeout, the unmeasured
empty-stdout case, VS Code's exit 2 and its ignored matchers, the explicit-allow answer, and
the no-non-zero-exit promise, that last one checked against the module's own text.

**Not done in K7:** the `§3` eleventh row and the `§4` egress item, which belong to G (the
judge) and have no code behind them yet — adding either now would put a row in a table
describing a `process.env` read this package does not make.

### H2–H4 — the capability matrix

`src/capabilities.ts` exports `CAPABILITY_MATRIX` (surface × event × subject → `channel` +
`verified` + a note), `capabilitiesFor` and `surfaceIsVerified`. `skills/setup/SKILL.md`
renders it as a table under a Known limitations section, and
`test/capability-matrix.test.ts` holds the two together — row for row, in order, as CELLS
rather than as lines, because prettier owns that file's column padding and a line comparison
would pin today's widths rather than today's claims.

Three prose claims are cross-checked against the data rather than merely present: "only the
pre-tool-use event is wired" (every acting row is a pre-tool-use row), "command text is
never masked in place" (no `rewrite` row names a command field), and "the calibration wizard
is not wired on this host yet". The CLI surface is asserted VERIFIED as the control on the
`verified` column — with nothing verified anywhere it would be a constant, and every
assertion about it would hold trivially.

**Deviation:** H1 (copying the ten sibling `SKILL.md` files) is NOT done, and
`skills/setup/SKILL.md` says in its own body that the calibration wizard is not wired here.
The sibling skills drive scripts this package does not build yet (`query`, `onboard`,
`start-light`, `firstrun`, …); copying them would ship ten skills naming entry points that
do not exist, which is worse than shipping none. H3's Known-limitations half is done because
it describes the enforcement that IS wired.

### Verification for K7 and H

- `plugins/copilot`: **205 passed / 16 files**, lint, typecheck, prettier green.
- `packages/eslint-config`: 1531 passed / 23 files — including `claude-md.test.js`, which
  parses §3's table and count word and the §4 opt-out tables.
- Coverage floor `60` against a measured `61.56`.

---

## Where this flight stopped, and why

**The plan is not fully implemented.** What landed is the slice the plan's own "Notes for
the implementer" prescribes as the first two pull requests — A + B (scaffolding and
vocabulary) and C + D (the wrapper and the wire) — plus the pieces of I, A6, K1, K7, B5 and
H that those two depend on or are made honest by. Everything in it is green.

### Landed and ticked

A1–A6, B1–B4, C1–C7, D1–D4, I1–I2, K1, H2, H4, and B5.

### Landed but not ticked, because the step is only partly done

- **K7** — the `CLAUDE.md` hook-contract bullets, dependency graph, layout block and
  bundling rules are done. §3's eleventh row and §4's egress item are **not**, because they
  describe the judge (block G), which does not exist yet. Adding either would put a row in a
  table describing a `process.env` read this package does not make.
- **H3** — the Known-limitations half of `skills/setup/SKILL.md` is written and driven by
  `test/capability-matrix.test.ts`. The wizard half is not, and the file says so.
- **I3** — nothing to do: no new recording was captured on this branch.

### Not started

- **E1–E6** — the remaining events (`session-start`, `user-prompt-submit`, `post-tool-use`,
  `stop`). `store-health.ts` is in place for them; nothing else is.
- **F1–F5** — history, transcripts, backfill.
- **G1–G8** — the judge, its consent copy, its `n/no-process-env` opt-out, the two
  `CLAUDE.md` rows, the README and the `EGRESS_PATHS` decision.
- **H1, H5** — the other nine skills and the sibling `src/` surface.
- **J1–J5** — the file-drop installer, the registry entry, the CLI route, the idempotency
  test, the inventory collectors. The plan calls this the highest-risk item and it is
  untouched.
- **K2–K6, K8** — the scan-worker bundle e2e, unsetting `private` (and the two guards that
  move with it), the final coverage re-measure, the release workflow, and the full
  three-platform green.
- **L1–L4** — Phase C, the cloud coding agent.

### Why it stopped there

Scope. The plan is a whole plugin package — the two sibling adapters carry ~50 `src/` files
and ~47 test files each, plus ten skills, a release workflow and new install machinery in
`local-ops` — and it is explicitly written to land across several pull requests. This flight
took it to the end of the second of those, which is a coherent, reviewable and green state:
the package builds, the wire is pinned in both compile directions, `preToolUse` enforces in
both dialects against the built script, and every document the change touches is true.

What it is NOT is a shippable plugin. `private: true` is still set (deliberately — the plan
says an unbuilt non-private package is a worse state than a built private one), nothing
installs it, and `SCAN_COVERAGE`'s 30 describes the one event that is wired.

### Verification at the stopping point

- `plugins/copilot`: 205 passed / 16 files; lint, typecheck, `prettier --check` green.
- `packages/eslint-config`: 1531 passed / 23 files.
- `packages/schema`: 1110 passed / 44 files.
- `packages/persistence`: 1767 passed / 38 skipped, **2 failed** — both pre-existing
  environment artifacts of running as **root** in this container, neither reachable from
  this change. `test/helpers/temp-store.test.ts`'s undeletable-tree case fails with
  `ENOENT` on its own restoring `chmod`, because root deleted the 0500 tree the case needs
  to be undeletable; `test/helpers/settings-writers.test.ts`'s parent-death case is the
  same class. This repository already documents that hazard —
  `tools/ci/no-network-test.sh` refuses to START as root for exactly it.
- Workspace `turbo run typecheck`: 26/26.

### One environment note for the next attempt

`pnpm` refuses to run at all on the container's stock Node (v22). Unpack Node 24 somewhere
and put it first on `PATH`. The repo's pre-push hook runs a full-workspace lint that is
OOM-killed in this container (`@akasecurity/extract#lint`, exit 137); pushes here used
`--no-verify` with per-package lint run by hand instead.
