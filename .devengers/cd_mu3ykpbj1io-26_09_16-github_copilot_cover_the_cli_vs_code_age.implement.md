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
