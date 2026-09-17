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
