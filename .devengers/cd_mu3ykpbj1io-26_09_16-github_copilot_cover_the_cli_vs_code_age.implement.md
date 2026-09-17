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
