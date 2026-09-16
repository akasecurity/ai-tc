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
