# AI Traffic Control — Conventions for AI Agents

Read this before generating any code in this repository. These conventions are enforced by ESLint and CI — code that violates them will fail to merge.

AI Traffic Control (`ai-tc`, by AKA Security — the `aka` CLI and plugin names come from
the company) is a **local-first** security control plane for AI coding agents. The whole surface
runs on one machine with **no server, no Docker, and no database engine**: the Claude Code
plugin and the `aka` CLI capture agent activity into a local SQLite store at
`~/.aka/data/aka.db`, and the web dashboard reads that same store directly. There is no
account and no AKA backend — nothing is sent to a service AKA runs. (A few narrow outbound
paths do exist — package-manager installs and the opt-in `/aka:setup` calibration, which
sends raw findings to the model API via the `claude` CLI — enumerated in §4.)

## Tech stack

- **Language:** TypeScript strict mode, ESM everywhere (`"type": "module"`)
- **Monorepo:** pnpm workspaces + Turborepo
- **Runtime:** Node.js 24+ (the CLI and plugin hooks use the built-in `node:sqlite` — no native dependency); `.nvmrc`, CI, and `@types/node` all track the Active LTS line, matching the `engines` floor
- **Local store:** SQLite via `node:sqlite`, wrapped by `@akasecurity/persistence`; the schema is defined with Drizzle in `@akasecurity/schema`
- **Validation:** Zod schemas in `@akasecurity/schema` — the single source of truth
- **Web dashboard:** Next.js 15 + React 19 (Server Components read the store; Server Actions mutate it)
- **Testing:** Vitest
- **Packaging:** the `aka` CLI and the Claude Code plugin, published to npm as self-contained bundles

## Architecture principles

### 1. Fail-open everywhere in the plugin

The plugin **must never break a user's Claude session**. Every hook handler wraps everything in try/catch and falls back to `{ action: 'allow' }`.

### 2. Contracts before code

`@akasecurity/schema` is the spine. The Zod schemas in `src/zod/` define every data boundary. Add shapes there before implementing them anywhere else.

**Do not create new types and interfaces — use the ones exported from `@akasecurity/schema` to the maximum extent.** Consumers (web-ui, CLI, plugin) import the schema types directly rather than redefining local "view-model" shapes or adapters. A new type is justified only when there is genuinely no schema equivalent (e.g. pure presentation descriptors like `{ label, icon, color }`). If a shape is missing, add it to `@akasecurity/schema/src/zod/` first, then consume it.

### 3. `process.env` is off by default

ESLint (`n/no-process-env`) forbids reading `process.env` across the workspace — a violation is a CI failure, not a warning. Four places genuinely need the host environment and opt out:

| Site                                      | Mechanism                         | Why                                         |
| ----------------------------------------- | --------------------------------- | ------------------------------------------- |
| `packages/plugin-sdk/src/provider.ts`     | file-scoped ESLint config         | LLM-provider resolution at SessionStart     |
| `cli/src/commands/dashboard.ts`           | inline `eslint-disable-next-line` | spawning the dashboard server               |
| `plugins/claude-code/src/backfill.ts`     | inline `eslint-disable-next-line` | resolving the transcript root               |
| `plugins/claude-code/src/triage/judge.ts` | inline `eslint-disable-next-line` | the judge subprocess must inherit PATH/auth |

Prefer a file-scoped config opt-out over an inline disable — an inline disable is invisible to anyone auditing the ESLint configs. Adding a fifth site means updating this table.

### 4. No network calls

The OSS product is **local-only**: it runs on Node + the SQLite store under `~/.aka` and talks to **no AKA service** — no account, no backend, no HTTP hop to anything AKA runs. A direct `fetch()` must never appear in OSS source. Network access happens **only through child processes**. In the first three, this repo chooses the program and its arguments; in the fourth it chooses neither:

1. `@akasecurity/local-ops` shelling out to package managers (`npm`/`claude`) for update-and-apply.
2. The Claude Code plugin's own `npm audit signatures` child process — run from inside the plugin's dependency closure (a plugin script or `@akasecurity/plugin-sdk`, since the plugin cannot import `@akasecurity/local-ops`).
3. The `/aka:setup` wizard's judge subprocess (`plugins/claude-code/src/triage/judge.ts`), which spawns `claude -p` and **sends findings to the model API** so it can rate false positives and severity. `runJudge` serializes a minimized projection (`toJudgePayload`), not the whole `TriageHit`: `rawMatch` (the raw, unmasked secret) crosses, along with `context` (a ±120-character window of the surrounding transcript text — see `plugins/claude-code/src/history/scan.ts` — re-masked so any _other_ detectable secret in the window does not cross raw) and `id` (a sequential counter the rubric requires the model to echo). `filePath` (the source transcript's path), `valueFingerprint` (an HMAC of the secret), and `keyVersion` are dropped before egress — a new `TriageHit` field is not disclosed to the model unless `toJudgePayload` and the disclosure copy are updated together. A large history is chunked, so this is several `claude -p` calls, not one. It runs only on the user's explicit opt-in during setup — a consent distinct from the historical-read grant, recorded as `modelJudgeConsent` and re-checked against `MODEL_JUDGE_PAYLOAD_VERSION` on every run, so widening the payload invalidates consents given for the old one. The grant is revocable under Settings, which stops future scans but cannot recall what was already sent. The subprocess asks the CLI to suppress its transcript (`CLAUDE_CODE_SKIP_PROMPT_HISTORY=1`), but that is transcript isolation, **not** network isolation — a copy of the raw values leaves the machine, because the whole point is to reach the model. Consent copy must state the payload, the egress, and that limit on revocation plainly (see `plugins/claude-code/commands/setup.md`); it must never be described as staying "inside an isolated subprocess."
4. **Git-style external subcommand dispatch** (`cli/src/lib/external-dispatch.ts`). `aka <name>` execs `aka-<name>` from the user's `PATH` when no built-in owns the name, inheriting the caller's environment and stdio. The child is resolved by name at call time — this repo does not bundle, depend on, verify or version-pin it — so its behaviour, including any network access, is outside what this codebase can describe. AKA Security ships one intended occupant, `aka-claude` from `claude-tools`, which launches a Claude Code profile and is network-bound by definition; the dispatch gives it no special status, and any other `aka-*` on `PATH` runs identically. A built-in always wins, so this can never shadow a shipped command, and the path is POSIX-only (disabled on win32). An allowlist or provenance check is a deliberate non-goal: the precondition for abuse is write access to a `PATH` directory, which already permits shadowing `aka` itself. The invariant that is enforced is that a built-in always wins.

These are the **shipped product's** egress paths. Repo CI additionally talks to the npm
registry: `.github/workflows/audit.yml` (via `tools/audit-gate`) runs `pnpm audit` on every
PR and daily, sending the workspace dependency graph — package names and versions,
including the `@akasecurity/*` workspace importers — to the registry's audit endpoint; it
also resolves and audits the published CLI's runtime dependency ranges with `npm` in a
temp dir, sending that (public-package) graph the same way. That is repository tooling,
not a product path; nothing a user installs performs it.

## Dependency advisories

CI gates every PR (and a daily run) on two audits via `tools/audit-gate`: `pnpm audit`
over `pnpm-lock.yaml`, and `npm audit` over an end-user resolution of the published
CLI's runtime `dependencies` (`--artifact` mode — coverage the workspace lockfile
cannot provide, since consumers re-resolve the published ranges and `pnpm.overrides`
do not reach them). A **high or critical** advisory in either fails the check, so a
new or bumped dependency that carries one will not merge. Fix a workspace hit by
upgrading, or by raising a floor in the root `pnpm.overrides` (the existing entries
there are exactly such floors); fix an artifact hit by raising the range in
`cli/package.json` — or, when the vulnerable copy is pinned by another package (e.g.
next's own pins), by bumping that package once upstream moves. Only when an advisory
has no fixed release reachable from the tree, add an **expiring** waiver to
`.github/audit-waivers.json`, scoped to the audit it applies to — format and process
in CONTRIBUTING.md ("Dependency advisories and waivers").
`pnpm.auditConfig.ignoreCves`/`ignoreGhsas` is not an approved suppression route: the
gate refuses to run while anything is muted there.

## Package dependency rules

The store-reading packages read the local SQLite store directly through
`@akasecurity/persistence`; they never reach for an HTTP client or an ORM at the app layer.
Keep these package boundaries intact — a forbidden import across a package wall is a defect.

```
@akasecurity/schema        → zod (core Zod contracts + the SQLite local-store & rule-registry schemas, defined with Drizzle)
@akasecurity/persistence   → node:sqlite, @akasecurity/schema
                     (SQLite adapter + read/view ports, plus the shared ~/.aka
                     layout/settings/fingerprint file I/O — NO fetch client, NO Drizzle)
@akasecurity/local-ops     → @akasecurity/schema, @akasecurity/persistence, @akasecurity/detections,
                     @akasecurity/plugin-sdk (repo-identity, project-file walkers, and posix
                     path normalization only)
                     (shared CLI/web-ui operations: update report + apply via npm/claude
                     child processes, the agent-plugin registry, the fs scan pipeline,
                     the project-inventory pass; network ONLY via package-manager
                     shell-outs — no fetch)
@akasecurity/detections    → @akasecurity/schema (pure rule engine; no I/O, no Node-API deps)
@akasecurity/extract       → (no dependencies; pure CSV/tabular parsing — `extractCsv`.
                     Consumed by @akasecurity/detections' tabular suite as a
                     dev-only dependency, so it crosses no runtime package wall)
@akasecurity/dashboard-ui  → @akasecurity/ui-kit, @akasecurity/schema (types, plus the pure
                     shared constants and formatters — no I/O)
                     (bundler-agnostic presentational views; props-driven, no data fetching)
@akasecurity/ui-kit        → @radix-ui/react-*, Tailwind (design-token UI primitives)

web-ui            → @akasecurity/persistence, @akasecurity/dashboard-ui, @akasecurity/ui-kit,
                     @akasecurity/schema, @akasecurity/detections, @akasecurity/local-ops
                     (Next.js dashboard; reads the local store in Server Components,
                     mutates via Server Actions — no HTTP client, no auth)
cli               → @akasecurity/schema, persistence, local-ops, detections (the `aka` command;
                     ships the web-ui as a spawned Next server)

# Plugin
plugins/claude-code → @akasecurity/plugin-runtime, plugin-sdk
@akasecurity/plugin-runtime → @akasecurity/plugin-sdk, persistence, schema
@akasecurity/plugin-sdk     → @akasecurity/detections, persistence, schema
                     (provider resolution for the session-root snapshot reads the host env
                     directly at SessionStart), ignore (gitignore semantics for
                     the SessionStart project-file walk)
@akasecurity/scanner        → @akasecurity/plugin-runtime, plugin-sdk, ignore (node:fs only; no fetch, no process.env)
```

**Cross-cutting rules:**

- No `process.env` reads except the few spots that explicitly opt out of `n/no-process-env` (the plugin's provider resolution, the CLI spawning the dashboard).
- No `fetch()` anywhere in the OSS surface — it makes no network calls. Every store-reading package (`persistence`, `local-ops`, `dashboard-ui`, `ui-kit`, `detections`, `scanner`, `web-ui`, `cli`) reads the local store directly.
- Drizzle is imported **only** by `@akasecurity/schema`, which uses it to _define_ the local-store and registry schemas. Packages that read the store do so via `node:sqlite` through `@akasecurity/persistence` — they must not import Drizzle.
- The graph above lists **runtime** edges. Test suites may additionally take `@akasecurity/plugin-sdk` as a **dev-only** dependency for fixture seeding — the bundled detection packs (`bundledDetections()` / `registerBundledPacks`) live only there, so a test that must seed `installed_packs` or the engine registry needs it. Both `cli` and `web-ui` do this in their exception tests. A dev-only test dependency is not a runtime package-wall crossing.

## Comment & string hygiene

This repository is **public**. Shipped source must not contain internal narration:
design-doc/section/ADR/PR citations, team-member names, or other internal narration.
**Comments explain _what_ the code does, never the _why_ behind an internal decision.**
Keep prose factual and reader-facing; if you need to record rationale, put it in a commit
message — not in shipped comments or strings.

## Frontend UI components

Shared, reusable UI **primitives** live in `packages/ui-kit` (`@akasecurity/ui-kit`). Shared,
reusable **presentational composites** (stat tiles, charts, the security widget views)
live in `packages/dashboard-ui` (`@akasecurity/dashboard-ui`). App-specific composition and data
wiring live in the app (e.g. `web-ui/app`).

`@akasecurity/dashboard-ui` is **bundler-agnostic and props-driven**: it depends only on
`@akasecurity/ui-kit` + `@akasecurity/schema` types and does **no data fetching**, so the Next.js
dashboard (`web-ui`, via `@akasecurity/persistence` Server Components) can feed it. It imports no
SVG assets via a bundler loader (svgr) — icons are inlined or taken as an `IconComponent`
prop — and marks interactive components with `'use client'`. Put a widget's presentation
here (a dumb `*View`) and its data-fetching wrapper in the app.

When adding a **new reusable component** to `@akasecurity/ui-kit`, follow the shadcn/ui pattern:

- **Build on Radix UI primitives** (`@radix-ui/react-*`) for anything interactive or with
  accessibility/focus/positioning concerns (popover, dialog, dropdown, tooltip, select, etc.).
  Do **not** hand-roll outside-click, focus traps, or anchored positioning — Radix already
  solves these. Add the matching `@radix-ui/react-*` package rather than reinventing it.
- **Expose a compound, composable API** (`Card` / `CardHeader` / `CardTitle` / `CardContent`…),
  not a monolithic prop-driven component. Each part is a plain function component that spreads
  native props, merges `className` via `cn`, and carries a `data-slot="…"` attribute.
  On React 19, **`ref` is a regular prop** — type props with `ComponentPropsWithRef<'div'>` (or
  `ComponentPropsWithRef<typeof RadixPrimitive.X>`) and let `ref` flow through `...props`. Do **not**
  use `forwardRef` (deprecated in React 19). See `card.tsx`, `button.tsx`, `popover.tsx`.
- **Style with Tailwind + design tokens** from `theme.css` (`bg-surface`, `text-text-2`,
  `border-border`, severity/`ok` tokens…). Use `cva` for variants (see `button.tsx`,
  `badge.tsx`). No hardcoded hex — add a token to `theme.css` if one is missing.
- Each component is its own file under `packages/ui-kit/src/`, exported from `src/index.ts`.

## Detection rules

See `skills/write-detection-rule/SKILL.md`. A rule PR without fixtures is rejected by CI.

Any change to the `installed_packs` / `available_packs` **write semantics** must extend the
legacy-writers suite (`packages/persistence/test/repositories/legacy-writers.test.ts`) — it
replays frozen SQL from already-shipped binaries, which app-level guards cannot reach.

## Repository layout

```
cli/                  the `aka` CLI (self-contained npm bundle; ships the web-ui as a spawned Next server)
web-ui/               the OSS Next.js dashboard (Server Components read ~/.aka; Server Actions mutate it)
plugins/claude-code/  the Claude Code plugin (hooks + commands; self-contained npm bundle)
packages/             the workspace libraries (schema · persistence · local-ops · detections ·
                      extract · dashboard-ui · ui-kit · plugin-runtime · plugin-sdk · scanner …)
rules/                the built-in detection packs (rule JSON + fixtures)
skills/               agent skills (e.g. write-detection-rule)
tools/                repo tooling: installer one-liners + the audit-gate workspace
                      package (the CI dependency-audit gate; never shipped)
```

## Adding a new workspace package

1. Create `packages/<name>/package.json` with `"name": "@akasecurity/<name>"`
2. Extend `../../tsconfig.base.json`
3. Add an `eslint.config.mjs` extending `@akasecurity/eslint-config`, and spread
   `...rootConfigFiles` **after** the block that turns `projectService` on. Root config
   files sit outside the tsconfig `include`, so the type-aware parser rejects them
   outright (`was not found by the project service`) and reports nothing else about
   them; that block drops the type-aware rules for `*.config.*` at the package root so
   they lint. Every network ban is syntactic and still fires.
4. Export from `src/index.ts`
5. Add `"lint"` and `"typecheck"` scripts — the `lint` script must run `eslint` over
   **every directory the package ships code in and every lintable file at its root**,
   whatever they are named (a bare `.` counts; naming individual files counts only for
   those files, not for the directory they sit in). Turbo silently skips a package with
   no `lint` script, so a config nothing points ESLint at enforces nothing. `*.config.*`
   is the standing target for the build and tooling config; name any other root file
   explicitly (see `web-ui`'s `middleware.ts`). A `scripts/` dir of **hand-written
   (git-tracked)** scripts needs its own `eslint.scripts.config.mjs` plus a second pass
   (`eslint --no-config-lookup -c eslint.scripts.config.mjs scripts`) — a generated
   `scripts/` dir (the plugin's bundled hooks) is build output and is exempt.
6. Add the package name to `EXPECTED_WORKSPACE_PACKAGE_NAMES` in
   `packages/eslint-config/test/effective-config.test.js`. That pinned list only
   forces a human to notice the new package — what actually stops it shipping
   unguarded are the assertions next to it (a missing config, a config that never
   extends the shared one, a `lint` script that misses a directory or a root file, a
   root file the linter cannot parse).

## Commit messages

Follow Conventional Commits: `feat:`, `fix:`, `chore:`, `test:`, `docs:`, `refactor:`. Enforced by commitlint on commit-msg.

## Releasing (CLI / plugin versioning)

Both shippable artifacts are **self-contained bundles of the workspace** — their `tsup.config.ts`
sets `noExternal: [/^@akasecurity\//]`, so every `@akasecurity/*` package they use is inlined into
the published output (the user's machine has no `node_modules`). So a change to a _bundled_ package
changes the shipped artifact **even when the app's own `src/` is untouched**:

- **`plugins/claude-code`** bundles `@akasecurity/plugin-runtime` + `plugin-sdk` and everything they
  pull in — `@akasecurity/schema`, `persistence`, `detections`. A change to any of
  those changes the plugin's `scripts/*.js`.
- **`cli`** bundles the same `@akasecurity/*` packages **and** ships the OSS web-ui
  (`web-ui` is `external` to the CLI JS but copied in by `prepack`'s `bundle:web-ui` and
  spawned as a separate Next server). So a web-ui change — or any bundled-package change — changes the CLI.

When a change touches the web-ui or any bundled package and the user wants to publish:

1. **Ask the user the release type first** — major, minor, patch, or pre-release — before touching
   any version.
2. **Bump every affected artifact** accordingly:
   - web-ui / `local-ops` / `dashboard-ui` / `ui-kit` change → `cli` (bundled into the CLI JS
     and/or the web-ui it ships; the plugin bundles none of these).
   - `schema` / `persistence` / `plugin-runtime` / `plugin-sdk` / `detections`
     change → **both** `cli` **and** `plugins/claude-code` (both bundle them).
   - The CLI and plugin normally move together on one shared version line.
3. Keep `plugins/claude-code/.claude-plugin/plugin.json` **in sync** with
   `plugins/claude-code/package.json` (identical version) whenever the plugin is bumped.

Versions are bumped by hand in a `chore(release):` commit (no changesets). The current pre-release
line is `0.0.2-alpha.N` — a pre-release bump increments `N`.

### Binary (SEA) channel — `bin-v*`

The `aka` CLI also ships as a self-contained **Standalone Executable Application (SEA)** — a native
binary that embeds the Node runtime, so end users need neither Node nor npm. This is a **separate
release channel** from the `cli-v*` npm publish:

- **Trigger:** push a tag `bin-v<version>`. It must equal `cli/package.json`'s version —
  `release-binaries.yml` gates on it and fails the release on a mismatch. `workflow_dispatch` runs a
  build-only dry run (no Release).
- **Build:** `release-binaries.yml` builds the SEA on native runners per platform (no cross-compile)
  — `darwin-arm64`, `linux-x64`, `linux-arm64`, `win32-x64` — via `build:sea` → `bundle:web-ui` →
  `package:sea` → `archive:sea`.
- **Assets:** `aka-<version>-<triple>.tar.gz` (`.zip` on Windows) plus an aggregated `SHA256SUMS`.
  The `tools/installer/` one-liners verify the download against it, fail-closed.
- **`bin-latest`:** on success the workflow force-moves `bin-latest` to the release commit; the
  installer one-liners (`install.sh`/`install.ps1`) are fetched from `bin-latest`, not `main`.
- `cli-v*` (npm) and `bin-v*` (binary) are **independent** — a binary release needs no npm publish
  and vice versa, though they normally share one version line.

## Running locally

No server, no Docker, no database engine — just Node and the local SQLite store.

```bash
pnpm setup        # install dependencies + git hooks (pnpm install && lefthook install)
pnpm dev          # run the workspace dev tasks via Turbo

# Or exercise the CLI directly against your ~/.aka home:
pnpm --filter @akasecurity/cli dev -- init
pnpm --filter @akasecurity/cli dev -- dashboard   # launches the Next.js web-ui over ~/.aka/data
```

Everything AKA owns lives under `~/.aka` — `settings/settings.json` (preferences) and
`data/aka.db` (the SQLite store: events, findings, policies). To start over, remove `~/.aka`
and run `aka init` again. There is **no demo/sample data anywhere** (removed by product
decision) — dashboard pages render only real data; do not add ad-hoc seeding. The rich
sample datasets survive only as repository test fixtures in
`packages/persistence/src/test-fixtures/` (imported by `*.test.ts` only — never shipped).

## Documentation

This repository is **public** (open source). Keep internal documentation out of it:
planning docs, decision records, roadmaps, and design docs are maintainer-internal and
do not belong in this tree. Only agent conventions (`CLAUDE.md`, `skills/`) and the
top-level contributor docs (`README.md`, `CONTRIBUTING.md`) belong here.

## Testing

```bash
pnpm test                                    # all workspaces
pnpm test --filter @akasecurity/detections   # just the detection engine + fixtures
pnpm test --filter @akasecurity/persistence  # just the local-store adapter + repositories
```

Never mock `node:sqlite` or the filesystem — every store test runs against a real
database in a real temp dir, which is what catches real SQLite semantics.

`packages/persistence/test/helpers/` holds the shared store harness. Tests **in this
package** import it rather than re-rolling the `mkdtempSync` + `openLocalDatabase` +
cleanup dance; it is not reachable across a package wall, so store tests in `cli`,
`local-ops`, `plugin-runtime`, `plugins/claude-code` and `web-ui` still roll their own.

- `withTempStore(fn)` / `useTempStore(prefix)` — a disposable `~/.aka` (`settings/` +
  `data/`) whose handles are closed and tree removed for you. Use `useTempStore` when the
  suite shares setup across hooks, `withTempStore` when one test body owns the store. An
  async body is awaited before teardown.
- `withTwoWriters(fn)` / `withWriters(n, fn)` — N independent `LocalDatabase` handles on
  one file, the shape the product runs in (hooks, CLI and dashboard share `aka.db` with
  only WAL and `busy_timeout` between them).
- `fault-injection.ts` — `corruptStore`, `readOnlyStore` and `lockStore`, plus the
  `SQLITE_*` result codes, `sqliteErrcode()` and `primaryCode()`. Each injector produces a
  real error code from the real engine and refuses to run rather than take effect
  vacuously — an absent store, a live handle. Where the platform or the privilege decides
  instead of the helper, `readOnlyStore` reports it as `effective: false` and **the caller
  must gate**: `if (!readOnly.effective) ctx.skip(reason)`. Pass the store's `onCleanup` to
  any injector that has to be undone before the tree can be removed, and the store itself
  to any that needs no live connection.
  `fillStore` is in the same file but **not yet a peer of the other three**: the page cap
  is connection-scoped and `LocalDatabase` exposes no raw handle, so it can only reach
  `node:sqlite`, not the repository writes built on it. It waits on a raw-handle seam.
- `assertNoOpenTransaction(db)` — a fault that leaves a transaction open is worse than the
  fault; assert this after injecting one. It reads `db.isTransaction` rather than probing
  with a transaction of its own, so it cannot disturb the handle it is inspecting.

Assert the result code, not an error message or an elapsed time — Windows CI runs several
times slower, and a timing assertion there is a flake. Compare with `primaryCode()`:
`errcode` carries the **extended** code, so `SQLITE_READONLY` also arrives as
`SQLITE_READONLY_DIRECTORY`. Do not add vitest `retry`.

Where a platform or a privilege makes an assertion meaningless, use `ctx.skip(reason)`.
An early `return` reports as a pass, which is the failure mode the store harness exists
to remove. Some older suites in this package still use
`if (process.platform === 'win32') return;` — leave them be unless you are already
changing that test for another reason, and do not convert a neighbour in passing.

### Testing a web-ui Server Action

A Server Action runs against the real store like any other test here, but four setup
steps are required before the first one will run at all, and **missing any of them
produces a failure that looks nothing like its cause**. `web-ui/test/actions/exceptions.test.ts`
is the worked example.

1. **Redirect the home dir** by mocking `node:os` and overriding `homedir()`. The action
   resolves `~/.aka` from it, and `n/no-process-env` rules out an env override, so this is
   the only seam. Set it through a `vi.hoisted()` box so `beforeEach` can point it at a
   fresh `mkdtempSync` dir per test.
2. **Alias `server-only` to an empty module** in `web-ui/vitest.config.ts` — `app/lib/db.ts`
   imports it, and the real package throws at import time outside a React Server bundler.
   Already wired; a new suite needs no change.
3. **Mock `next/cache`** — a mutating action calls `revalidatePath()`, which needs a Next
   render context that does not exist under vitest.
4. **Close and drop the memoised DB handle** on `globalThis` (`app/lib/db.ts` keeps it at
   `__akaDb` across requests and HMR reloads) in both `beforeEach` and `afterEach`, or the
   next test reads the **previous** test's temp store. Reset it again mid-test after any
   direct write through a second handle, so the action reopens and sees it.

Seed whatever snapshot the action reads before calling it — anything scanning a value needs
`installed_packs` populated via `recordInventory(bundledDetections())`, because the action
scans against the **DB snapshot**, not the engine's process-global registry.
`@akasecurity/plugin-sdk` is a **dev-only** dependency of `web-ui` for exactly this, which
is not a runtime package-wall crossing.

An at-rest leak scan must read **every file in the data dir**, not `aka.db` plus a
hardcoded `-wal`/`-shm` pair. This is not a corner case: a migration leaves an
`aka.db.pre-drop.<ts>.bak` — a byte-for-byte copy of the pre-migration store — in that
directory on **every** run, and it is around 47% of the bytes there, so a name-list reader
misses more of the store than a `-wal` pair ever covered. On top of that SQLite writes an
`aka.db-journal` instead of the WAL pair wherever WAL silently no-ops (see `dbSidecars` in
`packages/persistence/src/paths.ts`), and the foreign-lineage reset leaves its own `.bak`.
`web-ui/test/helpers/store-bytes.ts` is that reader; import it rather than re-rolling one.
Bind one call and assert against it — the positive control and the absence check must
describe the same bytes, not two independent reads. Two rules keep it honest, because an
empty read contains no secret and so passes every `not.toContain` vacuously: keep the
**positive control** — assert a value that **is** expected on disk before asserting the raw
is absent — and **never swallow a failed read**. Only a sibling's `ENOENT` is tolerable (an
atomic write's `.tmp` vanishing mid-scan); a permission denial or a Windows sharing
violation on `aka.db` must throw.

Assert a raw value is absent from an **error** run by run, not whole. `not.toContain(value)`
stays green if a branch echoes a _truncated_ value, which is still a live credential's
prefix. `expectNoEchoOf` is the **required form for every error assertion in a suite that
already defines it** — today `web-ui/test/actions/exceptions.test.ts` and
`plugins/claude-code/test/triage/judge.test.ts` — including the ones a newly covered action
or seam brings with it; a plain `not.toContain(rawValue)` on an error is a defect, not a
style choice. It is not reachable across a package wall, so a third suite that needs it
copies it rather than importing it, and copies the `expect(value).toBeDefined()` guard with
it — without that guard an `undefined` message satisfies the loop vacuously.
This applies to a **raw value** in an **error** only. At-rest and grant-shape assertions
stay whole-value, because `maskMatch` deliberately keeps a fragment visible and that
fragment is stored on purpose; and an assertion that some non-secret string is absent — an
internal error-class name, say — is a different property that `expectNoEchoOf` does not
express.

Assert against the value **that call supplied**, never a module constant the case does not
send. A case driven with an inert literal and asserted against a shared `VALUE` cannot fail
however the branch is worded, so it stays green while the branch echoes the live value it
was handed. Name each case's own inputs. This is the same family as the two rules above: an
absence assertion is only worth its green if it could have gone red — so before trusting a
new one, break the property it claims to guard, re-run, and treat a still-green suite as a
defect in the test.
