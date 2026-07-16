# AI Traffic Control — Conventions for AI Agents

Read this before generating any code in this repository. These conventions are enforced by ESLint and CI — code that violates them will fail to merge.

AI Traffic Control (`ai-tc`, by AKA Security — the `aka` CLI and plugin names come from
the company) is a **local-first** security control plane for AI coding agents. The whole surface
runs on one machine with **no server, no Docker, and no database engine**: the Claude Code
plugin and the `aka` CLI capture agent activity into a local SQLite store at
`~/.aka/data/aka.db`, and the web dashboard reads that same store directly. Nothing leaves
the machine — there is no account, no network hop, and no backend to stand up.

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

ESLint (`n/no-process-env`) forbids reading `process.env` across the workspace — a violation is a CI failure, not a warning. The few places that genuinely need the host environment (the plugin's LLM-provider resolution, the CLI spawning the dashboard server) opt out explicitly in their own ESLint config.

### 4. No network calls

The OSS product is **local-only**: it runs on Node + the SQLite store under `~/.aka` and talks to **no AKA service** — no account, no backend, no HTTP hop. A direct `fetch()` must never appear in OSS source. The only network access is `@akasecurity/local-ops` shelling out to package managers (`npm`/`claude`) for update-and-apply.

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
                     @akasecurity/plugin-sdk (repo-identity + project-file walkers only)
                     (shared CLI/web-ui operations: update report + apply via npm/claude
                     child processes, the agent-plugin registry, the fs scan pipeline,
                     the project-inventory pass; network ONLY via package-manager
                     shell-outs — no fetch)
@akasecurity/detections    → @akasecurity/schema (pure rule engine; no I/O, no Node-API deps)
@akasecurity/dashboard-ui  → @akasecurity/ui-kit, @akasecurity/schema (types)
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
legacy-writers suite (`packages/persistence/src/repositories/legacy-writers.test.ts`) — it
replays frozen SQL from already-shipped binaries, which app-level guards cannot reach.

## Repository layout

```
cli/                  the `aka` CLI (self-contained npm bundle; ships the web-ui as a spawned Next server)
web-ui/               the OSS Next.js dashboard (Server Components read ~/.aka; Server Actions mutate it)
plugins/claude-code/  the Claude Code plugin (hooks + commands; self-contained npm bundle)
packages/             the workspace libraries (schema · persistence · local-ops · detections ·
                      dashboard-ui · ui-kit · plugin-runtime · plugin-sdk · scanner …)
rules/                the built-in detection packs (rule JSON + fixtures)
skills/               agent skills (e.g. write-detection-rule)
```

## Adding a new workspace package

1. Create `packages/<name>/package.json` with `"name": "@akasecurity/<name>"`
2. Extend `../../tsconfig.base.json`
3. Add an `eslint.config.mjs` extending `@akasecurity/eslint-config`
4. Export from `src/index.ts`
5. Add `"lint"` and `"typecheck"` scripts

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
