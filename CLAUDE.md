# AI Traffic Control — Conventions for AI Agents

Read this before generating any code in this repository. These conventions are enforced by ESLint and CI — code that violates them will fail to merge.

AI Traffic Control (`ai-tc`, by AKA Security — the `aka` CLI and plugin names come from
the company) is a **local-first** security control plane for AI coding agents. The whole surface
runs on one machine with **no server, no Docker, and no database engine**: the Claude Code
plugin, the Codex CLI plugin, the Antigravity plugin, the browser extension (ChatGPT +
Claude.ai web chat, bridged over Chrome native messaging — no port, no listener), and the
`aka` CLI capture agent activity into a local SQLite store at `~/.aka/data/aka.db`, and the
web dashboard reads that same store directly. There is no
account and no AKA backend — nothing is sent to a service AKA runs. (Narrow outbound paths
do exist — the default-on update notice's `npm view` lookups, package-manager installs, the
opt-in `/aka:setup` calibration, which sends raw findings to the model API via the `claude`
CLI, and an attached machine's forwarding to a control plane the USER's organization runs —
enumerated in §4. "No AKA backend" stays true across all of them: `aka attach` names a
deployment the customer operates, not one AKA does.)

## Tech stack

- **Language:** TypeScript strict mode, ESM everywhere (`"type": "module"`)
- **Monorepo:** pnpm workspaces + Turborepo
- **Runtime:** Node.js 24+ (the CLI and plugin hooks use the built-in `node:sqlite` — no native dependency); `.nvmrc`, CI, and `@types/node` all track the Active LTS line, matching the `engines` floor
- **Local store:** SQLite via `node:sqlite`, wrapped by `@akasecurity/persistence`; the schema is defined with Drizzle in `@akasecurity/schema`
- **Validation:** Zod schemas in `@akasecurity/schema` — the single source of truth
- **Web dashboard:** Next.js 15 + React 19 (Server Components read the store; Server Actions mutate it)
- **Testing:** Vitest
- **Packaging:** the `aka` CLI and the Claude Code / Codex CLI / Antigravity plugins, published to npm as self-contained bundles

## Architecture principles

The long-form rules live under `conventions/`, one file per topic, and are read on
demand: open the file when you touch its area, not before. Each section keeps its original
numbered heading, and several CI guards parse those files, so edit a rule where it lives
and do not copy its text elsewhere. The one-paragraph versions below say when a file applies.

1. **Fail-open everywhere in the plugin** — a hook never breaks the user's session: every
   hook wraps `main()` in try/catch, then `process.exit(0)`, and writes nothing to stdout on
   failure. Emit a real opinion only through `emit()` and its `HookOutput` union; never emit
   `{ action: 'allow' }`. A field too large to scan in time is the one path that fails
   closed. Antigravity inverts the convention (silence is a deny). Read
   [fail-open.md](conventions/fail-open.md) before touching any hook entry or watchdog.
2. **Contracts before code** — `@akasecurity/schema` is the spine; add a Zod shape there
   first and consume its exported types rather than defining local ones. Agent ids come
   from the `HARNESS` / `SOURCE_TOOL` registries, spelled through a member, and tables over a
   vocabulary are annotated `Record<ThatVocabulary, …>`. Never use a TypeScript `enum`. See
   [contracts.md](conventions/contracts.md).
3. **`process.env` is off by default** — `n/no-process-env` is a CI failure; the permitted
   sites are one exact table, and a new site means updating it.
4. **No network calls** — the product talks to no AKA service. Only `@akasecurity/remote`
   (`src/http.ts`) may open a socket, and only for a machine attached to a deployment its
   own organization runs. Network primitives are banned by ESLint; the opt-out files are one
   exact table, file-scoped. Egress through child processes is enumerated there too. Both
   in [process-env-and-network.md](conventions/process-env-and-network.md); read it
   before adding any import of `node:http`/`https`/`net`, a `fetch`, or an `eslint-disable`.
5. **A scan that cannot be interrupted runs off the main thread** — `scan()` is synchronous,
   so a pulled or custom regex rule is pre-flighted and scanned in a worker under a deadline;
   the fast path (no such rule) must stay free. See
   [scan-isolation.md](conventions/scan-isolation.md) before changing the scanner,
   the quarantine, or the dashboard's folder scan.
6. **Every writer of `settings.json` takes its lock** — read-modify-write goes through
   `withFileLock` / `applyOnboarding`, with anything derived from the current file computed
   inside the lock. An administrative overlay is read, never written. See
   [settings-lock.md](conventions/settings-lock.md).
7. **A command spawned by bare name goes through the planner** — use `planBareCommand`
   (`@akasecurity/plugin-sdk/bare-command`); never build a shell command line from external
   text. See [bare-command.md](conventions/bare-command.md).

## Where the rest lives

| Topic | File |
| --- | --- |
| Dependency advisories and waivers; package dependency rules (the allowed import graph) | [dependencies.md](conventions/dependencies.md) |
| UI components, tonal tokens, time and locale rendering | [frontend.md](conventions/frontend.md) |
| Adding a workspace package (lint, tsconfig, vitest guards, checklist) | [new-package.md](conventions/new-package.md) |
| Releasing, release channels, the binary channel | [releasing.md](conventions/releasing.md) |
| Testing: coverage floors, benchmarks, store scale, guards, fixtures, Server Action and page tests | [testing.md](conventions/testing.md) |

Package dependency rule in one line: store-reading packages read the local SQLite store
through `@akasecurity/persistence` and never import an HTTP client or an ORM; Drizzle is
imported only by `@akasecurity/schema`; a forbidden import across a package wall is a defect.
The full graph is in `dependencies.md`.

Checks to run before a PR: `pnpm typecheck && pnpm lint && pnpm test`. Adding a package
or a lint target has a checklist in `new-package.md`; a CLI or plugin version bump is made
at release time, not in a feature PR.

## Detection rules

See `skills/write-detection-rule/SKILL.md`. A rule PR carrying fewer than 2 positive or
2 negative fixtures is rejected by CI — `packages/detections/test/engine.test.ts` asserts
the bar per rule, and each posture suite under `packages/detections/test/posture/` asserts
it for its own rules. Every one of them reads it from
`packages/detections/test/helpers/fixture-bar.ts`, so the number and its message live in
one place; the count is of DISTINCT cases, because a repeated fixture exercises nothing the
first one did not.

Any change to the `installed_packs` / `available_packs` **write semantics** must extend the
legacy-writers suite (`packages/persistence/test/repositories/legacy-writers.test.ts`) — it
replays frozen SQL from already-shipped binaries, which app-level guards cannot reach.

## Repository layout

```
cli/                  the `aka` CLI (self-contained npm bundle; ships the web-ui as a spawned Next server)
web-ui/               the OSS Next.js dashboard (Server Components read ~/.aka; Server Actions mutate it)
plugins/claude-code/  the Claude Code plugin (hooks + commands; self-contained npm bundle)
plugins/codex/        the Codex CLI plugin (hooks + skills; self-contained npm bundle)
plugins/antigravity/  the Antigravity plugin (hooks + skills; self-contained npm bundle)
plugins/copilot/      the GitHub Copilot plugin — the Copilot CLI, VS Code agent mode and
                      the cloud coding agent, one package over two payload dialects
plugins/browser-extension/  the Chrome extension for ChatGPT + Claude.ai web chat (MV3
                      content scripts + a native-messaging host; private — bundled into
                      the CLI by `bundle:extension`, installed via `aka extension install`)
packages/             the workspace libraries (schema · persistence · local-ops · detections ·
                      remote ·
                      extract · dashboard-ui · ui-kit · plugin-runtime · plugin-sdk · scanner …)
rules/                the built-in detection packs (rule JSON + fixtures)
skills/               agent skills (e.g. write-detection-rule)
tools/                repo tooling, never shipped: the installer one-liners and
                      the installer workspace package whose suite drives them end
                      to end, plus audit-gate (CI dependency-audit),
                      portability-gate (cross-platform test rules),
                      coverage-gate (per-PR diff coverage), and
                      package-manifests (renders the Homebrew formula, Scoop
                      manifest and VERSION file a binary release publishes,
                      from that release's own SHA256SUMS)
```

## Commit messages

Follow Conventional Commits: `feat:`, `fix:`, `chore:`, `test:`, `docs:`, `refactor:`. Enforced by commitlint on commit-msg.

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
`packages/persistence/src/test-fixtures/` — never shipped, because only a package's own
`test/` and `bench/` files import it and `src/index.ts` never re-exports it. That rule is
about DIRECTORIES rather than filename suffixes (`test/helpers/corpus.ts` is an importer
and is neither a `*.test.ts` nor a `*.bench.ts`), and
`packages/eslint-config/test/test-fixtures-imports.test.js` derives it from the tracked
tree — so a product importer fails CI rather than being caught in review. Two kinds live
there and they answer different questions: the
`seedSample*` datasets are FIXED rows shaped to exercise a read surface, while
`generate.ts` is a deterministic GENERATOR for the benchmark harness, because the store
sizes that matter there cannot live in git.

**Derive the importer set from import SPECIFIERS, never from filenames or a grep.** Both
mislead, in opposite directions. A grep for the directory name counts a file that merely
mentions it in a comment — `test/migrations.test.ts` does, and imports nothing from here,
which is how an earlier count of this set came out one too high. Filenames miss the other
way: a `*.bench.ts` reaching the fixtures through `test/helpers/corpus.ts` is a transitive
reader, not a direct one. Today no `*.bench.ts` imports the directory directly, and that
is a fact about the seam rather than a second rule — seeding needs the raw connection, and
`test-only-seam.test.js` classifies a `.bench.` file as shipped source. The two predicates
answer different questions and are deliberately not shared; do not collapse them into
"`bench/` may not import fixtures".

## Documentation

This repository is **public** (open source). Keep internal documentation out of it:
planning docs, decision records, roadmaps, and design docs are maintainer-internal and
do not belong in this tree. Only agent conventions (`CLAUDE.md`, `conventions/`, `skills/`) and the
top-level contributor docs (`README.md`, `CONTRIBUTING.md`) belong here.

## Comment & string hygiene

This repository is **public**. Shipped source must not contain internal narration:
design-doc/section/ADR/PR citations, team-member names, or other internal narration.
**Comments explain _what_ the code does, never the _why_ behind an internal decision.**
Keep prose factual and reader-facing; if you need to record rationale, put it in a commit
message — not in shipped comments or strings.

This is available to each package, and adopted per package: `comment-narration/no-process-narration`
in `@akasecurity/eslint-config` walks the comment table and refuses plan and spec paths, LLD
references, unit and task numbers, `§` section refs beside a plan cue, PR/issue and
review-response numbers, commit SHAs and dated decisions. Nothing consumes it yet — an adopting
package spreads it in its own `eslint.config.mjs` and passes `conventionsFile: 'CLAUDE.md'`, since
the rule's message names `AGENTS.md` by default and this repo's conventions live here. It is spread per package (like `noDrizzleImports`) rather than
folded into `base`, so a package adopts it in the change that clears its own backlog. Four
probes are deliberately narrow, because a ban that cries wolf gets a disable directive: a SHA must
carry a hex letter (a dated model-id suffix such as `-20241022` is not a SHA) and is skipped on a
frozen-artifact banner, where the SHA is the identity of what is pinned; a date must sit next to a
process cue (a fixture or retention date is not a decision); and a `§` must sit beside a plan cue,
because the shorthand inside a repo is the bare section number — an exemption list of standard
names left 40 false positives against 5 true ones over 1,812 files. Where a package has a
standing reason, `allowPatterns` exempts a comment and `disableProbes` switches off one probe —
both review-visible.
