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

The OSS product is **local-only**: it runs on Node + the SQLite store under `~/.aka` and talks to **no AKA service** — no account, no backend, no HTTP hop to anything AKA runs. A direct `fetch()` must never appear in OSS source.

ESLint enforces that across the workspace — a violation is a CI failure, not a warning. Four rules carry it (`no-restricted-globals`, `no-restricted-properties`, `no-restricted-imports`, `no-restricted-syntax` — all defined in `packages/eslint-config/src/index.js`), banning:

- the network globals `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `WebTransport`, both bare and hung off a container (`globalThis.`/`window.`/`self.`/`global.`), plus `navigator.sendBeacon`;
- the modules `http`, `https`, `http2`, `net`, `dgram`, `tls`, `dns`, `dns/promises` (each in both the `node:`-prefixed and bare form) and the clients `axios`, `undici`, `got`, `node-fetch` (including their subpaths), in the static **and** the dynamic (`import()`/`require()`) form.

Five files carry a genuine local-only opt-out:

| Site                                                                                                            | Allowed specifier                                      | Why                                                                                                                                                                                            |
| --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cli/src/commands/dashboard.ts` (via `cli/eslint.config.mjs`)                                                   | `node:net`                                             | `isPortFree()` binds a probe server on 127.0.0.1 to find a free port before launching the dashboard — a local bind                                                                             |
| `cli/scripts/smoke-dashboard.mjs` (via `cli/eslint.scripts.config.mjs`)                                         | `node:http`                                            | the CI smoke test polls the launched dashboard over loopback to confirm it came up                                                                                                             |
| `test/setup/no-network.ts` (via `eslint.root.config.mjs`)                                                       | `node:net`, `node:dgram`, `node:dns`                   | the vitest no-network guard wraps connect/send/resolve on all three transports to refuse non-loopback egress                                                                                   |
| `tools/ci/egress-probe.mjs` (via `eslint.root.config.mjs`)                                                      | `node:net`                                             | the CI egress probe opens a TCP socket to a loopback listener before trusting a failed connect                                                                                                 |
| `packages/eslint-config/test/no-network-runtime.test.js` (via `packages/eslint-config/eslint.guard.config.mjs`) | `node:net`, `node:dgram`, `node:dns`, `fetch` (inline) | the runtime half of the no-network guarantee imports the three transports to drive real connect/send/resolve calls against the patched guard; its one real `fetch()` carries an inline disable |

All are **file-scoped**, never package-wide, and drop the static and dynamic bans together (`noNetworkImports` + `noNetworkSyntax`) so the exception holds whichever import form the file uses; every other network module stays banned in those same files. The one **global** opt-out — the runtime suite's deliberate `fetch()`, marked `fetch` (inline) above — is an inline `eslint-disable`, not a config `allow`, because `noNetworkGlobals()` (unlike its import/syntax siblings) takes no `allow` option, so §3's preference for a config opt-out cannot be met for a global today. It is pinned instead by the raw-guard measure in `no-network-runtime.test.js` (which lints with inline config **off**, so it sees the disabled `fetch` and would catch a second one), not by the `DOCUMENTED_OPT_OUTS` audit, which reads `no-restricted-imports` paths and structurally cannot see a global. Adding another opt-out site means updating this table.

**Which configs that audit reads is derived, not globbed.** An ESLint config enforces
something exactly when a `lint` script points ESLint at it, so `no-network.test.js` walks the
eslint invocations a green `pnpm lint` really runs — every `-c` / `--config` / `--config=`
target, plus, for an invocation carrying none, the config ordinary flat-config lookup finds
from the directory that invocation runs in (asked of ESLint's own `findConfigFile`, not
modelled). A filename glob was the earlier answer and is a hole one rename wide: ESLint
honours `-c eslint.extra.config.js` exactly like the two conventional names, so a third
config was referenced by the lint script, applied on every pass, and inspected by nobody —
while the suite's own test count went _up_, because the extra invocation generates more probe
targets elsewhere. Two consequences for anyone adding a config:

- **Name it anything and it is still audited** — but an opt-out in it must then appear in
  `DOCUMENTED_OPT_OUTS` and in the table above, exactly as for the conventional names.
- **A config no invocation runs is a failure, not a no-op.** Dead config enforces nothing
  while reading like a lint surface, so the audit differences the tree's `*eslint*.config.*`
  files against the derived set and names anything left over. Wire it into a `lint` script or
  delete it.

The reader itself — which invocations a green run makes, which config each runs under, and
which paths each covers — is one shared module (`packages/eslint-config/test/helpers/`), used
by both that audit and the per-package lint-coverage check in `effective-config.test.js`. Two
readers of one shell string would be free to disagree about what runs, which is how a file
ends up covered by one guard and audited by neither.

Network access happens **only through child processes**. In the first three, this repo chooses the program and its arguments; in the fourth it chooses neither:

1. `@akasecurity/local-ops` shelling out to package managers (`npm`/`claude`) for update-and-apply.
2. The Claude Code plugin's own `npm audit signatures` child process — run from inside the plugin's dependency closure (a plugin script or `@akasecurity/plugin-sdk`, since the plugin cannot import `@akasecurity/local-ops`).
3. The `/aka:setup` wizard's judge subprocess (`plugins/claude-code/src/triage/judge.ts`), which spawns `claude -p` and **sends findings to the model API** so it can rate false positives and severity. `runJudge` serializes a minimized projection (`toJudgePayload`), not the whole `TriageHit`: `rawMatch` (the raw, unmasked secret) crosses, along with `context` (a ±120-character window of the surrounding transcript text — see `plugins/claude-code/src/history/scan.ts` — re-masked with `maskText`, which scans the **bundled** packs rather than the installed set — coverage is still complete because `buildTriageHit` has already redacted every other finding from the full-ruleset scan, and this hit's own value is masked here where it appears in the window; `rawMatch` is therefore the only raw value that crosses), `id` (a sequential counter the rubric requires the model to echo), and the non-sensitive scoring labels `ruleId`, `category`, `severity`, `maskedMatch` and `confidence`. `filePath` (the source transcript's path), `valueFingerprint` (an HMAC of the secret), and `keyVersion` are dropped before egress — a new `TriageHit` field is not disclosed to the model unless `toJudgePayload` and the disclosure copy are updated together. A large history is chunked, so this is several `claude -p` calls, not one. It runs only on the user's explicit opt-in during setup — a consent distinct from the historical-read grant, recorded as `modelJudgeConsent` and re-checked against `MODEL_JUDGE_PAYLOAD_VERSION` on every run, so widening the payload invalidates consents given for the old one. `historicalAccess` gates the READ only — a `full` grant authorizes no egress by itself, and no consent surface may imply that it does. Both grants are revocable under Settings, where **Historical access** and **Model-judge consent** are separate controls; revoking stops future scans but cannot recall what was already sent. The subprocess asks the CLI to suppress its transcript (`CLAUDE_CODE_SKIP_PROMPT_HISTORY=1`), but that is transcript isolation, **not** network isolation — a copy of the raw values leaves the machine, because the whole point is to reach the model. Consent copy must state the payload, the egress, and that limit on revocation plainly; it must never be described as staying "inside an isolated subprocess." Four surfaces carry that copy and move together: `plugins/claude-code/commands/setup.md`, the `[^egress]` footnote in each of the two READMEs, and the Settings copy in `packages/dashboard-ui/src/settings/WorkspaceSettingsFormView.tsx`.
4. **Git-style external subcommand dispatch** (`cli/src/lib/external-dispatch.ts`). `aka <name>` execs `aka-<name>` from the user's `PATH` when no built-in owns the name, inheriting the caller's environment and stdio. The child is resolved by name at call time — this repo does not bundle, depend on, verify or version-pin it — so its behaviour, including any network access, is outside what this codebase can describe. AKA Security ships one intended occupant, `aka-claude` from `claude-tools`, which launches a Claude Code profile and is network-bound by definition; the dispatch gives it no special status, and any other `aka-*` on `PATH` runs identically. A built-in always wins, so this can never shadow a shipped command, and the path is POSIX-only (disabled on win32). An allowlist or provenance check is a deliberate non-goal: the precondition for abuse is write access to a `PATH` directory, which already permits shadowing `aka` itself. The invariant that is enforced is that a built-in always wins.

These are the **shipped product's** egress paths. Repo CI additionally talks to the npm
registry: `.github/workflows/audit.yml` (via `tools/audit-gate`) runs `pnpm audit` on every
PR and daily, sending the workspace dependency graph — package names and versions,
including the `@akasecurity/*` workspace importers — to the registry's audit endpoint; it
also resolves and audits the published CLI's runtime dependency ranges with `npm` in a
temp dir, sending that (public-package) graph the same way. That is repository tooling,
not a product path; nothing a user installs performs it.

**Three gates enforce this, and they cover different things.** Losing track of which is
which is how "enforced by ESLint and CI" becomes a claim nobody has checked:

| Gate                                          | Catches                                             | Cannot see                                                                     |
| --------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------ |
| The ESLint ban (`@akasecurity/eslint-config`) | A network primitive **written** into source         | A transitive dependency, a non-literal `import()`; a file no lint pass targets |
| `test/setup/no-network.ts` (every vitest run) | A non-loopback connect **called** at test time      | A child process — it has its own copy of `node:net`                            |
| The `No-network` CI job (`ci.yml`)            | Anything in the process tree, subprocesses included | A path the suite never executes; it is Linux-only                              |

The first one is only as wide as the files something points ESLint at, which is why
coverage is derived and guarded rather than remembered — every package's source dirs and
root files, and every lintable file belonging to no package at all (see "Adding a new
workspace package", step 5). The middle one is a vitest `setupFiles` entry every package
wires (see [Testing](#testing)); the last runs the whole suite inside a loopback-only
network namespace via `tools/ci/no-network-test.sh`, and fails if it cannot first prove
egress really is blocked (`tools/ci/egress-probe.mjs` is that proof — it connects to its
own loopback listener before trusting a failed connect, so a probe that cannot reach
anything is never mistaken for an absent network).

**What none of the three sees** is code no test runs. All of them observe either source
text or an executed call, so an untested path can still reach out — which is why the
gate table's third row says "a path the suite never executes" rather than "nothing". The
packaged artifact is the other uncovered surface: nothing here installs the published
tarball and exercises it under a block. Note also that the three gates scope to the
**product** and to `ci.yml`: `audit.yml` reaches the registry on purpose, as above, and
runs in its own workflow rather than inside the `No-network` job's namespace.

**Checking the first gate has one trap, and it is in the package that defines the ban.**
Every package's `eslint.config.mjs` imports `@akasecurity/eslint-config`, so ESLint
**executes** that package's `src/` to build any config at all. Append a `fetch()` there and
no rule ever runs: the call fires during config resolution and the process dies with
`TypeError: fetch failed`. It exits non-zero, which is exactly what makes it dangerous — a
check asserting only that `pnpm lint` failed passes on that crash, and would go on passing
with every network rule deleted. Verify this one by planting into a file ESLint does not
load as config (`vitest.config.ts`, `test/`). The suite covers that `src/` without executing
anything and must stay that way: it resolves the cascade at the real path and parses the
real bytes, planting nothing on disk.

The plugin — and the web dashboard's folder scan — also start a **worker thread** (`@akasecurity/plugin-sdk`'s isolated scan, below). A worker is not a child process, opens nothing, and gets no network of its own — it runs the same in-repo detection engine on a second thread of the same process. It is listed here only so an audit of "what else executes" finds it.

### 5. A scan that cannot be interrupted runs off the main thread

`scan()` is synchronous and a regex has no upper bound, so a catastrophic pattern is not a stall but a **detection bypass**: the hook blows its 10 s harness timeout, and a timed-out hook fails open, letting the whole tool call through unscanned. Nothing on the calling thread can interrupt a running `exec`; the fail-open `catch` only catches throws.

Two gates sit in front of that, and **both run on a worker thread**, because both are unbounded runs of an untrusted pattern:

- **The timing pre-flight** (`packages/plugin-sdk/src/rule-quarantine.ts`) measures every pulled/custom-pack regex rule against the adversarial probe battery once, caches the verdict locally, and excludes a rule that blows the budget. This is **empirical** — it proves a pattern did not backtrack on the inputs the battery constructs, not that it cannot. And the battery decides by _driving the pattern into backtracking_, so measuring a rule is itself a way to hang on one: `(a|a|a|a)+$` passes `Rule.safeParse` and never returns on the battery's own derived probe. So `filterUnsafeRules` takes a **prober** and the plugin runtime always supplies one — the measurement runs where it can be killed. Without a prober it falls back to the calling thread, which is for callers that already control the rules they pass (tests, tooling), never a pulled pack.
- **The isolated scan** (`packages/plugin-sdk/src/guarded-scan.ts` + `isolated-scan.ts` + `scan-worker.ts`) is the bound on the scan itself. Whenever the effective ruleset contains a regex rule that only the pre-flight stands behind, the whole scan runs in a `worker_thread` under a wall-clock deadline; `worker.terminate()` reaches V8's execution terminator, which interrupts a spinning regex. The terminated rule is quarantined through the pre-flight's own cache, so the next process never loads it, and the built-in packs keep detecting meanwhile.

Four properties are load-bearing and easy to break by accident:

- **The fast path must stay free.** A machine with no pulled or custom regex rule — the overwhelming majority — starts no worker and pays nothing. Nor does a machine whose verdicts are all cached, which is the steady state: the prober is built on first use. Do not widen the isolation to every scan; the permanent per-call tax is exactly why this was deferred once.
- **An ordinary scan is one `scan()` call.** Naming the rule that hung needs a pass that walks the unverified rules one at a time, and that pass is a **retry** of a scan that already timed out — never a tax on the scans that succeed. Worst case for a hang is therefore two deadlines, paid once per scanner (per process for a hook, per request for the dashboard); move that pass onto the happy path and the isolated cost stops scaling like the in-process cost.
- **The whole ruleset goes into the worker, never half of it.** Splitting the scan across two `scan()` calls breaks `requiresNearby` corroboration between the halves and silently drops findings.
- **Worker startup is charged to no deadline.** The worker posts `ready` before the parent starts the clock. Fold startup into the job budget and a cold or contended machine looks exactly like a catastrophic rule — and that misreading gets a legitimate rule quarantined forever.

A quarantine verdict is the one detection decision the machine reaches on its own, from a wall-clock measurement, and it is cached forever. So it is **recoverable and visible**: `aka detections unquarantine` forgets every quarantine verdict (keeping the `safe` ones, which are measurements worth keeping), and `aka detections` reports the count. The stderr line the plugin writes names the command, because a hook's stderr is otherwise the only place the machine ever mentions it; the dashboard's folder scan writes the same line to the server's console and additionally returns a notice to the page, since nobody is reading a server log while they click Scan. Anything that adds a new way to quarantine must keep those surfaces true.

The worker is a **build entry**, not a source file the loader finds: the published plugin ships `scripts/` only, so `plugins/claude-code/tsup.config.ts` emits `scripts/scan-worker.js` beside the hooks and the SDK resolves it as a sibling. A worker URL resolved against a source path works in the repo and under vitest and fails only once installed — `plugins/claude-code/test/e2e/scan-worker-bundle.e2e.test.ts` is what pins it, by driving a **built** hook against a throwaway home with a pulled rule installed.

**Where else the bound applies, and where it does not.** The capture path is `runtime.evaluate`, and so every hook plus `@akasecurity/scanner`. The dashboard's folder scan is the second caller and reaches the same two gates through `packages/local-ops/src/guarded-scan.ts` — `web-ui/app/(app)/scan/actions.ts` builds a `createGuardedFileScanner` over the installed-pack snapshot and hands `scanPathIntoStore` its `scanText` seam, never the raw `rules`, which is the in-process path. Three things differ there and each is load-bearing:

- **The scanner is per REQUEST, not per process.** The first hang retires isolation for the scanner's whole life; the dashboard server outlives every scan it runs, so a process-wide scanner would cost it its pulled rules until someone restarted it. That is also why `createGuardedScanner` takes a `degradeScope` — the stderr warning must not claim a lifetime it does not have.
- **The worker location is a caller input** (`GuardedFileScannerOptions.workerUrl`), never the SDK's sibling lookup. A Next build replaces `import.meta.url` with the BUILD MACHINE's absolute source path, so that lookup resolves where the build ran and nowhere else — silently costing an installed dashboard its bound. `web-ui/tsup.config.ts` emits the worker to `web-ui/dist/scan-worker.js`, `next.config.ts` traces it into the standalone build, and `web-ui/app/lib/scan-worker.ts` resolves it against `process.cwd()` (the app dir: Next's standalone `server.js` chdirs to its own directory, and every other launch runs from the package). Those three move together, `web-ui/test/e2e/scan-worker-bundle.e2e.test.ts` pins the first and third, and `cli/scripts/bundle-web-ui.mjs` throws at pack time if the second stopped working.
- **With no worker, a rule that cannot be bounded is dropped, not run** — including one the pre-flight already cleared, since that verdict is empirical. The scan says what it dropped (`GuardedFileScanner.dropped()` → the Scan page's notice); it does not quietly run a smaller ruleset than the Detections page lists.
- **A dropped rule is only ever pointed at `aka detections` when a verdict was actually cached.** `DroppedRules` splits on that — `quarantined` was measured and left a row, `unmeasured` was never timed here (no worker, or the pre-flight's pass budget spent) and deliberately leaves none, since caching a verdict for a rule nobody measured would disable it forever. Only the first has anywhere to send someone, and `countQuarantined()` — the value the command itself prints from — is what the notice gates on. Any new way to drop a rule has to say which of the two it is.

Two `scan()` calls inside the SDK are not exposure: `mask.ts` and `tokenize.ts`'s self-scan both pass `getLoadedRules()`, the compiled-in registry the CI battery gates on every commit, so no pulled pattern reaches them. `aka scan` passes no ruleset and falls back to that same registry, so the CLI runs in-process by design and is not exposed — passing it an installed snapshot instead would put an unreviewed regex on an unbounded path.

What remains uncovered is the packaged artifact: nothing installs the published CLI and drives its dashboard's folder scan under a hostile pack, so the chain above is proven link by link rather than end to end.

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
                     @akasecurity/plugin-sdk (repo-identity, project-file walkers, posix
                     path normalization, and the ReDoS gates the dashboard's folder
                     scan reuses — filterUnsafeRules + createGuardedScanner, see
                     src/guarded-scan.ts and Architecture principles §5)
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
                     the SessionStart project-file walk), node:worker_threads
                     (the isolated scan — see Architecture principles §5)
                     `src/scan-worker.ts` is the worker's own entry, exported as the
                     `./scan-worker` subpath and reachable only from `@akasecurity/detections`
                     + `./isolated-scan-protocol.ts`. It must stay that narrow: Node loads it
                     directly (bundled `.js` when installed, type-stripped `.ts` in the repo),
                     so `src/bundled-packs.generated.ts` — 101 JSON imports without import
                     attributes — would break it at load, and it never needs them anyway
                     because the ruleset arrives over `workerData`.
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

### Tonal tokens come in pairs: a hue and an ink

Every tonal family (`sev-critical`, `sev-high`, `sev-medium`, `sev-low`, `ok`, `teal`,
`violet`) carries **two** foregrounds, and picking the wrong one is an accessibility bug
that compiles, renders, and reads fine in review:

- `--color-X` — the **hue**: chart series, status dots, bar segments. Non-text, so what
  matters is staying distinguishable from its neighbours (WCAG 1.4.11).
- `--color-X-ink` — **text** on that family's tint, and solid fills that carry text
  (WCAG 1.4.3, 4.5:1).

They cannot be collapsed. Forcing every hue dark enough to read as text on a pale tint
crowds them into one luminance band — severity chart separation measured 1.69 before and
1.05 after, with red/orange/yellow rendering as the same brown. So **a foreground always
spells the `-ink` form**, and every family carries one even where its hue already clears
4.5:1 (violet in light; all of them in dark, where ink == hue): a family missing its
`-ink` makes `text-X-ink` generate no CSS at all, because an undefined theme variable
produces no utility and the element silently inherits its color.

`--color-primary` is the one exception and reads the other way round — it **is** the ink,
and `--color-primary-solid` is its fill. So `text-primary` is right while
`text-sev-critical` is wrong, and nothing in the names says which. That is why it is
enforced rather than remembered: `tonalInkTokens` in `@akasecurity/eslint-config` is a
`no-restricted-syntax` ban on a bare hue reached through `text-*`, spread by `ui-kit`,
`dashboard-ui` and `web-ui`. It re-spreads `noNetworkSyntax()` because a flat-config
`rules` entry **replaces** the rule's options rather than merging them — drop that and
those three packages silently lose §4's dynamic-import ban.
`packages/eslint-config/test/tonal-ink-tokens.test.js` pins both halves.

What the ban does **not** see, and what still needs reading: a hue handed over as a CSS
variable string, since `iconColor="var(--color-ok)"` and `iconBg="var(--color-ok-fill)"`
are the same node to a selector (`toneColors()` and the `StatTile` `iconColor` prop are
the live examples); and a class assembled from a non-literal.

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

   **Naming a target is not enough if the same invocation hands it back.** An
   `--ignore-pattern` cancels a target it matches, so `*.config.*` plus an ignore of
   `vitest.config.ts` reads as covering that file and lints it not at all. Anything an
   ignore flag excludes therefore counts as uncovered however the targets read, and the
   fix is to drop the flag rather than the directory. `--ignore-path` counts as excluding
   its whole invocation: flat-config ESLint rejects the flag outright, so that `eslint`
   call lints nothing. No `lint` script carries either flag today, and
   `packages/eslint-config/test/effective-config.test.js` is what would catch one that
   took coverage back. It bounds the damage rather than banning the flag: an ignore
   matching nothing the package ships stays green, which is what stops the guard
   over-reporting.

   A `lint` script is a shell string, so **two ESLint calls are chained with `&&`
   and nothing else**. Behind a `||` the second runs only once the first has
   failed, so no green run ever lints what it targets; `|| true` is the mirror
   image, running the call and discarding its exit code. The same guard drops a
   segment carrying any operator but `&&` — reporting the package as covering
   nothing, rather than crediting a call a green run skips.

   That covers files a **package** owns. Files **outside every package** — at the
   repo root or under a directory no package claims — are a separate case with its
   own pass: `pnpm lint:root` / `pnpm typecheck:root`. Both run outside Turbo
   (`turbo run …` drives per-package scripts, each with its package as the working
   directory, and no package's `lint` script targets anything outside its own
   tree), and CI runs them as their own steps beside `format:check`. `pnpm lint`
   and `pnpm typecheck` additionally **chain** them with `&&`, so the pre-push
   hook, the two release workflows and a contributor running them locally all
   cover the repo root rather than reading green while a file there is unlinted or
   unchecked — those callers run only the workspace-wide scripts and never the CI
   steps. The chain has to be unconditional: behind a `||` the root pass runs only
   once the workspace pass has already failed, which is every green run skipping
   the repo root. `lint:root` is a single invocation: `eslint.root.config.mjs` runs
   the full ruleset over `test/setup/**`, `tools/ci/**`, and the repo-root
   `*.config.*`. `typecheck:root` runs `tsc -p tsconfig.root.json`.

   It used to carry a second, network-only invocation over the plain-JS
   enforcement suites in `packages/eslint-config/test/**`, because that package's
   `lint` was a deliberate no-op and a root pass was the only thing that could
   reach them. It lints itself now — `eslint src *.config.*` then
   `eslint --no-config-lookup -c eslint.guard.config.mjs test`, the same
   full-ruleset + network-only split every other two-pass package makes — so those
   suites are covered by the ordinary per-package check and nothing about them is
   special any more.

   Anything new outside every package belongs in those passes — and a **file** at
   the root is named explicitly, not folded into a directory glob (the same rule
   step 5 draws inside a package). `*.config.*` is the standing lint target for root
   config and catches the root ESLint config and commitlint's; any other root
   file is named by hand — including one whose `.config.` segment is capitalized,
   since a shell glob is case-sensitive on every platform and `*.config.*` reaches
   `aka.config.mjs` but not `aka.Config.mjs`. A root file carrying `// @ts-check`
   (as `eslint.root.config.mjs` does) is also named in `tsconfig.root.json`'s
   `include`, or the directive is
   decorative — nothing runs `tsc` over it and a real type error surfaces nowhere.
   Miss the pass and esbuild strips its types unchecked and nothing lints it.

   **Forgetting is caught rather than remembered.** `effective-config.test.js`
   derives the set of git-tracked lintable files belonging to no workspace package
   (`git ls-files` minus the `pnpm-workspace.yaml` globs — never a hardcoded list,
   or a file added tomorrow would not be in it), and fails naming each one that no
   eslint invocation lints. The coverage side is derived too, and from what is
   actually **run**: the invocations are walked out of the root `package.json`
   starting at `lint` and following the scripts it **unconditionally** chains, so
   a pass sitting in a script no gate invokes — a `lint:fix`, say — covers
   nothing, and neither does one the chain reaches only on failure. That rule
   applies to the eslint calls inside a script as well as to the scripts it
   chains: `eslint <a> || eslint <b>` reads as two passes and runs the second only
   once the first has already failed, so a green run never lints `<b>`. A
   fault-injection case then plants network code at each real path and requires
   all four network
   rules to fire with no fatal parse error, because a file outside every tsconfig
   `include` reports a parse error and NO rule violations — structurally wired,
   behaviorally correct, enforcing nothing. Adding such a file means adding a lint
   target for it and listing it in `EXPECTED_NON_PACKAGE_FILES`.

   It also means keeping the repo-root glob in `@akasecurity/eslint-config#test`'s
   `turbo.json` `inputs`: the per-package input globs all require a directory
   segment, so without it a new root-level file leaves that task's hash untouched
   and turbo replays a cached green in which the check never ran. Those globs spell
   their extensions by hand, so the same suite drives that list against the one it
   enumerates by — a file whose extension it counts as lintable and the glob omits
   is the same cached-green hole one extension wide.

6. Add the package name to `EXPECTED_WORKSPACE_PACKAGE_NAMES` in
   `packages/eslint-config/test/effective-config.test.js`. That pinned list only
   forces a human to notice the new package — what actually stops it shipping
   unguarded are the assertions next to it (a missing config, a config that never
   extends the shared one, a `lint` script that misses a directory or a root file, a
   root file the linter cannot parse).

7. If it has a `test` script, run those tests through **vitest** and wire the
   no-network guard into its `vitest.config.ts`, then add its name to
   `EXPECTED_VITEST_PACKAGES` in
   `packages/eslint-config/test/no-network-runtime.test.js`. Copy the block from a
   neighbour at the same depth — the relative path is `../../` from
   `packages/<name>/`, `plugins/<name>/` or `tools/<name>/`, and `../` from a
   repo-root package (`cli`, `web-ui`):

   ```ts
   const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));
   // …
   test: { setupFiles: [noNetworkGuard], … }
   ```

   The runner is not incidental: the guard is a vitest `setupFiles` entry, so a
   package testing through anything else (`node --test`, say) runs with no runtime
   network guard at all. That suite enumerates every package with a `test` script
   and fails on any that is not vitest, so such a package has to be argued into
   `EXPECTED_NON_VITEST_TEST_PACKAGES` — a list that is empty and should stay that
   way, since every entry is a hole in the guarantee.

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

### The no-network guard

`test/setup/no-network.ts` is loaded by **every** package as a vitest `setupFiles`
entry. It refuses any outbound connection that is not loopback — TCP (and therefore
TLS, HTTP, HTTP/2, `fetch`), UDP, and the DNS `resolve*` family — and its error
**names the call site**, digging past ~60 frames of bundled undici to find the line
that actually reached out. It prefers this repo's own code over a `node_modules`
frame, since a transitive dependency reaching out is the case the ESLint ban cannot
see and the frame a reader has to act on is the one that called it. Loopback
(`127.0.0.0/8`, `::1`, `localhost`) and unix/named-pipe sockets stay open; the CLI's
port probe and the dashboard boot test depend on them.

Four things about it are load-bearing:

- **A refusal is recorded as well as thrown.** Almost every boundary here is
  deliberately fail-open, so a throw inside a `catch {}` would be swallowed and the
  run would go green having reached the network. `afterEach`/`afterAll` fail on any
  undrained record. A test that provokes a refusal on purpose must drain it with
  `takeBlockedAttempts()`.
- **It imports `node:net`/`node:dgram`/`node:dns`, which the lint ban forbids.**
  That is the enforcement, not a violation. `packages/eslint-config/test/no-network-runtime.test.js`
  lints the file and fails if it trips a **fourth** ban.
- **A child process is invisible to it**, which is the whole reason the `No-network`
  CI job exists. Do not describe the guard as covering shell-outs.
- **Every package must wire it**, at the right relative depth. The same suite fails
  the workspace if a package drops the entry, points it at a path that does not
  resolve to the guard, or is added without one. That last one holds for packages
  that test through **vitest**; a package testing through another runner cannot load
  a `setupFiles` entry at all, so the suite enumerates every package with a `test`
  script and fails on any non-vitest one unless it is named in
  `EXPECTED_NON_VITEST_TEST_PACKAGES` (empty, and each entry would be a real hole).

The only opt-out is **`takeBlockedAttempts()`**, and there is no env escape hatch or
config flag. Draining is how a test consumes a refusal it provoked on purpose, so it
is also the way to hide one — the seam is deliberate, narrow, and visible in review.
A test that needs the outside world needs an injectable seam instead — `local-ops`'
`ReportDeps.viewVersion` and `judge.ts`'s `spawnClaude` are the two worked examples,
and neither `vi.mock`s `execFileSync`: they take the boundary as a parameter, so the
network call site is never reached rather than being intercepted.

`dns.lookup` is deliberately **not** patched (the connect guard already gates what it
feeds). Be accurate about what that leaves: a bare lookup still discloses the hostname
to whoever runs the resolver, which is real egress even though it is not a dependency
on a remote service. Only the Linux `No-network` job blocks it.

**The CI script is a tested artifact, not a script nobody reads.** It is the only gate
covering child processes, and its whole value is a positive control that refuses to run
vacuously — which is worthless if nothing exercises it. The same suite drives
`tools/ci/no-network-test.sh` with a `PATH` of hand-written stubs and pins every
outcome: probe tooling missing, DNS still resolving, the target still answering, the
probe reporting itself broken, the probe file gone, started as root, and the one green
path where the command actually runs. Change a probe and a case fails; delete one and
the case that covered it fails.

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

### Testing a web-ui page

An async Server Component is a plain async function that returns an element, so a route's
own data work — which store reads it issues, and which one it hands to which consumer — is
testable by **calling the page and reading the props it hands down**. No renderer, no DOM,
no jsdom. `element.props` carries them; assert `element.type` alongside, so a page that
starts returning a wrapper fails naming that rather than reading every prop as `undefined`.
`web-ui/test/pages/exceptions-page.test.ts` is the worked example. The four steps above
apply unchanged (a read-only page needs no `next/cache` mock).

This is not the browser tier — nothing mounts, no event fires, no client component runs.
It covers the seam between the store and the props, which is where a route's derivations
live and where nothing else can see them.

**The one thing that makes it work is a config line.** `web-ui/tsconfig.json` sets
`"jsx": "preserve"` because Next's own compiler consumes untransformed JSX, and vitest
inherits it — so the page's JSX survives into the output and the parser that reads it next
rejects it. `oxc.jsx` in `web-ui/vitest.config.ts` overrides that for the test run only. It
is already wired; a new suite needs no change, but a parse error on a `.tsx` import is what
its absence looks like, and it names neither JSX nor the tsconfig.

A route that issues **more than one read of the same table** is the case worth writing a
page test for at all: a count derived from the wrong one of two windows is still a number,
so it typechecks, lints, and satisfies every assertion aimed at the pieces. Make the fixture
straddle the two windows and **pin the straddle itself** — with rows that all fall inside
both, the assertions pass whichever read the page used, and the suite proves nothing.

An at-rest leak scan must read **every file in the data dir**, not `aka.db` plus a
hardcoded `-wal`/`-shm` pair. This is not a corner case: a migration leaves an
`aka.db.pre-drop.<ts>.<rand>.bak` — a byte-for-byte copy of the pre-migration store — in that
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
prefix. `expectNoEchoOf` is the **required form for every raw-value absence assertion that is
newly written or newly touched** in a package carrying the helper — `cli/test/helpers/no-echo.ts`,
`plugins/claude-code/test/helpers/no-echo.ts` and `web-ui/test/helpers/no-echo.ts`. A plain
`not.toContain(rawValue)` in a new or edited assertion is a defect, not a style choice, and
editing a file means its in-class assertions come along rather than being left beside converted
ones.

**Older assertions are a backlog, not a clean tree.** `plugins/claude-code` still carries around
twenty whole-value raw-value assertions in files this convention has not reached —
`history/`, `journey/`, `remediation/`, `render.test.ts`, `triage/plan-file.test.ts`,
`hooks/pointer-substitution.test.ts` and `backfill.test.ts` among them. Do not read the rule
above as a claim that the package is clean. Two shapes are genuinely **exempt** and stay
whole-value: an assertion on a masked preview (`writeback.test.ts` on `maskedValue`,
`triage/surfaced-secrets.test.ts` on `maskedToken`), because that fragment is revealed on
purpose; and the deliberate **control** assertions inside each `no-echo.test.ts`, which exist
to show the whole-value form would have passed.

**Share it inside a package, copy it across a wall — and a copy takes the suite with it.**
All three packages import a `test/helpers/no-echo.ts` with its own tests in `no-echo.test.ts`:
each case drives the helper with an output that leaks a run, and asserts both that the helper
refuses it **and** that the whole-value form it replaced would have passed. That second half is
what shows the assertion is _stronger_ rather than merely also-red, and it is why raising the
run length or emptying the loop cannot go unnoticed — widening `ECHO_RUN` leaves every
**caller** green, so the helper's own suite is the only thing that goes red. `web-ui` is the
worked example of that failure: its copy was inline with no suite, and all 86 of its action
tests passed with `ECHO_RUN` set to 64. A package wall blocks the import, not the pattern, so a
fourth package copies **both** files — including the `expect(value).toBeDefined()` guard,
without which an `undefined` message satisfies the loop vacuously.

**A masked-preview control calls the product's mask, never a hand-rolled one.** A locally built
literal asserts that a string the test constructed lacks a run of another string the test
constructed — true by construction, and it stays true however `maskMatch` changes. Each
`no-echo.test.ts` calls `maskMatch` itself (`@akasecurity/plugin-sdk` re-exports it, so the
plugin crosses no package wall), which is what makes widening its generic branch go red where
the reason is written down.

**Capture the error outside the `catch`.** This shape passes while the function under test
stops throwing entirely:

```ts
try {
  parse(input);
  throw new Error('expected parse to throw'); // caught by its own catch, below
} catch (err) {
  expect((err as Error).message).not.toContain(RAW); // asserts on THAT message
}
```

The guard error carries no secret, so the absence check is satisfied by the test's own
throw. Use `errorFrom(() => parse(input))` (the plugin's helper) or the CLI's
`.then(() => undefined, (e) => e as Error)`, then assert what the error **says** before
asserting what it **omits** — a never-thrown error arrives as `undefined` and `toBeDefined()`
catches it. Naming the expected refusal is also the positive control: without it a case
proves only that _some_ error said nothing, not that the guarded branch was the one reached.

**Never point it at bytes that can come back empty.** Every `not.toContain` passes on `''`,
and `toBeDefined()` does not catch that: it catches a never-thrown error arriving as
`undefined`, while a Prompter's `output()` returns `string` and is never undefined, so the
guard is **inert on stdout**. Where a path prints nothing at all, assert that —
`expect(io.output()).toBe('')` — which goes red on anything printed there, raw or not.
Where it does print, pin a **positive control** on the same bytes first.

This applies to a **raw value**, in an **error** and on whatever further surface a suite
binds below. At-rest and grant-shape assertions stay whole-value, because `maskMatch`
deliberately keeps a fragment visible and that fragment is stored on purpose; and an
assertion that some non-secret string is absent — an internal error-class name, say — is a
different property that `expectNoEchoOf` does not express. Drive the window with a
**high-entropy** fixture: against an English-phrase literal an eight-character window
collides with ordinary output text instead of catching a leak. High-entropy does **not**
mean credential-shaped — this repo is public, and a fixture that looks like a real secret
does not belong in it. Where a suite needs both (`cli/test/commands/exception-reveal.test.ts`
tokenizes a value the engine never scans), a random-looking string that matches no rule
satisfies them together; where the value must match a rule, take it from that rule's own
`examples` so no secret-shaped literal is written by hand.

The CLI's `exception` suites bind it **wider than an error** — to their **stdout**
assertions too, because a CLI's terminal output is where a leaked value gets scrolled,
pasted into a bug report and captured by CI logs. That is safe rather than fragile **for
the values those suites use**: what they print of a blocked **generic** secret is
`maskMatch`'s first-and-last preview (`A******E`), two characters, which cannot fill an
eight-character window. **It does not generalize to every value `maskMatch` handles.** The
email branch reveals the first local character plus the **whole domain**
(`user@example.com` → `u***@example.com`), and a single-character local part returns the
input unchanged — both fill the window on purpose. A surface printing a pii/email preview is
out of scope for the stdout half, not a leak it found; `no-echo.test.ts` pins both branches
so that boundary is written down rather than re-derived. If the **generic** branch is ever
widened past two characters, that suite goes red first, which is the correct answer and not
a reason to loosen the callers back.

**Bind it per assertion, never per file.** `cli/test/commands/vault.test.ts` is the worked
example: its forged-pointer refusal pins absence like any other, but `aka vault show`'s
success path prints the raw value **on purpose** and asserts `output().startsWith(RAW)`, so
a run-by-run rule over that case would assert the opposite of the command's contract. Exempt
the case, not the file — a file-level exemption also disarms the refusal paths in it, which
are the ones a leak actually travels through.

Assert against the value **that call supplied**, never a module constant the case does not
send. A case driven with an inert literal and asserted against a shared `VALUE` cannot fail
however the branch is worded, so it stays green while the branch echoes the live value it
was handed. Name each case's own inputs. This is the same family as the two rules above: an
absence assertion is only worth its green if it could have gone red — so before trusting a
new one, break the property it claims to guard, re-run, and treat a still-green suite as a
defect in the test.
