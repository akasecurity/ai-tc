# AI Traffic Control — Conventions for AI Agents

Read this before generating any code in this repository. These conventions are enforced by ESLint and CI — code that violates them will fail to merge.

AI Traffic Control (`ai-tc`, by AKA Security — the `aka` CLI and plugin names come from
the company) is a **local-first** security control plane for AI coding agents. The whole surface
runs on one machine with **no server, no Docker, and no database engine**: the Claude Code
plugin, the Codex CLI plugin, the Antigravity plugin, the browser extension (ChatGPT +
Claude.ai web chat, bridged over Chrome native messaging — no port, no listener), and the
`aka` CLI capture agent activity into a local SQLite store at `~/.aka/data/aka.db`, and the
web dashboard reads that same store directly. There is no
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
- **Packaging:** the `aka` CLI and the Claude Code / Codex CLI / Antigravity plugins, published to npm as self-contained bundles

## Architecture principles

### 1. Fail-open everywhere in the plugin

The plugin **must never break a user's Claude session**. Every hook entry wraps `main()` in
try/catch and then calls `process.exit(0)`, so a hook that fails writes **nothing to stdout and
exits 0** — which the hook protocol reads as "no opinion", i.e. allow. Failing open is the
_absence_ of output, not a payload.

**No hook emits `{ action: 'allow' }`, and none should start.** `action` is a `CaptureResult`
field that never crosses the wire; the internal fallback `handleCapture` returns when the runtime
throws is `{ action: 'log' }`, and `'allow'` is only ever assigned to an **excepted** finding.
Emitting a real opinion means writing one JSON object to stdout via `emit()`
(`plugins/claude-code/src/hooks/shared.ts`), which takes the `HookOutput` union rather than
`unknown`, so a payload outside that union cannot reach the wire at all. Its six shapes are
`decision` and `systemMessage` at the top level, plus one `hookSpecificOutput` per hook —
`PreToolUse`'s `permissionDecision`, `PostToolUse`'s `updatedToolOutput`, `MessageDisplay`'s
`displayContent` and `SessionStart`'s `additionalContext`. The write is awaited, because
`process.exit` does not flush a pending pipe write and a truncated object reads as invalid JSON,
passing the original payload through unscanned.

That enumeration is derived rather than remembered, because this is the sentence that drifted last
time — it claimed four shapes while six were reaching stdout, and the two it omitted belong to the
two hooks nothing else in this file mentions. `plugins/claude-code/test/hook-output-shapes.test.ts`
reads it and drives it against the union: the count word, the two top-level keys, and each
`hookEventName` paired with the field that distinguishes it. A seventh variant added to
`HookOutput` fails to compile until that test's map names it, and fails that test until this
sentence does.

`plugins/claude-code/test/e2e/fail-open.e2e.test.ts` is what holds this rather than review: it
drives the built hooks against malformed, truncated, binary and oversized stdin, asserting exit 0
and empty stdout, and its `expectNoActionKey` fails any emitted payload carrying an `action` key.
That last check is worth **nothing** on the rows above it, which have already asserted the stdout
is empty — `''` matches no pattern. So the file also drives a real finding through each enforcing
hook at block, redact, warn and log, asserts the shape each cell is expected to emit (the positive
control, without which a hook that stopped emitting would turn every absence assertion back into
the vacuous form), and reads `expectNoActionKey` over the payload that produced. Keep both halves:
the fault rows prove silence, and only the enforcement rows can prove what the noise looks like.

**What "fall back to allow" means is the HOST's convention, not a fixed payload.** Claude Code
and Codex read "exited 0, said nothing" as "no opinion" — so a silent `catch` is genuinely
fail-open there. **Antigravity reads it as a `deny`**: a hook that exits non-zero, is killed on
its timeout, or prints nothing blocks the tool call outright. On that host, failing open means
_printing an explicit_ `{"decision":"allow"}` on every path — see
`runHookFailOpen` in `plugins/antigravity/src/hooks/shared.ts`. Before writing a fail-open path
for a new harness, check which convention it uses; assuming this one is what turns a crashing
hook into a wedged session.

**That guarantee reaches exactly as far as the event loop does, and the gap is not academic.**
`runHookFailOpen` races the body against a `setTimeout`, so it covers a throw, an undecided
body, and a body that outruns the watchdog — everything that _yields_. It cannot preempt a body
that blocks the thread, because nothing on the calling thread can. A block that clears inside
the host's own 10s still emits and exits 0 — the denial needs the block to outlast the HOST,
not merely the watchdog. Two blocking stretches sit on the capture path and compose:
`openLocalDatabase` is synchronous `node:sqlite` whose `PRAGMA busy_timeout = 2000` is charged
per contended **statement** rather than once per open (so the reachable total is a multiple of
2s), and §5's fast-path `scan()` is synchronous and in-process whenever the ruleset carries no
pulled or custom regex rule. `emit` sits outside the race as well, so a stalled pipe has no
deadline at all — and on that path the closing `process.exit(0)` is never reached either. This is §5's argument arriving at a second boundary — the fix for an unbounded stretch is
to move it off the thread, never to lengthen the timer — and the consequence here is harsher
than a missed scan: the condition that blocks (a contended store, a held lock) persists, so the
denial does too. Do not describe the explicit-allow as unconditional; it is unconditional over
what yields.

Both halves are covered, and by different suites because they fail differently.
`plugins/antigravity/test/hooks/fail-open-wrapper.test.ts` drives `runHookFailOpen` itself —
the throw, the undecided body, the watchdog win, a late rejection that must not surface as an
unhandled rejection (which would exit non-zero, i.e. deny, by a route the wrapper never writes
to), and the synchronous-block limit pinned as behaviour rather than prose. It also asserts one
JSON object, not merely a non-empty stdout: two concatenated objects do not parse, so a second
write is a deny exactly like silence.
`plugins/antigravity/test/e2e/fail-open.e2e.test.ts` is the Claude Code sibling's mirror image
and drives all four built hooks against empty, malformed, truncated, scalar, binary and
oversized stdin plus an unopenable store. Every assertion there is a **presence** check —
absence checks are the right shape on a fail-open host and the wrong one here, where `''` is
the failure being guarded against.

### 2. Contracts before code

`@akasecurity/schema` is the spine. The Zod schemas in `src/zod/` define every data boundary. Add shapes there before implementing them anywhere else.

**Do not create new types and interfaces — use the ones exported from `@akasecurity/schema` to the maximum extent.** Consumers (web-ui, CLI, plugin) import the schema types directly rather than redefining local "view-model" shapes or adapters. A new type is justified only when there is genuinely no schema equivalent (e.g. pure presentation descriptors like `{ label, icon, color }`). If a shape is missing, add it to `@akasecurity/schema/src/zod/` first, then consume it.

### 3. `process.env` is off by default

ESLint (`n/no-process-env`) forbids reading `process.env` across the workspace — a violation is a CI failure, not a warning. Eight places in shipped source genuinely need the host environment and opt out — test harnesses that spawn the real hooks carry inline disables of their own and are out of this table's scope:

| Site                                              | Mechanism                         | Why                                                        |
| ------------------------------------------------- | --------------------------------- | ---------------------------------------------------------- |
| `packages/plugin-sdk/src/provider.ts`             | file-scoped ESLint config         | LLM-provider resolution at SessionStart                    |
| `packages/plugin-sdk/src/provider-codex.ts`       | file-scoped ESLint config         | Codex LLM-provider resolution at SessionStart              |
| `cli/src/commands/dashboard.ts`                   | inline `eslint-disable-next-line` | spawning the dashboard server                              |
| `plugins/claude-code/src/backfill.ts`             | inline `eslint-disable-next-line` | the host session id the self-contamination guard skips     |
| `plugins/claude-code/src/triage/judge.ts`         | inline `eslint-disable-next-line` | the judge subprocess must inherit PATH/auth                |
| `plugins/codex/src/triage/judge.ts`               | file-scoped ESLint config         | the judge subprocess must inherit PATH + `CODEX_HOME` auth |
| `plugins/antigravity/src/triage/judge.ts`         | file-scoped ESLint config         | the judge subprocess must inherit PATH + `~/.gemini` auth  |
| `packages/plugin-sdk/src/provider-antigravity.ts` | file-scoped ESLint config         | LLM-provider resolution at Antigravity's first invocation  |

Prefer a file-scoped config opt-out over an inline disable — an inline disable is invisible to anyone auditing the ESLint configs. Adding a ninth site means updating this table.

That last sentence is enforced, not merely asked: `packages/eslint-config/test/effective-config.test.js` parses this table and drives each column against the thing it describes — the site against the tracked tree, the mechanism against the resolved config and the file's own text, the count word against the row count, and the row set against every opt-out shipped source actually carries. So a fifth site that never reaches the table fails CI, and so does a row that outlives the exception it describes. The `Why` column is prose about intent and is guarded by nothing.

**Both mechanisms are inventoried, not just the config one.** An inline disable is invisible to
anything that resolves configs, so the check above would never have seen one had it been the only
check: `packages/eslint-config/test/inline-disables.test.js` reads the **directives** instead, over
every tracked lintable file, and asserts the set that disables `n/no-process-env` **exactly** — a
floor would let a new one in, which is the whole failure mode. Its expectation is wider than this
table on purpose, because this table is scoped to shipped source: the test harnesses that spawn the
real hooks carry inline disables of their own, and until that suite landed nothing inventoried
them at all. Two forms this table's language does not reach are refused outright there rather than
tabled — a bare `/* eslint-disable */`, which takes every rule with it, and an inline
`/* eslint <rule>: … */`, which can empty a ban while leaving it at `error`. Both run to the end of
the file, so both exempt code nobody has written yet.

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

**Inline disables are inventoried too, and across the whole tree rather than four files.** Every
audit named above resolves **configs**, so none of them can see an inline `eslint-disable` — and
one line of it admits `node:https` into any package's shipped source with `pnpm lint` at exit 0.
The raw-guard measure closes that for the four files it pins and only those.
`packages/eslint-config/test/inline-disables.test.js` is the tree-wide half: it reads the
directives in every tracked lintable file and asserts the set disabling any of the four network
rules **exactly**. That set is one entry long — this section's `fetch` (inline) — and an exact set
is the point, since a guard that only forbids removals lets the next one in. It also refuses the
two forms this table has no language for: a bare `/* eslint-disable */`, which disables all four at
once, and an inline `/* eslint <rule>: … */`, which can empty a ban while leaving it at `error`.

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
which paths each covers — is one shared module
(`packages/eslint-config/test/helpers/lint-invocations.js`), used by both that audit and the
per-package lint-coverage check in `effective-config.test.js`. Two readers of one shell string
would be free to disagree about what runs, which is how a file ends up covered by one guard
and audited by neither. `trackedFiles()` sits there for the same reason and is the one
`git ls-files` walk every audit in the package asks — including the ones below, which ask what
the tree really holds rather than what a lint script says.

`DOCUMENTED_OPT_OUTS` is a hand-written mirror of that table, and it is not what keeps the table true — it never opens this file. `packages/eslint-config/test/no-network.test.js` parses the table and asserts it twice: against that mirror, so the two cannot drift apart in either direction, and against the configs themselves, resolving each row's site through ESLint under the config the row names. The second is what covers the **Site** column, which the mirror does not carry and so cannot check — a row may not name a file the config never reaches, nor keep an exception that has been removed. Any entry in the **Allowed specifier** column that is neither a banned module nor a banned global marked `(inline)` fails rather than being skipped, since a token the module audit cannot see is enforced by nothing.

Network access happens **only through child processes**. In all but the external-dispatch path, this repo chooses the program and its arguments; in that one it chooses neither:

1. `@akasecurity/local-ops` shelling out to package managers (`npm`/`claude`) for update-and-apply.
2. The Claude Code plugin's own `npm audit signatures` child process — run from inside the plugin's dependency closure (a plugin script or `@akasecurity/plugin-sdk`, since the plugin cannot import `@akasecurity/local-ops`).
3. The `/aka:setup` wizard's judge subprocess (`plugins/claude-code/src/triage/judge.ts`), which spawns `claude -p` and **sends findings to the model API** so it can rate false positives and severity. `runJudge` serializes a minimized projection (`toJudgePayload`), not the whole `TriageHit`: `rawMatch` (the raw, unmasked secret) crosses, along with `context` (a ±120-character window of the surrounding transcript text — see `plugins/claude-code/src/history/scan.ts` — re-masked with `maskText`, which scans the **bundled** packs rather than the installed set — coverage is still complete because `buildTriageHit` has already redacted every other finding from the full-ruleset scan, and this hit's own value is masked here where it appears in the window; `rawMatch` is therefore the only raw value that crosses), `id` (a sequential counter the rubric requires the model to echo), and the non-sensitive scoring labels `ruleId`, `category`, `severity`, `maskedMatch` and `confidence`. `filePath` (the source transcript's path), `valueFingerprint` (an HMAC of the secret), and `keyVersion` are dropped before egress — a new `TriageHit` field is not disclosed to the model unless `toJudgePayload` and the disclosure copy are updated together. A large history is chunked, so this is several `claude -p` calls, not one. It runs only on the user's explicit opt-in during setup — a consent distinct from the historical-read grant, recorded as `modelJudgeConsent` and re-checked against `MODEL_JUDGE_PAYLOAD_VERSION` on every run, so widening the payload invalidates consents given for the old one. `historicalAccess` gates the READ only — a `full` grant authorizes no egress by itself, and no consent surface may imply that it does. Both grants are revocable under Settings, where **Historical access** and **Model-judge consent** are separate controls; revoking stops future scans but cannot recall what was already sent. The subprocess asks the CLI to suppress its transcript (`CLAUDE_CODE_SKIP_PROMPT_HISTORY=1`), but that is transcript isolation, **not** network isolation — a copy of the raw values leaves the machine, because the whole point is to reach the model. Consent copy must state the payload, the egress, and that limit on revocation plainly; it must never be described as staying "inside an isolated subprocess." Four surfaces carry that copy and move together: `plugins/claude-code/commands/setup.md`, the `[^egress]` footnote in each of the two READMEs, and the Settings copy in `packages/dashboard-ui/src/settings/WorkspaceSettingsFormView.tsx`.
4. **Git-style external subcommand dispatch** (`cli/src/lib/external-dispatch.ts`). `aka <name>` execs `aka-<name>` from the user's `PATH` when no built-in owns the name, inheriting the caller's environment and stdio. The child is resolved by name at call time — this repo does not bundle, depend on, verify or version-pin it — so its behaviour, including any network access, is outside what this codebase can describe. AKA Security ships one intended occupant, `aka-claude` from `claude-tools`, which launches a Claude Code profile and is network-bound by definition; the dispatch gives it no special status, and any other `aka-*` on `PATH` runs identically. A built-in always wins, so this can never shadow a shipped command, and the path is POSIX-only (disabled on win32). An allowlist or provenance check is a deliberate non-goal: the precondition for abuse is write access to a `PATH` directory, which already permits shadowing `aka` itself. The invariant that is enforced is that a built-in always wins.
5. The Codex `aka-setup` wizard's judge subprocess (`plugins/codex/src/triage/judge.ts`), which spawns `codex exec` and sends the same minimized `toJudgePayload` projection to the model API as the Claude Code judge — `rawMatch`, the re-masked `context` window, and the sequential `id`; never `filePath`, `valueFingerprint`, or `keyVersion` — chunked into several `codex exec` calls for a large history, under the same distinct `modelJudgeConsent` opt-in, the same `MODEL_JUDGE_PAYLOAD_VERSION` re-check, and the same revocation limit (revoking stops future scans but cannot recall what was already sent). The `--ephemeral` flag stops the judge session from being written under `~/.codex/sessions` (which AKA's own backfill scans — a persisted judge session would re-ingest the raw findings it carries), but that is session-persistence isolation, **not** network isolation. The same consent-copy honesty rules apply (`plugins/codex/skills/setup/SKILL.md`).

6. The Antigravity `aka-setup` wizard's judge subprocess (`plugins/antigravity/src/triage/judge.ts`), which sends the same minimized `toJudgePayload` projection to the model API as the other two judges — `rawMatch`, the re-masked `context` window, and the sequential `id`; never `filePath`, `valueFingerprint`, or `keyVersion` — under the same distinct `modelJudgeConsent` opt-in, the same `MODEL_JUDGE_PAYLOAD_VERSION` re-check, and the same revocation limit. **This host is materially weaker than the other two, and the consent copy must say so.** Its CLI documents no `exec` subcommand and no ephemeral mode: the headless entrypoint is `agy -p "<prompt>" --output-format json`, so (a) every judge run **persists** a conversation under `~/.gemini/antigravity/brain/<conversationId>/` — the same store AKA's own backfill sweeps — which this module then deletes itself in a `finally`, best effort only (a killed process leaves it), and (b) the prompt rides **argv** rather than stdin, so the raw values are visible to `ps` for the life of the run and sit under the OS's `ARG_MAX` (the caller's chunking is what keeps them under it). Deletion is a local-write cleanup, **not** network isolation. Attribution for that deletion is deliberately conservative — the reported `conversation_id`, else a newly-appeared conversation only when exactly one appeared — because deleting a conversation the user started is unrecoverable while leaving a judge conversation merely re-surfaces their own known secrets. The same consent-copy honesty rules apply (`plugins/antigravity/skills/setup/SKILL.md`).

These are the **shipped product's** egress paths. Repo CI additionally talks to the npm
registry: `.github/workflows/audit.yml` (via `tools/audit-gate`) runs `pnpm audit` on every
PR and daily, sending the workspace dependency graph — package names and versions,
including the `@akasecurity/*` workspace importers — to the registry's audit endpoint; it
also resolves and audits the published CLI's runtime dependency ranges with `npm` in a
temp dir, sending that (public-package) graph the same way. The binary channel's packaging
is the second such path: `cli/scripts/package-sea.mjs` shells out to `npm install` to place
the Next standalone server's runtime dependencies (`next`, `react`, `react-dom` and their
transitive graph) inside the archive, so `release-binaries.yml` and `build-binaries.yml`
both reach the registry — and `pnpm package:sea` does not run offline. Both are repository
tooling, not product paths; nothing a user installs performs either.

**Three gates enforce this, and they cover different things.** Losing track of which is
which is how "enforced by ESLint and CI" becomes a claim nobody has checked:

| Gate                                          | Catches                                                                                              | Cannot see                                                                                                                                                                                                                  |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The ESLint ban (`@akasecurity/eslint-config`) | A network primitive **written** into source                                                          | A transitive dependency, a non-literal `import()`; a file no lint pass targets; **itself** — an inline `eslint-disable` takes the ban off the line below it, which is why the directives are inventoried separately (above) |
| `test/setup/no-network.ts` (every vitest run) | A non-loopback connect **called** at test time, on this thread and in any **worker** spawned from it | A child process — it has its own copy of `node:net` — and therefore any worker that child starts                                                                                                                            |
| The `No-network` CI job (`ci.yml`)            | Anything in the process tree, subprocesses included                                                  | A path the suite never executes; it is Linux-only                                                                                                                                                                           |

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

The plugin — and the web dashboard's folder scan — also start a **worker thread** (`@akasecurity/plugin-sdk`'s isolated scan, below). A worker is not a child process and opens nothing: it runs the same in-repo detection engine on a second thread of the same process, and today it reaches out nowhere. Say that as a description of what it **does**, never of what it **can** do — a worker has the full `node:net` surface, and its fresh module registry means an in-process patch does not reach it unless something puts one there. Two things do. The runtime guard re-installs itself into every worker spawned from a guarded thread (see [Testing](#testing)), which covers the suite; the Linux `No-network` job covers the shipped artifact, because a network namespace applies to every thread in the tree. The worker is listed here so an audit of "what else executes" finds it.

### 5. A scan that cannot be interrupted runs off the main thread

`scan()` is synchronous and a regex has no upper bound, so a catastrophic pattern is not a stall but a **detection bypass**: the hook blows its 10 s harness timeout, and a timed-out hook fails open, letting the whole tool call through unscanned. Nothing on the calling thread can interrupt a running `exec`; the fail-open `catch` only catches throws.

Two gates sit in front of that, and **both run on a worker thread**, because both are unbounded runs of an untrusted pattern:

- **The timing pre-flight** (`packages/plugin-sdk/src/rule-quarantine.ts`) measures every pulled/custom-pack regex rule against the adversarial probe battery once, caches the verdict locally, and excludes a rule that blows the budget. This is **empirical** — it proves a pattern did not backtrack on the inputs the battery constructs, not that it cannot. And the battery decides by _driving the pattern into backtracking_, so measuring a rule is itself a way to hang on one: `(a|a|a|a)+$` passes `Rule.safeParse` and never returns on the battery's own derived probe. So `filterUnsafeRules` takes a **prober** and the plugin runtime always supplies one — the measurement runs where it can be killed. Without a prober it falls back to the calling thread, which is for callers that already control the rules they pass (tests, tooling), never a pulled pack.
- **The isolated scan** (`packages/plugin-sdk/src/guarded-scan.ts` + `isolated-scan.ts` + `scan-worker.ts`) is the bound on the scan itself. Whenever the effective ruleset contains a regex rule that only the pre-flight stands behind, the whole scan runs in a `worker_thread` under a wall-clock deadline; `worker.terminate()` reaches V8's execution terminator, which interrupts a spinning regex. The terminated rule is quarantined through the pre-flight's own cache, so the next process never loads it, and the built-in packs keep detecting meanwhile.

Five properties are load-bearing and easy to break by accident:

- **The fast path must stay free.** A machine with no pulled or custom regex rule — the overwhelming majority — starts no worker and pays nothing. Nor does a machine whose verdicts are all cached, which is the steady state: the prober is built on first use. Do not widen the isolation to every scan; the permanent per-call tax is exactly why this was deferred once.
- **An ordinary scan is one `scan()` call.** Naming the rule that hung needs a pass that walks the unverified rules one at a time, and that pass is a **retry** of a scan that already timed out — never a tax on the scans that succeed. Worst case for a hang is therefore two deadlines, paid once per scanner (per process for a hook, per request for the dashboard); move that pass onto the happy path and the isolated cost stops scaling like the in-process cost.
- **The whole ruleset goes into the worker, never half of it.** Splitting the scan across two `scan()` calls breaks `requiresNearby` corroboration between the halves and silently drops findings.
- **Worker startup is charged to no deadline.** The worker posts `ready` before the parent starts the clock. Fold startup into the job budget and a cold or contended machine looks exactly like a catastrophic rule — and that misreading gets a legitimate rule quarantined forever.
- **The kill leaves no trace in anything the deadline returns.** The `timeout` outcome, the named culprit, the replacement thread — every one of those comes from the timer, and a rule that never returns reports nothing either way, so replacing `terminate()` with a no-op keeps the whole suite green while each hang leaks a thread that goes on burning a core. What pins it is a fixture that spins for a bounded stretch and reports through shared memory (`plugin-sdk/test/helpers/spinning-scan-worker.ts` + `spin-counters.ts`), because only work that WOULD have finished can show that it did not: a killed thread must post neither a further heartbeat nor a completion. The **pre-flight** is the case to keep — it warns and keeps iterating, so one pass leaks a thread per hostile rule where a scan leaks at most one. Those cases assert no elapsed time and must not grow one: a thread that was not stopped is at every instant either still executing or already finished, so the two readings are exhaustive between them and a slow runner blunts one only by sharpening the other.

The first two are **counted, not timed** — a different claim from the fifth, which forbids an
elapsed assertion outright because its two readings are already exhaustive. How many threads a path builds is the property —
none on the fast path, one for the pre-flight, two for a hang that has to be recovered and then
attributed — and `IsolatedScanOptions.onWorkerStart` reports each construction so
`packages/plugin-sdk/test/{runtime-isolation,isolated-scan}.test.ts` can assert the number
directly. Elapsed ceilings sit beside those counts and answer a different question: a ceiling
loose enough to survive a cold start on a contended runner (the two-cycle case is granted 75s
against a shipped worst case of ~14s) swallows a whole extra cycle without noticing, so it can
only separate "this path got slower" from "this path stopped terminating" — which the per-test
timeout cannot. Do not fold one into the other, and do not answer a flake here by widening a
ceiling that was never measuring the property.

A quarantine verdict is the one detection decision the machine reaches on its own, from a wall-clock measurement, and it is cached forever. So it is **recoverable and visible**: `aka detections unquarantine` forgets every quarantine verdict (keeping the `safe` ones, which are measurements worth keeping), and `aka detections` reports the count. The stderr line the plugin writes names the command, because a hook's stderr is otherwise the only place the machine ever mentions it; the dashboard's folder scan writes the same line to the server's console and additionally returns a notice to the page, since nobody is reading a server log while they click Scan. Anything that adds a new way to quarantine must keep those surfaces true.

**Only a MEASURED rule is quarantined, and only that line may name the command.** A rule leaves the pre-flight three ways, and `rule-quarantine.ts` says which: measured and over budget (`quarantined rule "…"`, with the `unquarantine` hint, since a row exists to clear); never reached because the pass budget ran out (`skipped rule "…"`, no hint, back on the next pass); and never measured because there was nowhere killable to measure it. The third is **not a per-rule line at all** — it is one line for the whole pass, carrying the prober's own `unavailable` reason and naming no rule, because a missing or unstartable worker excludes EVERY pulled/custom regex rule on the machine from every scan until the install is repaired. It is a property of the install, and a fault the ruleset cannot fix. Collapsing any of the three into the timing wording is the defect this replaced: two of them cache nothing, so a user sent to `aka detections unquarantine` reaches a list their rule is not on, and a user told their rule blew a timing budget goes to audit a ruleset that is fine. `packages/plugin-sdk/test/rule-quarantine.test.ts`'s `what the pre-flight says on stderr` holds it, pairwise — a future collapse goes red whatever the new wording is.

The worker is a **build entry**, not a source file the loader finds: the published plugin ships `scripts/` only, so `plugins/claude-code/tsup.config.ts` emits `scripts/scan-worker.js` beside the hooks and the SDK resolves it as a sibling. A worker URL resolved against a source path works in the repo and under vitest and fails only once installed — `plugins/claude-code/test/e2e/scan-worker-bundle.e2e.test.ts` is what pins it, by driving a **built** hook against a throwaway home with a pulled rule installed.

**Where else the bound applies, and where it does not.** The capture path is `runtime.evaluate`, and so every hook plus `@akasecurity/scanner`. The dashboard's folder scan is the second caller and reaches the same two gates through `packages/local-ops/src/guarded-scan.ts` — `web-ui/app/(app)/scan/actions.ts` builds a `createGuardedFileScanner` over the installed-pack snapshot and hands `scanPathIntoStore` its `scanText` seam, never the raw `rules`, which is the in-process path. Three things differ there and each is load-bearing:

- **The scanner is per REQUEST, not per process.** The first hang retires isolation for the scanner's whole life; the dashboard server outlives every scan it runs, so a process-wide scanner would cost it its pulled rules until someone restarted it. That is also why `createGuardedScanner` takes a `degradeScope` — the stderr warning must not claim a lifetime it does not have.
- **The worker location is a caller input** (`GuardedFileScannerOptions.workerUrl`), never the SDK's sibling lookup. A Next build replaces `import.meta.url` with the BUILD MACHINE's absolute source path, so that lookup resolves where the build ran and nowhere else — silently costing an installed dashboard its bound. `web-ui/tsup.config.ts` emits the worker to `web-ui/dist/scan-worker.js`, `next.config.ts` traces it into the standalone build, and `web-ui/app/lib/scan-worker.ts` resolves it against `process.cwd()` (the app dir: Next's standalone `server.js` chdirs to its own directory, and every other launch runs from the package). Those three move together, `web-ui/test/e2e/scan-worker-bundle.e2e.test.ts` pins the first and third, and `cli/scripts/bundle-web-ui.mjs` throws at pack time if the second stopped working.
- **With no worker, a rule that cannot be bounded is dropped, not run** — including one the pre-flight already cleared, since that verdict is empirical. The scan says what it dropped (`GuardedFileScanner.dropped()` → the Scan page's notice); it does not quietly run a smaller ruleset than the Detections page lists.
- **A dropped rule is only ever pointed at `aka detections` when a verdict was actually cached.** `DroppedRules` splits on that — `quarantined` was measured and left a row, `unmeasured` was never timed here (no worker, or the pre-flight's pass budget spent) and deliberately leaves none, since caching a verdict for a rule nobody measured would disable it forever. Only the first has anywhere to send someone, and `countQuarantined()` — the value the command itself prints from — is what the notice gates on. Any new way to drop a rule has to say which of the two it is.

Two `scan()` calls inside the SDK are not exposure: `mask.ts` and `tokenize.ts`'s self-scan both pass `getLoadedRules()`, the compiled-in registry the CI battery gates on every commit, so no pulled pattern reaches them. `aka scan` passes no ruleset and falls back to that same registry, so the CLI runs in-process by design and is not exposed — passing it an installed snapshot instead would put an unreviewed regex on an unbounded path.

What remains uncovered is the packaged artifact: nothing installs the published CLI and drives its dashboard's folder scan under a hostile pack, so the chain above is proven link by link rather than end to end.

### 6. Every writer of `settings.json` takes its lock

`writeOwnerOnlyFileSync`'s tmp+rename makes each PUBLISH indivisible. It does not make a
**read-modify-write** indivisible, and that is the shape every settings write has: read the file,
merge answers over it, rename the result. The plugin, the CLI and the dashboard are three separate
processes over one home, so two of them read the same bytes and the second rename discards the
first one's answers — with both reporting success, because neither ever learns the other existed.

`withFileLock` (`packages/persistence/src/file-lock.ts`) is the section around that pair. It is the
existence of a sibling `<file>.lock`, taken with an exclusive create — `flock` has no Windows
equivalent, and an fd-held lock is lost by any writer that opens the file a second time. Six
properties are load-bearing:

- **It is ADVISORY, and it is scoped to one file.** A writer that skips it is not excluded by the
  ones that take it, so the guarantee is only as wide as the set of writers holding it. Two
  writers hold it today: `applyOnboarding` (which the `/aka:setup` wizard and the dashboard's
  Settings action both go through) and `aka init`'s create-if-absent. A third that writes
  `settings.json` directly reopens the hole for both. **Other `~/.aka` files are NOT covered** —
  `fingerprint.ts`'s key ROTATION and `local-ops`' `update-cache.ts` are unlocked
  read-modify-writes with the same shape, and each is its own outstanding fix. The first MINT
  is no longer one of them, and it was not fixed with a lock: `createKeyFile` publishes through
  `createOwnerOnlyFileSync`, which links an already-complete tmp into place, so exactly one
  caller wins and every loser reads the file back and ADOPTS the winner's key. That works only
  because a first mint has nothing to preserve — rotation must replace an existing file, so it
  still reads the current version and writes version+1 over it, and the same fix does not reach
  it. Do not read this section as a property the store has; it is a property `settings.json`
  has.
- **Anything derived from the current file is derived INSIDE it.** `applyOnboarding` takes an
  updater function for exactly this: a caller that reads first and passes a plain object has put
  its read outside the lock and kept the lost update, one frame further out. The dashboard's
  vault-consent carry-forward is the worked example — read outside, it writes a grant back over a
  concurrent revoke.
- **It fails loudly rather than writing unlocked.** The fields at stake include the vault and
  model-judge consent grants, so the write that goes missing can be a REVOCATION. A refused save
  the user retries beats a silent one they never learn about.
- **A killed holder must not wedge the file, and a slow one must not be evicted.** Taking an
  abandoned lock needs BOTH that its own recorded acquire clock is older than the stale window and
  that the pid it names is gone. Age alone evicts a holder that is merely suspended or throttled,
  which puts two writers in the section — the defect, reintroduced by its own recovery. The clock
  is read from the lock BODY, never from mtime, which on a network home is the file server's clock
  and drifts a fresh lock straight into staleness. `FileLockError.reason` separates `timeout`
  (contention) from `unavailable` (a directory that will never hold a lock); `aka init` branches on
  it, swallowing the first — another writer is already creating the file — and propagating the
  second, which is the fault its pre-lock write raised too.
- **A release must prove it still owns the lock.** Each acquisition writes a token and removes the
  file only while that token is still there — an unreadable body counts as somebody else's, since
  a lock exists for an instant between its exclusive create and its body write. Unlinking by path
  alone means a holder that was stolen from deletes its successor's lock, and the section is
  unguarded while that successor is mid-write, every writer reporting success.
- **Recovering an abandoned lock is itself a critical section**, held by a second exclusive file.
  Several waiters meet the same dead lock at once; unserialised they all judge it stale, one
  removes it and takes a fresh lock, and the next one's removal lands on THAT. Neither a rename
  nor a re-read closes it — every check is separated from its removal by a window another waiter
  acts in, and a rename that has to be undone clobbers whatever took the path meanwhile. Measured
  at 5 of 12 trials losing an update with eight waiters over one abandoned lock; zero once the
  judging and the removal became one section.

`packages/persistence/test/concurrency/settings-race.test.ts` is what holds this: real child
processes, released together on a readiness handshake, asserting no answer is lost and no
revocation is resurrected. It uses processes rather than worker threads deliberately — a worker
shares `process.pid`, and the atomic write's tmp path is per-process, so two threads meet a
collision two processes never can, which is the wrong axis.

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
`auditConfig.ignoreCves`/`ignoreGhsas` is not an approved suppression route, and the
gate refuses to run (exit 3) when it is set. **It is detected by reading the two files
pnpm takes the setting from — the root `package.json`'s `pnpm.auditConfig` and
`pnpm-workspace.yaml`'s top-level `auditConfig` — not by inspecting what pnpm returns.**
The payload cannot reveal it: pnpm removes a muted advisory from `advisories`, decrements
the `metadata` severity counts to match, and leaves the top-level `muted` array **empty**,
so a muted run is byte-for-byte the shape of a clean one. A guard reading `muted` is
therefore correct in isolation and unreachable in practice — which is what it was, while
both audits reported green. `assertNothingMuted` is kept as the payload-side half in case
a later pnpm does populate the field; `assertNoAuditConfigMutes` is the half that fires.

Both channels are real and were measured; `.npmrc` is not one, in either the flattened or
the camelCase spelling. `findAuditConfigMutes` refuses on the **presence** of the
`auditConfig` key — in **both** channels alike, and whether or not the ignore lists under
it carry entries. So an empty one is refused too, and a third key added by a later pnpm is
caught without a code change, because the key names are never enumerated. The two halves
have to answer alike here or the rule stops being statable: the YAML half cannot tell an
empty `auditConfig` from a populated one without a parser. A file that **exists but cannot
be read** is refused rather than read as "no config here" — absence means `ENOENT` and
nothing else, since a failed read that returned "nothing to see" would reach the exact
outcome this check exists to prevent. Its tests pin the discriminating case directly: a
payload reporting nothing muted **and** a manifest configuring `auditConfig` must still be
refused — delete the file read and that case, alone, goes red.

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
plugins/codex        → @akasecurity/plugin-runtime, plugin-sdk
plugins/antigravity  → @akasecurity/plugin-runtime, plugin-sdk
plugins/browser-extension → @akasecurity/plugin-runtime, plugin-sdk (the native-messaging
                     host only — Node side); the browser-side content script bundles just
                     `@akasecurity/plugin-sdk/browser` (mask.ts's Node-API-free slice) and
                     must never import anything Node-only
@akasecurity/plugin-runtime → @akasecurity/plugin-sdk, persistence, schema
@akasecurity/plugin-sdk     → @akasecurity/detections, persistence, schema
                     (provider resolution for the session-root snapshot reads the host env
                     directly at SessionStart — `provider.ts` for Claude Code,
                     `provider-codex.ts` for Codex CLI, `provider-antigravity.ts`
                     for Antigravity, each its own file-scoped
                     `n/no-process-env` opt-out), ignore (gitignore semantics for
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
@akasecurity/setup-wizard   → @akasecurity/plugin-sdk, schema, zod
                     (the harness-agnostic core of the /aka:setup calibration →
                     triage → remediation flow: pure logic plus dependency-injected
                     orchestration. It must NEVER name a host command, hardcode a
                     transcript location, or spawn a judge — each plugin supplies
                     those at its own I/O boundary, which is what lets multiple
                     harness plugins share this without forking it.)
```

All three CLI plugin packages bundle the SAME `plugin-runtime`/`plugin-sdk` core and differ
only in their own thin hook-entrypoint layer (stdin/stdout glue matched to each host's hook
contract) plus the harness-specific bits `plugin-sdk` deliberately keeps file-scoped (provider
resolution, tool-name → scannable-field tables).

**The hosts' hook contracts are NOT equivalent, and the differences are behavioral, not
cosmetic.** Each plugin's `skills/setup/SKILL.md` carries a "Known limitations" section that
is the authority on what its host can actually enforce; keep it accurate when the adapter
changes. The gaps that exist today:

- **Codex** does not yet fire PreToolUse/PostToolUse for `apply_patch` (file-write) calls,
  only `Bash`.
- **Antigravity** is the most constrained and the most different. It has only five events —
  no `SessionStart` and no `UserPromptSubmit` — so the once-per-session inventory pass hangs
  off the first `PreInvocation`. That event carries **no prompt text**, so prompts can be
  neither blocked nor redacted. `PreToolUse` has **no `updatedInput` equivalent**, so a
  `redact` policy escalates to a deny for every field (not just executable ones, the way
  Codex escalates), and a `warn` has no channel to print on. `PostToolUse` receives **no tool
  result at all**, so there is no live response scanning and no `tool-response.ts` /
  `scan-response.ts` counterpart in that package.
- **Antigravity also fails CLOSED**, which inverts this repo's §1 rule at the boundary: a
  hook that exits non-zero, is killed on timeout, or prints nothing is read as a `deny` on
  every tool call. "Fail-open" there therefore means _always printing an explicit_
  `{"decision":"allow"}`, which is what `runHookFailOpen` in
  `plugins/antigravity/src/hooks/shared.ts` guarantees — including on a throw and on its own
  watchdog. A silent exit is a bug that would block the user's every tool call. The guarantee
  holds over everything that **yields** and cannot reach a body that blocks the thread; §1
  states that limit and names the two suites that cover each half.

**Cross-cutting rules:**

- No `process.env` reads except the sites that explicitly opt out of `n/no-process-env` — §3 tables them, and deliberately is not restated here: a second copy of that list is how the count drifted last time.
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
plugins/codex/        the Codex CLI plugin (hooks + skills; self-contained npm bundle)
plugins/antigravity/  the Antigravity plugin (hooks + skills; self-contained npm bundle)
plugins/browser-extension/  the Chrome extension for ChatGPT + Claude.ai web chat (MV3
                      content scripts + a native-messaging host; private — bundled into
                      the CLI by `bundle:extension`, installed via `aka extension install`)
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
   the full ruleset over `test/setup/**`, `test/fixtures/**`, `tools/ci/**`, and the
   repo-root `*.config.*`. `typecheck:root` runs `tsc -p tsconfig.root.json`.

   It used to carry a second, network-only invocation over the plain-JS
   enforcement suites in `packages/eslint-config/test/**`, because that package's
   `lint` was a deliberate no-op and a root pass was the only thing that could
   reach them. It lints itself now — `eslint src *.config.*` then
   `eslint --no-config-lookup -c eslint.guard.config.mjs test`, the same
   full-ruleset + network-only split every other two-pass package makes — so those
   suites are covered by the ordinary per-package check and nothing about them is
   special any more.

   **Naming a target is not enough here either.** The rule the package paragraph
   above draws applies to `lint:root` unchanged: an `--ignore-pattern` cancels a
   target it matches, and an `--ignore-path` cancels the whole invocation, so the
   script reads as covering a repo-root file that ESLint then skips. Either way the
   file counts as **uncovered** and the failure names it, and the fix is to drop the
   flag rather than the target. This is enforced rather than remembered — the
   derived check below reads each invocation's ignore flags next to its own targets,
   so an ignore that takes a root file back out fails exactly as a missing target
   does.

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

All four shippable artifacts are **self-contained bundles of the workspace** — their `tsup.config.ts`
sets `noExternal: [/^@akasecurity\//]`, so every `@akasecurity/*` package they use is inlined into
the published output (the user's machine has no `node_modules`). So a change to a _bundled_ package
changes the shipped artifact **even when the app's own `src/` is untouched**:

- **`plugins/claude-code`**, **`plugins/codex`** and **`plugins/antigravity`** each bundle
  `@akasecurity/plugin-runtime` + `plugin-sdk` and everything they pull in —
  `@akasecurity/schema`, `persistence`, `detections`. A change to any of those changes ALL
  THREE plugins' `scripts/*.js`.
- **`cli`** bundles the same `@akasecurity/*` packages **and** ships the OSS web-ui
  (`web-ui` is `external` to the CLI JS but copied in by `prepack`'s `bundle:web-ui` and
  spawned as a separate Next server). So a web-ui change — or any bundled-package change — changes the CLI.

When a change touches the web-ui or any bundled package and the user wants to publish:

1. **Bump every affected artifact**:
   - web-ui / `local-ops` / `dashboard-ui` / `ui-kit` change → `cli` (bundled into the CLI JS
     and/or the web-ui it ships; the plugins bundle none of these).
   - `schema` / `persistence` / `plugin-runtime` / `plugin-sdk` / `detections`
     change → **all four** of `cli`, `plugins/claude-code`, `plugins/codex` **and**
     `plugins/antigravity` (all bundle them).
   - `setup-wizard` change → `plugins/claude-code`, `plugins/codex` **and**
     `plugins/antigravity` (all three bundle it; the CLI does not).
   - The CLI and all three plugins normally move together on one shared version line.
2. Keep `plugins/claude-code/.claude-plugin/plugin.json` in sync with
   `plugins/claude-code/package.json`, `plugins/codex/.codex-plugin/plugin.json` in sync
   with `plugins/codex/package.json`, and `plugins/antigravity/plugin.json` (Antigravity reads
   its manifest from the plugin ROOT, not a dotted dir) in sync with
   `plugins/antigravity/package.json` (identical version within each pair) whenever that plugin
   is bumped.

**The bump is not a decision to surface during feature work, because it is not made there.**
Pre-1.0.0 the version numbers are chosen **ad hoc**, at the **scheduled release** (twice a week)
— not per change. So do not ask which release type to use, and do not raise "this touches a
bundled package, so it needs a version bump" as an open question, a follow-up, or a caveat in a
summary or PR description. The steps above are what a **release** does: which artifacts move is
derivable from the bundling rules, and how far they move is settled at release time by whoever
cuts it.

Versions are bumped by hand in a `chore(release):` commit (no changesets). Every release is a
bare `X.Y.Z` on the one shared version line — never a pre-release suffix. The CLI and both
plugins currently share the `0.9.x` line.

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

### Benchmarks are a trend, never a gate

```bash
pnpm bench                                    # every package that has benchmarks
pnpm bench --filter @akasecurity/detections   # just one
```

`vitest bench` (no second framework), one `bench/*.bench.ts` per package, a `bench` turbo
task, and a nightly `bench.yml` on `main` that uploads each package's
`bench-results.json` as a workflow artifact. **Nothing gates a PR on wall-clock.** Hosted
runners vary by a large factor on neighbour load alone — this repository has retuned three
timing assertions for exactly that — so a wall-clock check on a PR fails for reasons
unrelated to the diff, and a check that cries wolf is one people learn to re-run until it
is green.

What DOES gate a PR is the timing **guards**, which are correctness assertions rather than
measurements: the adversarial-rule bound in `packages/detections/test/security/redos.test.ts`
and the isolation ceilings in `packages/plugin-sdk`. Keep the two apart — a benchmark that
threw would be a timing gate wearing a different name.

Four properties are load-bearing, and each is enforced by
`packages/eslint-config/test/bench-harness.test.js` rather than remembered:

- **`cache: false` on the `bench` turbo task.** Every other task derives its output from
  its inputs, so replaying one is sound; a benchmark returns a MEASUREMENT, and the machine
  it ran on is in none of the hashes. A cache hit hands the trend another runner's number
  and labels it this run's — the one stale green that cannot be spotted by reading it.
- **A package holding benchmarks declares a `bench` script.** `turbo run bench` skips a
  package without one silently and exits 0, so the nightly job goes on reporting success
  having measured nothing.
- **`bench/` is a lint target and a tsconfig `include` like any other source directory.** A
  bench file imports product code; outside those, its types are stripped unchecked and the
  network bans never apply to it.
- **`bench.yml` has no `pull_request` trigger**, still runs nightly, and still uploads.

A benchmark carries no assertions, so anything a bench file would otherwise have checked
about its own input belongs in a test instead. `generateCaptureCorpus` is the worked
example: it writes through the product's own `recordCapture` (so the corpus cannot drift
from what the product writes), wraps the whole corpus in one transaction, and — because
`recordCapture` is fail-open — **counts the rows that actually landed and throws when they
are not there**. Without that last check a locked or full store hands back an empty one and
every downstream measurement is a timing of nothing, reported as a fast one.

### Store scale: what is bounded, and what grows for ever

`packages/persistence/test/performance/` holds the scale guards, and they are **tests
rather than benchmarks** because each asserts a size, a query plan or a row set — none
of them a wall clock. A benchmark reports a trend and gates nothing; these fail a PR.

**No gate here asserts an elapsed time against a budget, and one used to.** The two
per-call store costs are gated as a **ratio of the same cost at two store sizes**
(`scale-budgets.test.ts`, 2k against 20k), because a ratio cancels the runner: half the
machine halves both sides and moves the quotient not at all. The absolute form was tried
first — a p95 against a budget ~165x the median, which reads like unmissable headroom —
and it reddened a healthy tree twice, at 43 ms and 277 ms against a 30 ms budget on one
commit. A shared runner does not get 1/165th as fast, it gets **preempted**, and a
preempted sample has no upper bound; no headroom multiple fixes that. Anything newly
added here follows the ratio shape, and **`p95` is not the estimator to build one from** —
measured across idle and 3x-oversubscribed runs, a p95 ratio spread 4.6x on capture and
17x on open, where the same ratio over the **fastest** sample spread 1.08x and 1.06x.
Noise only ever adds time, so the minimum of n is the estimator a loaded runner cannot
inflate.

One absolute bound survives, and only as a **gross-regression backstop** four orders of
magnitude clear of the measurement: a ratio is blind to a constant-factor regression
(0.06 ms → 500 ms at every size keeps a ratio of 1.0), just as the backstop is blind to a
scaling one. They catch different defects; neither substitutes for the other.

The numbers, measured on arm64 macOS / Node 24 against corpora from
`src/test-fixtures/generate.ts`:

| Property                                  | Measured                           | Gate                    |
| ----------------------------------------- | ---------------------------------- | ----------------------- |
| Store growth, 5k → 10k                    | **797.9 B/event** marginal         | ±15% band ✅            |
| `recordCapture` 2k → 20k                  | ratio **1.02** (fastest of 200)    | ratio < 3 ✅            |
| `openLocalDatabase` 2k → 20k              | ratio **0.99** (fastest of 20)     | ratio < 3 ✅            |
| `recordCapture` at 1M rows                | 0.076 ms median, 0.116 p95 (n=200) | backstop ≤ 1,000 ms ✅  |
| `openLocalDatabase` at 1M rows            | 0.55 ms median, 0.72 p95 (n=20)    | backstop ≤ 1,000 ms ✅  |
| `/security` (8 aggregations) at 1M events | **5,945 ms** median of 5           | ungated (misses 2 s) ❌ |

**Both pairs came down from a decade higher, and the reason is worth carrying.** They
were 5k → 50k and 10k → 20k, and at those sizes the two files were the largest single
pieces of work `@akasecurity/persistence` does — `scale-budgets` seeded for 117 s on a
macOS CI run that passed and 135 s on one that did not, against a 120 s hook ceiling. A
3% margin is not headroom, and it landed both ways inside one afternoon. The property in
each case is a RATIO or a SLOPE, and neither needs a particular absolute size, so the
corpus came down rather than the ceiling going up. The prices are stated where they are
paid: the ratio's sensitivity floor moved by 2.5x (below), and the growth band's centre
had to be retaken, because the marginal creeps with size — 791.3 B/event across 2.5k→5k,
797.9 across 5k→10k, 818.4 across 10k→20k, all measured, all byte-identical run to run.
**Do not carry a centre across a size change**; a stale one still reads green.

**A ratio gate has a sensitivity floor, and it is worth knowing before trusting one.**
The quotient is `(base + 10k) / (base + k)`, so clearing a ceiling of 3 needs the
size-dependent term to reach 2/7 of the baseline — ~15 us against `recordCapture`'s ~53 us
(measured 53.4 us at 2k and 53.0 us at 5k, i.e. flat in the corpus size),
i.e. a per-row slope of ~7.6 ns. Adding a `SELECT COUNT(*)` to that path is genuinely
linear and does **not** redden it: SQLite answers the count from a covering index. The
same scan with the index defeated (`WHERE LENGTH(id) = 999`, ~40 ns/row) reads 4.739 and
fails. So a ratio gate catches a linear cost that changes what the operation costs, not
one inside its noise floor — and the floor is proportional to the SMALL size, so cutting
the pair by 2.5x raised it by 2.5x.

**`/security` misses its budget, and it is not a missing index.**
`hot-read-query-plans.test.ts` drives every read the `/security`, `/activity` and
`/vault` pages issue and confirms each one runs indexed. That capture runs at 3k and
nothing re-captures the plans above it: the store carries no `ANALYZE` statistics, so
SQLite plans from the schema rather than from row counts and the plans are EXPECTED to
hold at 1M — reasoning, not a second measurement, and worth wording that way. The
cost is that FOUR of the eight never shrink with the window at all: `severitySummary`,
`recentFindings` and `recentlyResolved` take no range argument, and `mttrTrend` takes one
whose `EXISTS` prefilter bounds the RESULT rather than the scan (measured at 1,523 ms
returning zero rows). All four are linear in total FINDINGS, not events. And the page's
`Promise.all` buys nothing: every repository method here runs its SQL **synchronously**
and returns an already-resolved promise, so the page costs the SUM of the eight.

Linear past 100k at 6.19 ms per thousand events (373 ms at 100k, 5,945 ms at 1M, both
measured), so the budget is crossed near **363k events** (~300 MB). Fixing it means
bounding what the page reads — retention, pre-aggregation or a cap — which is a product
decision, not tuning.

**Two tables have a retention policy; six do not.**
`BLOCKED_DETECTIONS_RETENTION_MS` (24 h) sweeps `blocked_detections`, and
`EXCEPTION_RETENTION_MS` (90 days) sweeps terminal `exceptions`. `audit_events`,
`inspection_findings`, `inspection_definitions` and the three `secret_vault*` tables have
none — and `audit_events.content` is a full prompt corpus, so that is 818 B for every
prompt, response and tool-call body the machine has ever produced. The vault tables raise
a second concern beyond size: an entry nobody will reveal again is a ciphertext that
stays decryptable for as long as its key epoch survives. `retention-surface.test.ts` pins
the split behaviourally, with a positive control on the swept pair, so adding retention
for one of the unbounded tables is a deliberate edit rather than a silent one.

**`wal_autocheckpoint` is not set, and that does NOT mean the WAL is unbounded.**
`openWithPragmas` leaves it alone, so SQLite's own default of 1000 pages applies: at the
store's 4 KiB page size the log settles at about 4.2 MB and stays there — peak 4,198,312 B
measured over 20,000 committed captures. The unbounded case is a long TRANSACTION — a
checkpoint cannot run inside one — where the same 20,000 writes peak at 12,219,952 B, and
the fixture generator's 1M-event transaction grows the log by its whole page footprint,
which is hundreds of megabytes. Nothing on the capture path does that (every
`recordCapture` commits, and every hook is its own process), but a batch importer would.
Do not "fix" the pragma without re-reading `store-growth.test.ts`.

That WAL case is **skipped on Windows, on cost rather than on behaviour.** Demonstrating
the bound needs 20,000 SEPARATE commits — a checkpoint cannot run inside a transaction, so
batching them removes the property under test — and each one is an fsync on the platform
that charges most for it; it overran its own 180 s setup ceiling there and starved
neighbouring suites on the shared leg while doing it. What it asserts is SQLite's page
arithmetic, which does not vary by filesystem, so the other two legs cover it. Lowering
the event count instead is the worse trade: the count is what puts a log that never
checkpointed several times over the ceiling, so cutting it weakens the assertion on every
platform to buy coverage on one.

**`packages/persistence/bench/` is a separate tier, and it gates nothing.** `pnpm bench`
(turbo task `bench`, `vitest bench`) reports a TREND — the trajectory the table above was
taken from — and carries no assertions, because this repo does not gate a PR on
wall-clock. Its turbo task sets `cache: false`: every other task returns the same answer
for the same inputs, but a benchmark returns a measurement, and the machine it ran on is
not in the hash, so a cached hit would report another runner's number as this run's.
The nightly `.github/workflows/bench.yml` runs it unattended and uploads each package's
`bench-results.json`; the table above was taken by hand and is re-taken the same way.
Never wire it to a PR gate. Anything that must HOLD belongs in `test/performance/`
instead — restated as a **ratio** against a second store size, not carried over as the
elapsed number the bench prints, which is the one form that cannot survive a shared
runner.

Corpus scale is what decides where a scale test can live. Seeding is not flat per event,
so a six-figure corpus belongs in a `beforeAll`, where it is charged to `hookTimeout`
rather than eating a test's own budget before the first assertion. A synchronous body
cannot be interrupted, so one that overruns runs to completion and is then reported as a
timeout, which reads as a budget failure and is not one. Cut the corpus rather than
raising the ceiling.

**Take the rate yourself before sizing anything against it, and take the CI-to-local
FACTOR too — that factor, not the local rate, is what has cost a red main.** Measured as
the fastest of three seeds into a fresh store through `seedCaptureCorpus`, one warm-up
discarded, on arm64 macOS 26.5.2 / Node 24.18.0 with nothing else running: **0.0434
ms/event at 2k, 0.0427 at 3k, 0.0448 at 5k, 0.0558 at 20k, 0.0732 at 50k** (87 ms, 128 ms,
224 ms, 1.12 s and 3.66 s for the corpus). Seeding is not flat per event — it creeps ~1.7x
across that range — but there is **no step in it**, and no page-cache cliff: the rate runs
flat straight through 2,400 events (0.0434 / 0.0434 / 0.0427 at 2k / 2.4k / 3k).

What the 120 s ceiling in `scale-budgets.test.ts` was really missing is the runner
multiple. Seeding 5k + 50k costs 3.88 s locally, which is what that pair was sized
against and is accurate; the same hook took **116,970 ms on a macOS CI run that passed
and 135,237 ms on one that did not**, against a 120,000 ms ceiling — a factor of **~30x**,
not "several times". Size against the factor: 2k + 20k is 1.20 s locally, so ~36 s there.

Older figures in this section (a 0.091 ms/event rate at 3k, a cliff at ~2,400 events, and
the 100k and 1M rates of 0.096 and 0.639 ms/event) ran ~5-6x high and are retracted or
untaken. Re-measure rather than budget from them.

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

**It covers `vitest bench` too**, and by construction rather than by a second wiring:
bench mode resolves the same `vitest.config.ts`, so the same `setupFiles` entry loads.
Both halves were confirmed live there — the throw on a non-loopback connect, and the
`afterAll` backstop that fails a run where a refusal was swallowed. What that argument
rests on is a `bench` script not steering vitest at another config, which
`packages/eslint-config/test/bench-harness.test.js` asserts: a bench-only config missing
the entry would run product code unguarded while every existing assertion here, all of
which read the config the `test` script uses, stayed green.

Five things about it are load-bearing:

- **A refusal is recorded as well as thrown.** Almost every boundary here is
  deliberately fail-open, so a throw inside a `catch {}` would be swallowed and the
  run would go green having reached the network. `afterEach`/`afterAll` fail on any
  undrained record. A test that provokes a refusal on purpose must drain it with
  `takeBlockedAttempts()`.
- **It imports `node:net`/`node:dgram`/`node:dns`, which the lint ban forbids.**
  That is the enforcement, not a violation. `packages/eslint-config/test/no-network-runtime.test.js`
  lints the file and fails if it trips a **fourth** ban.
- **It re-installs itself into every worker it can reach.** A `worker_thread` gets a
  fresh module registry, so a worker used to escape the guard **silently** — nothing
  threw, and the parent recorded nothing for `afterEach` to fail on, which is worse
  than a miss. The guard wraps the `Worker` constructor (both the module property and,
  via `syncBuiltinESMExports`, the named-import binding `isolated-scan.ts` uses) and
  appends `--import <itself>` to the worker's `execArgv`. Wrapping the CONSTRUCTOR
  rather than the call sites is what reaches a worker **product code** starts, which
  is the case that matters; a worker's refusal cannot land in the parent's array, so
  it goes to a file `takeBlockedAttempts()` drains alongside it. Three consequences to
  keep true: that file is written only when a worker actually **refuses**, so a run
  that reaches for nothing touches the filesystem never and the drain reads a missing
  file as "no refusals"; it is **appended to and never truncated**, because a
  read-then-truncate drain destroys a refusal appended between the two; and a nested
  worker reports to the same file rather than stacking another preload onto `execArgv`.
  Any read failure that is not `ENOENT` fails the run — a channel that cannot be read
  reports zero refusals, which looks exactly like a clean one.
- **A child process is invisible to it**, which is the whole reason the `No-network`
  CI job exists. Do not describe the guard as covering shell-outs — and note that a
  worker started **by** such a child is out of reach for the same reason, since the
  wrapper lives in this process and the child never loaded it.
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

### The PATH shim, and why it fails OPEN

A suite that drives a **built** script cannot reach that script's spawn seams — they are
in-process, and the script is another process. So the external command is faked by putting a
controlled executable first on the child's `PATH`: the journey harnesses' judge stub
(`claude`/`codex`/`agy`) and `plugins/claude-code/test/provenance.test.ts`'s fake `npm`.

**A shim that does not land is not an `ENOENT`.** Resolution walks the rest of `PATH` and runs
the REAL installed binary — measured by joining `PATH` with `';'` on a POSIX host, which
resolved and executed the live `claude` CLI. So the failure mode is a suite that looks hermetic
while reaching a live model or the npm registry, and no gate above sees it: the ESLint ban reads
source, the vitest guard cannot follow a child process, and the Linux `No-network` job is the
only one that would — on the one platform where the shim happens to work.

`plugins/*/test/helpers/path-shim.ts` is the shared answer, and it is a **peer copy per
plugin** for the reason `no-echo.ts` is: a package wall blocks the import, and a copy takes its
`path-shim.test.ts` with it — or `assertShimResolves` can be weakened back into a no-op with
every caller staying green. Four properties are load-bearing:

- **Resolution is PROVEN before a chain is driven, not assumed.** `assertShimResolves` spawns
  the command the way the code under test will, so a miss is a red setup rather than a live
  call. It **performs** resolution rather than modelling it, so it agrees with libuv about
  `PATHEXT` instead of restating it.
- **`shell` and `cwd` must mirror the spawn being stood in for**, because the probe cannot
  discover either and PATH is not the whole of resolution. `provenance.ts` exports its
  `USE_SHELL` so the probe imports the runner's own condition rather than re-deriving it;
  `triage/judge.ts`'s `spawnClaude` uses no shell. **Windows searches the working directory
  before walking PATH**, so a probe taken under a different cwd than its subject faithfully
  performs a resolution the subject never performs — which is why the journey harness keys its
  proof by cwd rather than latching it once, its `run()` taking a per-step cwd.
- **The probe answer comes before anything else the stub does**, so probing is never recorded
  as an invocation — which is what a `judgeWasInvoked()`-style sentinel assertion rests on.
- **Three POSIX-only defects, not one**: `path.delimiter` rather than a literal `':'`, a `.cmd`
  launcher on win32 rather than an extensionless `#!` file, and no reliance on a `chmod` that
  is a no-op there. `tools/portability-gate`'s `path-separator-literal` rule catches the first
  returning to a call site, which is how it arrived.

`writeCommandShim` takes an optional `platform` (as `judgeEnv` does), so both branches are
driven from either host: writing the other platform's form is a resolution failure on this one.
Pin the **artifact** as well as the refusal there — a branch that wrote nothing also refuses,
and reads identically.

Two smaller things the same reasoning decides. The probe's own deadline sits **well under the
package's `testTimeout`**, because it runs inside a test body: equal deadlines mean vitest wins
the race and the refusal — the whole point of failing closed — is replaced by a bare timeout.
And `shimmedPath` returns the bin dir **alone** when there is no base PATH: an empty PATH entry
means the current directory to execvp and to libuv, so a trailing separator quietly puts the cwd
on a search path whose only purpose is that nothing but the shim is on it.

### The adversarial fixture corpus

`test/fixtures/adversarial/hostile-repo/` builds the hostile trees the tree walkers
have to survive — symlink loops, `..`-bearing names, nesting past the depth a path can
address, a `.gitignore` that ignores everything, 500k files ignored by directory and
the same number ignored by pattern. It sits at the repo root for the same reason the
no-network guard does: `project-files`, `local-ops`' folder scan and `scanner` all need
the SAME inputs, a package wall blocks the import, and three private copies of a symlink
loop drift apart. Only the first drives it today.

Two things about it are load-bearing:

- **Generators, not checked-in trees.** Most of these cannot live in git at all, and
  the ones that could would read as a mistake in a listing. Everything goes into a temp
  dir and comes back out through `cleanup()`.
- **A shape that cannot be built everywhere reports `created: false` with a reason, and
  the caller `ctx.skip`s on it** — a symlink needs a privilege on Windows, `chdir` is
  absent in a worker thread. An early `return` would report as a pass, which is the
  failure mode the store harness exists to remove.

**Depth is the part that is easy to get expensively wrong.** Creating a directory whose
absolute path exceeds `PATH_MAX` means descending with `process.chdir`, and the OS
re-resolves an ever-longer working directory on every step — so that descent is
QUADRATIC. Measured on an arm64 Mac: the first 500 levels take 35 ms, the next 1,000
take 4.0 s, the next 2,000 take 31 s, and a 10,000-level chain costs ~348 s to build
and ~347 s to remove. `deepChain` therefore builds the addressable part with plain
absolute `mkdirSync` (one syscall a level) and gets PAST the ceiling by making a
handful of NAMES 255 characters rather than the chain deep. A fixture that reaches for
literal 10,000-deep nesting is not thorough, it is a timeout.

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
- `corpus.ts` — `seedCaptureCorpus(db, options)`, a deterministic store of a stated SIZE
  written through the product's own `recordCapture` inside one transaction, plus
  `corpusConnection(db)` and the corpus clock (`CORPUS_EPOCH_MS`, and
  `GeneratedCaptureCorpus.endsAt` — prefer the latter). Two rules. **Drive every windowed
  read with the corpus clock**, never `Date.now()`: the corpus is stamped from a fixed
  2024 epoch, so the wall clock puts every `WHERE … >= :from` years past the data and the
  read matches nothing while still returning a real plan and a real, meaningless number.
  And **reach the connection through `corpusConnection`, never `UNSAFE_TEST_ONLY_RAW_HANDLE`
  directly, from anything outside `test/`** — `bench/` is not a `test/` path, so a
  `*.bench.ts` naming that seam is read as a product caller and fails
  `packages/eslint-config/test/test-only-seam.test.js`.
- `query-plans.ts` — `recordingConnection(db, into)` captures the SQL and the bound
  parameters as the repositories execute them, and `explain` / `classifyPlanRow` /
  `indexOwners` turn one into a plan step (`full-table` / `full-index` / `search`). The
  point is that no query is ever spelled twice: a plan assertion over SQL restated in a
  test is a real plan for a query no user issues. Record at EXECUTION, not at prepare
  time — several repositories prepare in their constructor.
- `fault-injection.ts` — `corruptStore`, `readOnlyStore` and `lockStore`, plus the
  `SQLITE_*` result codes, `sqliteErrcode()` and `primaryCode()`. Each injector produces a
  real error code from the real engine and refuses to run rather than take effect
  vacuously — an absent store, a live handle. Where the platform or the privilege decides
  instead of the helper, `readOnlyStore` reports it as `effective: false` and **the caller
  must gate**: `if (!readOnly.effective) ctx.skip(reason)`. Pass the store's `onCleanup` to
  any injector that has to be undone before the tree can be removed, and the store itself
  to any that needs no live connection.
  `fillStore` is in the same file and its page cap is connection-scoped, so it bounds only
  the handle it is given — which is what decides where it can be aimed. A repository
  constructed over a raw handle takes it (`SqliteAuditEventsRepository(raw)`, the
  `activity.test.ts` pattern), and so does `applyMigrations` — but only with a cap sized
  against a real migration: the default headroom on an empty file stops the ledger's own
  `CREATE TABLE`, so the applier's loop never runs and every claim about a partial
  migration then holds vacuously. The blanket fail-open sites in `database.ts`
  (`recordCapture`, `ensureInventory`, `recordConfigScan`, `recordProjectFiles`, and
  `reconcileWorktreeProjects`, which reaches `withTransaction` directly) are closures over
  the connection `openLocalDatabase` opened, so they are reached by capping **that**
  connection — `db[UNSAFE_TEST_ONLY_RAW_HANDLE]`, below. Handing `fillStore` a second
  handle on the same file instead is the mistake to avoid: it carries none of the cap, the
  facade writes on undisturbed, and every "the write was dropped" assertion then passes
  because nothing was ever refused.
- **`UNSAFE_TEST_ONLY_RAW_HANDLE`** — not a helper but the seam a connection-scoped
  injector aims at, so it is listed here: the `DatabaseSync` a `LocalDatabase` writes
  through, exported from `src/database.ts`, and the only test-only seam in shipped
  source. It is
  symbol-keyed and **not** re-exported from `src/index.ts`, and the package's `exports` map
  is `"." -> "./src/index.ts"` alone, so no other package can reach the module that defines
  it. Two properties are load-bearing and easy to break: it is a plain **enumerable data
  property**, because the helpers hand out `{ ...db, close }` wrappers and spread copies own
  enumerable symbols — a getter or a non-enumerable definition loses it silently; and it is
  the **real** connection, so `close()` reaches it.
  `packages/eslint-config/test/test-only-seam.test.js` is what keeps "test-only" true: it
  walks the tracked tree and fails if any file naming the seam is neither its one definition
  site nor a test. That is a derived rule, not a list — a new fault test needs no edit there,
  a product caller anywhere in the workspace fails CI. It lives in that package rather than
  in `persistence` because only that task's turbo `inputs` hash the whole workspace; the
  same check inside `persistence` would replay a cached green while a caller appeared in
  `cli/src`.
- `assertNoOpenTransaction(db)` — a fault that leaves a transaction open is worse than the
  fault; assert this after injecting one. It reads `db.isTransaction` rather than probing
  with a transaction of its own, so it cannot disturb the handle it is inspecting.
- `errorFrom(fn)` — the error a thunk threw, captured OUTSIDE its own catch (see
  [Testing](#testing) on why the try/catch form asserts on the test's own guard).
- `descriptorProbe()` — how many OS descriptors a synchronous thunk left behind. A
  `DatabaseSync` that escapes a failed open is unreachable to the caller, and POSIX
  unlinks an open file happily, so the temp tree still goes and the leak shows up
  nowhere; Windows alone refuses the delete. This counts instead, which is what makes
  the leak observable on the legs that run most of the suite. Three properties are
  load-bearing: the window must be **synchronous** (`leakedBy` refuses a thenable —
  an await hands the loop back and unrelated I/O lands in the delta), the count is
  the whole descriptor table rather than a per-file one (macOS `/dev/fd/N` entries
  are character devices, so `readlink` cannot name the store the way Linux's
  `/proc/self/fd` can), and the probe **self-checks** before reporting
  `observable: true` — a counter stuck at a constant reports "nothing leaked" for
  every input, so it proves it can see one descriptor it opens itself. Where it
  cannot (Windows has no `/dev/fd`), it reports `observable: false` with a reason and
  **the caller must gate**: `if (!probe.observable) ctx.skip(probe.reason)`, the same
  shape `readOnlyStore` uses for a mode the platform ignored.
- `captureEvent()` / `captureFinding()` — the minimal `recordCapture` pair. Both vary
  their identity per call, which is load-bearing: `contentHash` feeds the event's
  content-addressed id and `maskedMatch` is half the finding-level session dedup key, so a
  shared constant makes a second capture land as zero rows **by design** — and every "the
  event is gone" assertion in `test/faults/` would then pass whether or not the fault did
  anything.

`packages/persistence/test/faults/` is where those injectors are pointed at product code —
one file per fault (corrupt is covered in `database.test.ts`, which predates the
directory). A fault case documents the **actual** behaviour rather than the desirable one:
no fail-open site inspects a SQLite result code, so contention, a full disk, a read-only
file and a caller bug all arrive there as the same discarded `false`, and a dropped event
leaves no counter, marker or log line behind. (Scoped to those sites deliberately: the
package reads `errcode` in two places — `internal/sqlite-errors.ts` for
`SQLITE_CONSTRAINT_UNIQUE`, and `fingerprint.ts`, which separates "no such table" from a
damaged or locked store. Neither is a fail-open path.) Write that down and assert it; do not assert a signal the product does not
emit. Two behaviours there are the opposite of what the fault's name suggests and are
pinned so nobody "fixes" them: a store chmod'd read-only under a **live** handle keeps
being written (a descriptor carries the permission it was opened with, so only the next
open is refused), and a read-only store's refusal lands **inside the migration applier**
rather than on the first `PRAGMA journal_mode = WAL`, which succeeds and mints the
sidecars. A tightened directory the owner still owns is a third case, and the distinction
is the point: `ensureDataDirSync` widens the **data dir** back to 0700, so a 0500 there
never reaches SQLite — but a 0000 `~/.aka` is **reported**, as `EACCES` out of `mkdir`,
long before any chmod runs. `aka init` repairs a 0000 home because it calls
`ensureDataDirSync` on the home itself; `openLocalDatabase` does not, and the tests in
this directory assert the refusal.

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

**A Server Action's parameter types are a claim its runtime never checks.** The arguments
arrive as JSON over an HTTP POST, so a caller may post a number, a null, or an object
carrying a hostile `toString` wherever the signature says `string`. Such a value reaching a
`.trim()`, a `.slice()`, a template literal or a SQL bind parameter throws — and a **thrown
Server Action rejects**, so the browser gets a framework error page instead of the
recoverable `{ ok: false, error }` the action was written to return. That is the same
failure the store-failure guards in `actions.ts` exist to prevent, reached by another door,
which is why a fail-open `catch` around the store is not enough on its own.

The exceptions surface closes it by parsing the **whole input** — the shapes live in
`@akasecurity/schema` (`src/zod/exception-action.ts`) and every mutating action there
`parseActionInput`s its payload before touching a field. Three rules make it hold:

- **Parse the whole input, not each field.** A payload that is not an object at all fails
  before any field is read, and no per-field check can express that case.
- **The refusal names the schema's KEY, never the payload.** A field arriving as the wrong
  type is still a live credential, so nothing derived from it — including a Zod issue
  message — may reach the message describing its rejection.
- **Widening in a test alias is per-PARAMETER, not per-action.** An alias that widens
  `confirmation` to `unknown` and leaves `reason` at `string` covers one field while reading
  as covering the action; that is exactly how `reason` went unwidened, and unguarded, across
  three actions at once. Widen the alias's whole input to `unknown`.

Assert three things per case, in this order: it does not throw, it names the field, and it
echoes no raw value (`expectNoEchoOf`). The middle one is not decoration — `expectNoEchoOf`
catches an absent error but not an empty one, and every `not.toContain` passes on `''`, so
requiring the message to say something specific is what stops the echo check going vacuous.
Keep a positive control that a well-formed payload still succeeds, or an action rewritten to
refuse everything satisfies all three.

Every other `'use server'` file under `web-ui/app` is **not** guarded this way yet — eight
files, 20 exported actions at the time of writing — so do not read the above as a property
the dashboard has. The set is deliberately **not** listed here: a partial list reads as
exhaustive and stops an audit at the files it names, and a full one goes stale the first
time an action file lands. Derive it from the **directive**, which is not the same as
grepping for the words — `app/lib/dropped-rules.ts` mentions them in a comment and exports
a sync function, so it matches the text and is not a Server Action.

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
`plugins/claude-code/test/helpers/no-echo.ts`, `plugins/codex/test/helpers/no-echo.ts`,
`plugins/antigravity/test/helpers/no-echo.ts`, `web-ui/test/helpers/no-echo.ts` and
`packages/setup-wizard/test/helpers/no-echo.ts`. A plain
`not.toContain(rawValue)` in a new or edited assertion is a defect, not a style choice, and
editing a file means its in-class assertions come along rather than being left beside converted
ones.

**Older assertions are a backlog, not a clean tree.** `plugins/claude-code` still carries around
twenty whole-value raw-value assertions in files this convention has not reached —
`history/`, `journey/`, `remediation/`, `render.test.ts`, `triage/plan-file.test.ts`,
`hooks/pointer-substitution.test.ts` and `backfill.test.ts` among them. `plugins/codex` carries
the same backlog in its counterparts of those files — the helper reached its hook and
remediation-render assertions, not `history/`, `triage/judge.test.ts` or
`remediation/redact.test.ts`. Do not read the rule above as a claim that either package is
clean. Two shapes are genuinely **exempt** and stay
whole-value: an assertion on a masked preview (`writeback.test.ts` on `maskedValue`,
`triage/surfaced-secrets.test.ts` on `maskedToken`), because that fragment is revealed on
purpose; and the deliberate **control** assertions inside each `no-echo.test.ts`, which exist
to show the whole-value form would have passed.

**Share it inside a package, copy it across a wall — and a copy takes the suite with it.**
All six packages import a `test/helpers/no-echo.ts` with its own tests in `no-echo.test.ts`:
each case drives the helper with an output that leaks a run, and asserts both that the helper
refuses it **and** that the whole-value form it replaced would have passed. That second half is
what shows the assertion is _stronger_ rather than merely also-red, and it is why raising the
run length or emptying the loop cannot go unnoticed — widening `ECHO_RUN` leaves every
**caller** green, so the helper's own suite is the only thing that goes red. `web-ui` is the
worked example of that failure: its copy was inline with no suite, and all 86 of its action
tests passed with `ECHO_RUN` set to 64. A package wall blocks the import, not the pattern, so a
further package copies **both** files — including the `expect(value).toBeDefined()` guard,
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
