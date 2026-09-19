---
card: cd_mu3ykpbj1io
title: GitHub Copilot — cover the CLI + VS Code agent mode
stage: plan
created: 2026-09-16
---

> **Attachments:** the card lists none. Nothing was unreadable; nothing was inferred from
> evidence I could not open.

Everything below was checked against the tree at plan time. Where the spec and the tree
disagree, the tree wins and the difference is called out — there are four, and two of them
change the task list.

## Relevant existing architecture

### What is already on disk (16 files)

`plugins/copilot` is a **registered workspace package that builds nothing**:

- `package.json` — `@akasecurity/ai-tc-copilot`, **`"private": true`**, version `0.9.9`,
  scripts `lint` / `test` / `typecheck` only. **No `build`, no `prepack`, no `tsup`.**
  devDeps carry `plugin-runtime`, `plugin-sdk`, `schema`, `eslint-config`, `@types/node` —
  but **not** `persistence`, `scanner` or `setup-wizard`, which the siblings all declare.
- `src/identity.ts` — one export, `PLUGIN_PACKAGE`, with a placeholder comment.
- `vitest.config.ts` — both shared setup files already wired (`no-network.ts` **and**
  `no-managed-settings.ts`), `coverageOptions(import.meta.url)`, **no timeout overrides**
  and a comment explaining why the package is absent from the ratchet.
- `eslint.config.mjs` — `base` + `noDrizzleImports` + `projectService` + `rootConfigFiles`.
- `test/fixtures/cli/` — **eight live recordings** from Copilot CLI 1.0.83
  (`sessionStart`, `userPromptSubmitted`, `userPromptTransformed`, `preToolUse`,
  `postToolUse`, `permissionRequest`, `agentStop`, `sessionEnd`) plus a 197-line `README.md`
  that is the authoritative description of this host anywhere in the repo.
- `test/cli-fixture-shapes.test.ts`, `test/identity.test.ts`.

### Guards that are already pre-wired for this package

These are done and must not be re-done — but three of them carry a **trap** when Phase B
lands:

| Seam                                                                | State                                                             | Trap                                                                                                                                             |
| ------------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EXPECTED_WORKSPACE_PACKAGE_NAMES` (`effective-config.test.js:286`) | present                                                           | —                                                                                                                                                |
| `EXPECTED_VITEST_PACKAGES` (`no-network-runtime.test.js:188`)       | present                                                           | —                                                                                                                                                |
| `COVERAGE_FLOORS` (`test/vitest/coverage.ts:114`)                   | `99`                                                              | **placeholder, must be RE-MEASURED and lowered.** Siblings measure 58–71.                                                                        |
| `package-walls.test.js:70`                                          | probe file pinned as `src/identity.ts`                            | keep that file exporting something                                                                                                               |
| `required-checks.test.js:808`                                       | Windows `--filter` pinned **temporarily** because `private: true` | unsetting `private` moves it into the derived set; the temporary pin and the 40-line `ci.yml` prose block that explains it both become **false** |
| `turbo.json:361`                                                    | `!$TURBO_ROOT$/plugins/copilot/scripts/**` already excluded       | —                                                                                                                                                |
| `ci.yml:896`                                                        | `--filter=@akasecurity/ai-tc-copilot` on the Windows leg          | —                                                                                                                                                |

### Wire vocabulary — half landed

`packages/schema/src/zod/harness-map.ts` already carries `SOURCE_TOOL.Copilot =
'github-copilot'`, `HARNESS.Copilot = 'copilot'` and the `TOOL_TO_HARNESS` row.
`Provider` (`security.ts:233`) and `FindingProvider` (`finding.ts:80`) both extract
`Copilot`. **`HarnessId` (`inventory.ts:43`) does not** — it extracts only
`ClaudeCode, Cursor, Codex, Antigravity`. That one omission is why
`packages/persistence/src/repositories/inventory-assets.ts` has no Copilot row in
`HARNESS_LABELS` (:106), `TITLE_NEEDLES` (:165) or `resolveHarnessId` (:172).
`SCAN_COVERAGE` (`repositories/security.ts:101`) carries
`[HARNESS.Copilot]: { coverage: 0, supported: false }`.

Note for `TITLE_NEEDLES`: the rows are `stripSeparators(SOURCE_TOOL.X)`, which lowercases
and strips `[\s-]`. Copilot's needle is therefore **`githubcopilot`**, not `copilot` — and
a bare `copilot` needle would also match a title containing "GitHub Copilot CLI" _and_
anything else with the word in it. Use the `stripSeparators` form like every other row.

### Runtime seams the adapter calls

- `handleSessionStart(input, config)` — `packages/plugin-runtime/src/handle-session-start.ts:79`.
  `SessionStartInput` already carries `harnessInterface?: string` (opaque, no Zod schema,
  lands in the attribute bag). No schema change is needed for `cli|vscode|cloud`.
- `handleCapture(input, config, opts)` — `handle-capture.ts:38`, fully fail-open.
- `createPluginRuntime(gateway, settings, opts)` → `runtime.capture(input, opts)`.
  `runtime.evaluate` is private; `CaptureOptions.rewritable` is the seam that drives
  `redactDegradedTo`.
- `writeOwnerOnlyFileSync` — `packages/persistence/src/paths.ts:185` (tmp + `wx` + rename).
- `withFileLock(file, fn, {timeoutMs, staleMs})` — `file-lock.ts:439`. **`fn` must be
  synchronous** and it is not re-entrant. Throws `FileLockError` with
  `reason: 'timeout' | 'unavailable'`.

### The two template plugins

`plugins/antigravity` (fail-closed, `runHookFailOpen`) and `plugins/codex` (fail-open,
`SCANNABLE_FIELDS` + `decidePreToolUse` + `updatedInput`). Each carries ~35 `src/` files and
9–10 `skills/`. **This adapter needs a fusion of the two** — Antigravity's wrapper on
`preToolUse` only, Codex's structure everywhere else — and that is the honest size of the
job: the hooks layer is perhaps a fifth of the file count.

---

## Existing patterns

Extend these; invent nothing new where one exists.

| Need                                                   | Existing pattern to copy                                                                         | Path                                                  |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| Explicit-allow wrapper                                 | `runHookFailOpen(main, failOpen, watchdogMs)`                                                    | `plugins/antigravity/src/hooks/shared.ts`             |
| Silent hook entry                                      | `try { await main() } catch {} process.exit(0)`                                                  | `plugins/codex/src/hooks/session-start.ts`            |
| Narrowed `emit` union + two-direction compile pins     | `HookOutput` + `SHAPE_FIELD_BY_EVENT`                                                            | `plugins/claude-code/test/hook-output-shapes.test.ts` |
| Scannable-field table                                  | `Record<string, readonly ScannableField[]>`, `{field, executable}`                               | `plugins/codex/src/hooks/pre-tool-use-decision.ts`    |
| Pointer deny before the store opens                    | `decideInputPointerDeny`                                                                         | same file                                             |
| Redact escalation                                      | read `result.redactDegradedTo`, never re-derive                                                  | same file                                             |
| Input rewrite                                          | `updatedInput` variant of `PreToolUseOutput`                                                     | same file                                             |
| Response scan loop                                     | `scan-response.ts` + `tool-response.ts`                                                          | `plugins/codex/src/hooks/`                            |
| Judge, stdin prompt, `planBareCommand`                 | `spawnCodex` / `spawnAgy`                                                                        | `plugins/*/src/triage/judge.ts`                       |
| Throwaway state cleaned in `finally`                   | `mkdtempSync` + `finally` (codex) / `brainConversationIds` + `cleanupConversation` (antigravity) | same                                                  |
| Transcript adapter                                     | `transcriptsDir` / `iterateHistory` / `peekSessionOriginator`                                    | `plugins/*/src/history/transcripts.ts`                |
| Fail-open e2e, both halves                             | fault rows + enforcement rows                                                                    | `plugins/antigravity/test/e2e/fail-open.e2e.test.ts`  |
| Wrapper unit suite                                     | `test/hooks/fail-open-wrapper.test.ts`                                                           | antigravity only                                      |
| PATH shim (peer copy per plugin)                       | `helpers/path-shim.ts` + `path-shim.test.ts`                                                     | both                                                  |
| No-echo (peer copy per plugin)                         | `helpers/no-echo.ts` + `no-echo.test.ts`                                                         | both                                                  |
| Build entry emitting `scripts/*.js` + `scan-worker.js` | `tsup.config.ts` with `normalizeSqliteSpecifier`                                                 | both                                                  |
| One-shot build before the suite                        | `globalSetup: ['./test/global-setup.ts']`                                                        | both                                                  |
| Release workflow                                       | `release-plugin-antigravity.yml`                                                                 | `.github/workflows/`                                  |
| Registry entry with no automated install               | the `antigravity` entry (`installHint`, no `cliBin`)                                             | `packages/local-ops/src/registry.ts`                  |

**The one thing with no pattern:** nothing in `local-ops` writes a config file into a host's
directory. Every install today is either a delegated host-CLI spawn (`claude`, `codex`) or a
printed `installHint` (antigravity). `aka plugins install copilot` writing
`~/.copilot/hooks/aka.json` is **new machinery**, and it is the highest-risk item in this
plan.

---

## Implementation strategy

### 1. The fail convention, and where the wrapper does and does not go

Print an explicit allow on `preToolUse`; stay silent everywhere else. Correct under both
readings of "exit 0, empty stdout", which is the point — it turns the two blocked probes from
a gate into an optimisation.

- `preToolUse` (both dialects) → `runHookFailOpen(main, ALLOW_FOR_DIALECT, WATCHDOG_MS)`.
- every other event → Codex's silent shape.
- **no path ever exits non-zero**, and none exits 2.

`WATCHDOG_MS = 24_000` against a manifest-declared `timeoutSec: 30`, mirroring Antigravity's
8 s under 10 s ratio, with the margin reserved for `emit`'s awaited flush — which sits
**outside** the race by design and is therefore unbounded on a stalled pipe. Restate
`runHookFailOpen`'s limit verbatim in the module header rather than softening it: it covers
everything that _yields_; it cannot preempt synchronous `node:sqlite` (`busy_timeout = 2000`
charged **per contended statement**) or an in-process `scan()`. 30 s is more headroom than
Antigravity's 10 s, not a different property.

**The fast path must still print.** Codex bails silently when the tool name is not in
`SCANNABLE_FIELDS`. Here that would be a wedge on a fail-closed reading. The unknown-tool
exit is `emit(ALLOW)` then exit 0 — _before_ `loadConfig`, _before_ the store opens. VS Code
spawns the hook for every tool call (matchers are parsed and ignored), so this path is the
common one, not the rare one.

### 2. The event name comes from argv, always

Seven of eight recordings carry no event name (`permissionRequest.hookName` is the sole
exception). `src/hooks/event-name.ts` reads `process.argv[2]`, validates against a frozen
const union of the 15 CLI + 8 VS Code names, and returns `undefined` otherwise →
no opinion (explicit allow on `preToolUse`, silence elsewhere). Never read `hookName`;
never infer from payload shape. Two code paths for one fact is the defect.

**Consequence for `session-start`:** the siblings pass the plugin manifest path as
`argv[2]` so `harnessVersion()` can read it. Here `argv[2]` is the event name, so the
manifest moves to **`argv[3]`**. `build-info.ts` must be copied with that offset changed,
and its own test must pin the offset.

### 3. Two dialects, one package

`src/hooks/dialect.ts` — `detectDialect(payload): 'cli' | 'vscode' | undefined`:

1. `hook_event_name` present (string) → `vscode`. It is the one field VS Code sends on
   every event.
2. else `sessionId` present → `cli`; `session_id` present → `vscode`.
3. else `undefined` → no opinion.

Everything downstream takes the dialect as a parameter. Two `SCANNABLE_FIELDS` tables,
never merged — the tool vocabularies do not overlap (`bash` vs `run_in_terminal`).

### 4. `emit` takes a narrowed union spanning both dialects

One `HookOutput` union in `src/hooks/shared.ts` with the CLI variants
(`permissionDecision` + `permissionDecisionReason`; `modifiedArgs`; `modifiedResult`) and the
VS Code variants (`hookSpecificOutput.permissionDecision`,
`hookSpecificOutput.updatedInput`, `decision: 'block'` + `additionalContext`). A
`hook-output-shapes.test.ts` copied from `plugins/claude-code` pins it in **both**
directions with the `[A] extends [B] ? true : never` pins, plus
`Parameters<typeof emit>[0] extends HookOutput` so a widening back to `unknown` fails
compile. It also reads the new `CLAUDE.md` bullets, as the Claude Code original reads §1.

### 5. Fixtures: recordings and doc-derived, physically separated

- `test/fixtures/cli/` stays recordings-only; its README stays the authority and the shapes
  test keeps holding the file set to it.
- `test/fixtures/vscode-provisional/` is new, with its own README stating plainly that **no
  live session produced these**, naming the vendor pages, and listing every field whose
  presence, casing or type is unverified.
- `test/fixture-provenance.test.ts` fails when a file in `cli/` has no README paragraph
  describing its capture — which is what catches a doc-derived fixture moved across.

### 6. The capability matrix is code, not prose

`src/capabilities.ts` exports `CAPABILITY_MATRIX` — surface × event × field →
`{ channel: 'block'|'rewrite'|'warn'|'none', verified: boolean }`. `SKILL.md`'s Known
limitations renders from the same facts, and `test/capability-matrix.test.ts` parses the
markdown table out of `SKILL.md` and fails when the two disagree. Every VS Code row is
`verified: false` until a recording replaces it.

### 7. Install: file-drop floor, no plugin channel this card

Per the spec, the plugin channel is gated on D4 and is **out of this card's critical path**.
Ship the file-drop only. This has a consequence worth stating because it removes work:
an `AGENT_PLUGINS` entry carrying **both** `pluginRef` and `npmPackage` is swept by the
passive update notice's `npm view`, and that count is "three today" in `CLAUDE.md` §4 item 1
and in both READMEs' `[^egress]` footnotes. A file-drop-only entry (`npmPackage`, **no**
`pluginName`/`marketplace`) leaves the count at three and **nothing about the notice moves**.
Give it `pluginName` and the count becomes four and three documents move in the same commit.

New module `packages/local-ops/src/hook-file-install.ts`:

- reads the existing `~/.copilot/hooks/aka.json` if present, merges AKA's entries, writes
  through `writeOwnerOnlyFileSync`;
- because that is a **read-modify-write**, it takes `withFileLock` per §6 — and the callback
  must be synchronous, which the whole path already is;
- uninstall removes exactly AKA's entries and leaves foreign ones byte-identical;
- `--project` writes `.github/hooks/aka.json` instead;
- the command line it writes must be valid **PowerShell 5.1** (VS Code runs it through
  `powershell -ExecutionPolicy Bypass`), i.e. absolute quoted node path + absolute quoted
  script path + the literal event token. §7's cmd.exe quoting rules do not apply there.

### 8. Judge

`copilot` judge under a throwaway `COPILOT_HOME` pre-seeded
`{"remoteExport":false,"autoUpdate":false}` plus a temp workspace with no `.github/hooks`,
deleted in a `finally`. Prompt on **stdin**, argv fixed flags only, through
`planBareCommand` (`.cmd` under npm, `.exe` under winget — both planner paths live).
Same `toJudgePayload` projection as the other three. Consent copy states the model-API
egress **and** the account-sync risk without the pre-written setting, and never calls the
subprocess network-isolated.

That adds a `process.env` reader → `CLAUDE.md` §3's table gains an **eleventh** row and its
count word moves from "Ten" to "Eleven" (`claude-md.test.js` parses both, and `countWordIn`
throws rather than returning undefined). §4 gains a numbered egress item.

**Decide deliberately, do not assume:** whether `EGRESS_PATHS` in
`plugins/claude-code/test/privacy-claims.test.ts` gains a **row**. It has four today, keyed
by _class_ (`update notice`, `package-manager install`, `setup calibration`, `attached
control plane`), and its `COUNT_WORDS`/`ORDINAL_WORDS` derive the footnote's spelled count.
A fourth judge is arguably another instance of the existing `setup calibration` class rather
than a fifth class. Whichever way it goes, `privacy-claim-coverage.test.js` will require the
new plugin README to be classified, so that row is owed regardless.

---

## File-level changes

### Create — `plugins/copilot/`

**Build and manifest**

- `tsup.config.ts` — copy the sibling verbatim (`noExternal: [/^@akasecurity\//, 'zod']`,
  `normalizeSqliteSpecifier('scripts')`, the `triage-rubric.md` copy in `onSuccess`), entries
  for every hook script plus `scan-worker`, `reconcile`, `sync`, `history-sync`,
  `content-retention`, `query`, `dashboard`, `onboard`, `apply-suppressions`, `intro`,
  `start-light`, `firstrun`, `backfill`, `filescan`, `remediate`.
- `plugin.json` (Copilot reads a flat root manifest like Antigravity, not a dotted dir).
- `hooks.json` — **one Copilot-CLI-format file**, `version: 1`, one entry per event, each
  command carrying the event name as a literal argv token, `timeoutSec: 30`.
- `test/global-setup.ts` — the one-shot `tsup` the siblings use.

**Hooks layer — `src/hooks/`**

- `shared.ts` — `readStdin`, `parseJson`, `getString`, `emit(output: HookOutput)`,
  `HookOutput`, `runHookFailOpen`, `baseMetadata`, `WATCHDOG_MS`.
- `event-name.ts` — argv[2] → validated event name.
- `dialect.ts` — `detectDialect`, plus the per-dialect envelope readers
  (`readToolCall`, `readSessionId`, `readCwd`).
- `pre-tool-use.ts`, `pre-tool-use-decision.ts` (two `SCANNABLE_FIELDS` tables,
  `decideInputPointerDeny`, `decidePreToolUse`, the CLI and VS Code output builders).
- `post-tool-use.ts`, `tool-response.ts`, `scan-response.ts`.
- `user-prompt-submit.ts`, `session-start.ts`, `stop.ts`, `stop-payload.ts`,
  `store-health.ts`.

**Sibling surface — `src/`** (copy from `plugins/codex`, host wording changed)
`apply-suppressions.ts`, `backfill.ts`, `build-info.ts` (argv offset 3),
`calibration.ts`, `content-retention.ts`, `dashboard-launch.ts`, `dashboard.ts`,
`exception-guidance.ts`, `filescan.ts`, `firstrun-core.ts`, `firstrun.ts`,
`history-sync.ts`, `intro.ts`, `onboard.ts`, `posture.ts`, `present.ts`, `query.ts`,
`reconcile.ts`, `render.ts`, `scan-worker.ts`, `setup-frame-json.ts`, `setup-show.ts`,
`skills-registry.ts`, `start-light.ts`, `sync.ts`, `capabilities.ts` _(new to this plugin)_,
`history/{reconcile-trigger,scan,tail,transcripts,usage}.ts`,
`remediation/{entry,findings,redact,render,surfaced-redact}.ts`,
`triage/{consent,judge,presenter}.ts`.

**Skills** — `skills/{audit,dashboard,detections,exceptions,findings,health,recommend,scan,setup,tokens}/SKILL.md`,
setup keyed `aka-setup`, with the Known limitations section driven by the capability matrix.

**Tests** — `test/fixtures/vscode-provisional/*.json` + `README.md`;
`test/fixture-provenance.test.ts`; `test/capability-matrix.test.ts`;
`test/hook-output-shapes.test.ts`; `test/hooks/{fail-open-wrapper,dialect,event-name,
pre-tool-use-decision,scan-response,tool-response,user-prompt-submit,stop-payload,
store-health}.test.ts`; `test/e2e/{fail-open,pre-tool-use,scan-worker-bundle,build-info-bundle,
dashboard-launch}.e2e.test.ts`; `test/helpers/{no-echo.ts,no-echo.test.ts,path-shim.ts,
path-shim.test.ts,run-hook.ts}`; `test/history/*.test.ts`; `test/triage/judge.test.ts`;
`test/journey/no-model-judge-consent.journey.test.ts`; `test/privacy-claims.test.ts`
(if the coverage guard requires one); the rest of the sibling suite set.

### Modify — outside the package

- `plugins/copilot/package.json` — drop `"private": true`; add `build` / `dev` / `prepack`;
  add `@akasecurity/{persistence,scanner,setup-wizard}` + `tsup` devDeps; add `files`.
- `plugins/copilot/vitest.config.ts` — add `globalSetup`, `testTimeout: 20_000`,
  `hookTimeout: 20_000`.
- `plugins/copilot/src/identity.ts` — remove the placeholder comment; keep the export
  (`package-walls.test.js:70` pins this path).
- `packages/schema/src/zod/inventory.ts:43` — `HarnessId` gains `'Copilot'`.
- `packages/persistence/src/repositories/inventory-assets.ts` — `HARNESS_LABELS`,
  `TITLE_NEEDLES` (`stripSeparators(SOURCE_TOOL.Copilot)`), and **`resolveHarnessId`'s
  dispatch line, which is not type-enforced** — the known silent gap.
- `packages/persistence/src/repositories/security.ts:101` — `SCAN_COVERAGE` Copilot row off
  `{0,false}` with its argument recorded.
- `packages/local-ops/src/registry.ts` — `AGENT_PLUGINS` copilot entry, distinct
  `pluginName`-free shape (file-drop floor).
- `packages/local-ops/src/hook-file-install.ts` — **new**, plus its export from `index.ts`.
- `cli/src/commands/plugins.ts` — route the copilot id to the file-drop writer instead of
  the `installHint` dead end; `--project` flag.
- `test/vitest/coverage.ts:114` — re-measured floor.
- `packages/eslint-config/test/hook-timeout-ratchet.test.js` — add copilot's `TIMEOUTS` entry.
- `packages/eslint-config/test/required-checks.test.js` — retire or re-justify the temporary
  Windows pin now that `private` is unset.
- `.github/workflows/ci.yml` (the ~40-line comment block at :485–:528) — its prose asserts
  copilot is `private: true` and pinned for that reason. It stops being true.
- `.github/workflows/release-plugin-copilot.yml` — **new**, from the antigravity template.
- `CLAUDE.md` — §3 eleventh row + count word; §4 numbered egress item; the hook-contract
  bullets; the package-dependency graph block; the repository-layout block; the releasing
  section's bundling rules (a fourth plugin bundles `plugin-runtime`/`plugin-sdk`).
- `README.md`, `plugins/copilot/README.md`, and whichever `[^egress]` footnotes the derived
  count touches.
- `.github/hooks/aka.json` + a `copilot-setup-steps.yml` snippet — Phase C.

---

## Ordered implementation tasks

### A. Make the package build (nothing else can land first)

- [x] A1. Add `@akasecurity/{persistence,scanner,setup-wizard}` and `tsup` to
      `plugins/copilot/package.json` devDependencies at the exact ranges the siblings carry;
      add `build`, `dev`, `prepack` scripts and a `files` array. Leave `private` alone for now.
- [x] A2. Copy `tsup.config.ts` from `plugins/codex`, trimming `entry` to the hook scripts
      that exist at this point plus `scan-worker`. Verify `normalizeSqliteSpecifier` and the
      `triage-rubric.md` copy come across unchanged.
- [x] A3. Add `test/global-setup.ts` (one-shot `tsup`), wire `globalSetup` +
      `testTimeout: 20_000` + `hookTimeout: 20_000` into `vitest.config.ts`, and **replace**
      the comment there that says the package has no timeout overrides.
- [x] A4. Add `'@akasecurity/ai-tc-copilot': { testTimeout: 20_000, hookTimeout: 20_000 }`
      to `TIMEOUTS` in `packages/eslint-config/test/hook-timeout-ratchet.test.js`.
- [x] A5. Copy `src/build-info.ts` with the manifest read moved from `argv[2]` to
      **`argv[3]`**; add `test/build-info.test.ts` pinning that offset explicitly.
- [x] A6. Write `plugin.json` and `hooks.json` (one entry per event, event name as a literal
      argv token, `timeoutSec: 30`). Add a test asserting every command in `hooks.json`
      resolves to an emitted `scripts/*.js` and carries a valid event token.

### B. Wire vocabulary (independent of A; do early so types settle)

- [x] B1. Extend `HarnessId` in `packages/schema/src/zod/inventory.ts` with `'Copilot'` and
      run `pnpm typecheck` — the `Record<HarnessId, …>` tables will name every site that
      must now decide.
- [x] B2. Add the `HARNESS_LABELS` row.
- [x] B3. Add the `TITLE_NEEDLES` row as `stripSeparators(SOURCE_TOOL.Copilot)`.
- [x] B4. Add the `resolveHarnessId` dispatch line by hand — **the compiler will not ask for
      it** — and a test that drives a Copilot harness row end to end through it.
- [x] B5. Flip `SCAN_COVERAGE`'s Copilot row to a justified number with the argument in a
      comment beside it (see Risks: this is open question 3).

### C. The wrapper and the wire (the load-bearing half)

- [x] C1. Write `src/hooks/shared.ts`: `readStdin`, `parseJson`, `getString`, `baseMetadata`,
      `emit(output: HookOutput)`, and `runHookFailOpen(main, failOpen, watchdogMs =
WATCHDOG_MS)` ported from Antigravity. Restate the blocking-body limit in the header.
- [x] C2. Define the `HookOutput` union spanning both dialects.
- [x] C3. Write `src/hooks/event-name.ts` (argv[2], validated, `undefined` on anything else).
- [x] C4. Write `src/hooks/dialect.ts` (`hook_event_name` first, `sessionId`/`session_id`
      second, `undefined` third) plus the per-dialect envelope readers.
- [x] C5. `test/hooks/fail-open-wrapper.test.ts` — throw, undecided body, watchdog win, a
      late rejection that must not surface as an unhandled rejection, the synchronous-block
      limit pinned as behaviour, and **exactly one JSON object** on stdout (two concatenated
      objects do not parse).
- [x] C6. `test/hooks/{event-name,dialect}.test.ts` — including an envelope matching neither
      dialect.
- [x] C7. `test/hook-output-shapes.test.ts` — both compile-direction pins, the
      `emit`-narrows pin, and the read of `CLAUDE.md`'s bullets.

### D. PreToolUse

- [x] D1. `src/hooks/pre-tool-use-decision.ts`: `ScannableField`, the **two**
      `SCANNABLE_FIELDS` tables (CLI: `bash.command` executable, `bash.description`
      non-executable, `apply_patch` non-executable; VS Code: the tool ids from the
      provisional fixtures), `decideInputPointerDeny`, `decidePreToolUse` returning the
      dialect-correct output.
- [x] D2. Wire the redact channel: CLI `modifiedArgs`; VS Code
      `hookSpecificOutput.updatedInput` carrying the **full** camelCase object for the exact
      tool id. Read `result.redactDegradedTo`; never re-derive.
- [x] D3. `src/hooks/pre-tool-use.ts`: read argv event → parse stdin → detect dialect →
      unknown tool ⇒ **`emit(ALLOW)` and exit, before `loadConfig`** → pointer deny before
      the store opens → `loadConfig` → gateway → per-field `runtime.capture` with
      `rewritable: !spec.executable` → `decidePreToolUse` → return the output to
      `runHookFailOpen`.
- [x] D4. `test/hooks/pre-tool-use-decision.test.ts` covering both dialects at block, redact,
      redact-on-executable (degraded), warn and monitor.

### E. The remaining events

- [x] E1. `src/hooks/session-start.ts` — `handleSessionStart({ tool: SOURCE_TOOL.Copilot,
harnessVersion, harnessInterface })`, provider recorded `unknown` with the model id.
      The once-per-session pass must tolerate running **after** the session's first prompt
      (the recordings show `userPromptSubmitted` 20 ms _before_ `sessionStart`); add a case
      that drives that order.
- [x] E2. `src/hooks/user-prompt-submit.ts` — capture from `userPromptSubmitted.prompt`;
      record `userPromptTransformed.transformedPrompt` **separately**, never conflated.
      Block/rewrite only where the matrix marks it verified; otherwise record-only, and say
      so in `SKILL.md`.
- [x] E3. `src/hooks/post-tool-use.ts` + `tool-response.ts` + `scan-response.ts` — CLI
      `modifiedResult`; VS Code block-only. **Never read `toolResult.resultType` as the
      command's exit status** — add a case driven by the recorded `false`-command fixture,
      whose `resultType` is `"success"`.
- [x] E4. Ensure `preToolUse` and `permissionRequest` do not both record a tool-use event for
      one call. Scan point is `preToolUse` only; `permissionRequest.toolInput` is a strict
      subset (`command` only) and scanning it would silently skip `description`.
- [ ] E5. `src/hooks/stop.ts` + `stop-payload.ts` — `agentStop`/`Stop` → throttled reconcile;
      `sessionEnd` → runner-mode drain when attached.
- [x] E6. `src/hooks/store-health.ts`.

### F. History, backfill, transcripts

- [ ] F1. `src/history/transcripts.ts` reading
      `~/.copilot/session-state/<uuid>/events.jsonl`, keyed on
      `session.start.data.copilotVersion` and **version-tolerant** (the one local sample was
      written by 1.0.15; this is not a stable API).
- [ ] F2. Producer attribution — skip sessions whose `producer` / `context.hostType` belongs
      to another adapter's surface, so a machine running both plugins does not double-count.
- [ ] F3. `src/history/{tail,scan,usage,reconcile-trigger}.ts` from the Codex siblings.
- [ ] F4. `src/backfill.ts` — timestamp cutoff **plus** live-session exclusion by `sessionId`
      from stdin. Keep the read gated on the existing `historicalAccess` grant.
- [ ] F5. Capture a `session-state` corpus fixture and drive F1–F4 against it.

### G. Judge and disclosure (one commit, or the docs go out of step)

- [ ] G1. `src/triage/judge.ts` — throwaway `COPILOT_HOME` pre-seeded
      `{"remoteExport":false,"autoUpdate":false}`, temp workspace with no `.github/hooks`,
      both removed in a `finally`. Prompt on stdin, fixed-flag argv via `planBareCommand`.
      Same `toJudgePayload` projection; `MODEL_JUDGE_PAYLOAD_VERSION` re-check.
- [ ] G2. `src/triage/consent.ts` + the consent copy: model-API egress **and** the
      account-sync risk absent the pre-written setting. Never "isolated subprocess".
- [ ] G3. File-scoped `n/no-process-env` opt-out in `plugins/copilot/eslint.config.mjs` for
      `src/triage/judge.ts` (prefer file-scoped over inline, per §3).
- [ ] G4. `CLAUDE.md` §3 — eleventh row **and** the count word "Ten" → "Eleven".
- [ ] G5. `CLAUDE.md` §4 — the numbered egress item for the Copilot judge.
- [ ] G6. Decide and record whether `EGRESS_PATHS` gains a row (four today, keyed by class;
      a fourth judge may be another `setup calibration` instance). Move the derived
      `[^egress]` footnote counts in the same commit if it does.
- [ ] G7. `plugins/copilot/README.md` + its `privacy-claim-coverage` classification row.
- [ ] G8. `test/triage/judge.test.ts` and
      `test/journey/no-model-judge-consent.journey.test.ts`, with `helpers/path-shim.ts` +
      `path-shim.test.ts` and `helpers/no-echo.ts` + `no-echo.test.ts` **copied as peers**
      (a package wall blocks the import; a copy takes its suite with it).

### H. Skills, wizard and presentation

- [ ] H1. Copy the ten `skills/*/SKILL.md` from `plugins/codex`, changing host wording.
- [ ] H2. `src/capabilities.ts` — the typed matrix with its `verified` column.
- [ ] H3. `skills/setup/SKILL.md` Known limitations rendered from the matrix, stating plainly
      that VS Code enforcement is built to the published contract and **not confirmed against
      a live install**.
- [ ] H4. `test/capability-matrix.test.ts` — fails when matrix and `SKILL.md` disagree.
- [ ] H5. `src/{present,render,setup-show,setup-frame-json,intro,start-light,firstrun,
firstrun-core,posture,calibration,onboard,query,dashboard,dashboard-launch,
skills-registry,exception-guidance,filescan,apply-suppressions,sync,history-sync,
content-retention,reconcile,scan-worker}.ts` and `src/remediation/*` from the Codex
      siblings, plus their suites.

### I. Fixtures and provenance

- [x] I1. Create `test/fixtures/vscode-provisional/` with one file per VS Code event and a
      README naming the vendor pages and every unverified field.
- [x] I2. `test/fixture-provenance.test.ts` — a file in `cli/` with no README paragraph
      describing its capture fails.
- [ ] I3. Extend `test/cli-fixture-shapes.test.ts` for any new recording.

### J. Install channel

- [ ] J1. `packages/local-ops/src/hook-file-install.ts` — merge/remove AKA entries through
      `writeOwnerOnlyFileSync`, inside `withFileLock` (synchronous callback), `--project`
      variant writing `.github/hooks/aka.json`, PowerShell-5.1-valid command line.
- [ ] J2. `AGENT_PLUGINS` copilot entry: `sourceTool: SOURCE_TOOL.Copilot`, `npmPackage`,
      **no** `pluginName`/`marketplace`/`cliBin` for the file-drop floor. Confirm the
      `npm view` sweep count stays three; if it does not, move it in `CLAUDE.md` §4 item 1
      and both READMEs in the same commit.
- [ ] J3. Route the copilot id in `cli/src/commands/plugins.ts` to the writer.
- [ ] J4. Idempotency test: seed `~/.copilot/hooks/aka.json` with **foreign** entries,
      install, uninstall, assert the file is **byte-identical** to the seed.
- [ ] J5. Inventory collectors for the Copilot config assets. **Do not infer "CLI installed"
      from `~/.copilot` existing** — VS Code's Copilot Chat writes that directory.

### K. Ship gates

- [x] K1. `test/e2e/fail-open.e2e.test.ts` against the **built** scripts. Fault rows (empty,
      malformed, truncated, scalar, null, binary, oversized stdin, unopenable store) prove
      `preToolUse` emits exactly one explicit allow and every other hook emits nothing.
      Enforcement rows prove block, redact, warn and monitor each emit the shape their cell
      expects. Both halves, or the absence assertions go vacuous.
- [x] K2. `test/e2e/scan-worker-bundle.e2e.test.ts` — the worker resolves as a **sibling of
      the built scripts**, driven with a pulled rule against a throwaway home.
- [ ] K3. Unset `"private": true`.
- [ ] K4. Retire or re-justify the temporary Windows pin in `required-checks.test.js`, and
      **rewrite the `ci.yml` comment block at :485–:528**, whose prose claims copilot is
      private and pinned for that reason.
- [x] K5. Measure the real coverage number and lower `COVERAGE_FLOORS` from the `99`
      placeholder to one point below what the suite reports, with the measurement in the
      comment beside it.
- [ ] K6. `.github/workflows/release-plugin-copilot.yml` on `plugin-copilot-v*`, from the
      antigravity template, tag-vs-manifest version gate included. Its smoke test feeds junk
      to `preToolUse` and requires an **explicit allow**, and junk to every other hook and
      requires **silence**.
- [ ] K7. `CLAUDE.md`: hook-contract bullets (_Copilot CLI: `preToolUse` denies on crash,
      allows on timeout, other events fail open — documentation until the two probes run;
      VS Code Local: exit 2 blocks, everything else fails open, matchers ignored_), the
      package-dependency graph, the repository-layout block, and the releasing section's
      bundling rules.
- [ ] K8. Full green: `pnpm lint && pnpm typecheck && pnpm turbo run test` on macOS and
      Linux, with the Windows leg exercised through CI.

### L. Phase C — cloud coding agent

- [ ] L1. Repo-committed `.github/hooks/aka.json` on the default branch, using the `bash`
      field with a POSIX launcher.
- [ ] L2. `copilot-setup-steps.yml` snippet: Node 24, `@akasecurity/cli` + plugin,
      `aka attach --url … --key-stdin --no-sync-history --host-label …` from an Agents-type
      secret, control-plane host in the repo's Internet-access allowlist.
- [ ] L3. Runner-mode drain at `sessionEnd`/`agentStop`; `harnessInterface = 'cloud'`;
      a failed setup step means `~/.aka` is absent, so `preToolUse` must still emit the
      explicit allow — never silence.
- [ ] L4. Record that GitHub masks Agents secrets in its own session logs; do not
      double-count that masking as an AKA finding.

---

## Dependencies

```
A1 → A2 → A3 → A4
A2 → A5 → A6
B1 → B2, B3, B4, B5            (B1 is the compile gate; the rest are its fallout)
A2 + C1 → C2 → C7
C1 → C5 ;  C3, C4 → C6
C2 + C3 + C4 → D1 → D2 → D3 → D4
B1 + C* → E1..E6               (E1 needs handleSessionStart's harnessInterface, already there)
E1 → F1 → F2 → F3 → F4 → F5
A5 + C* → G1 → G2 → G3 → G4 → G5 → G6 → G7 → G8
D + E → H2 → H3 → H4 ;  H1, H5 are parallel to everything after A
I1 → D1 (the VS Code table is written FROM the provisional fixtures)
I1 → I2 → I3
B + J1 → J2 → J3 → J4 → J5
A6 + C + D + E → K1 ; A2 → K2
K1 + K2 → K3 → K4 → K5 → K6 → K7 → K8
J1 + L1 → L2 → L3 → L4
```

Three hard ordering facts:

1. **A before everything.** Nothing can be e2e-tested until the package emits `scripts/*.js`.
2. **B1 before every read-side change.** It is the compile gate that names the sites.
3. **I1 before D1.** The VS Code `SCANNABLE_FIELDS` table is written from the provisional
   fixtures, not the other way round — otherwise the fixtures get written to match the table
   and prove nothing.
4. **K3 before K4.** Unsetting `private` is what makes the required-checks pin and the
   `ci.yml` prose false; do them adjacently or `main` reds on a commit whose diff looks
   innocent.

---

## Risks

**High**

- **The file-drop installer is new machinery in `local-ops`.** Nothing there writes into a
  host directory today. It is a read-modify-write on a shared file, so it inherits §6 whole:
  `withFileLock`, a synchronous callback, `writeOwnerOnlyFileSync`, and a
  `FileLockError.reason` branch (`timeout` = another writer, swallow; `unavailable` =
  propagate). Getting this wrong silently discards a user's foreign hook entries.
- **`resolveHarnessId` is not type-enforced.** B1 makes `HARNESS_LABELS` and `TITLE_NEEDLES`
  compile-mandatory; the dispatch chain is a hand-written `if` ladder. A Copilot row that
  compiles and renders under no harness is the exact silent gap the spec names.
- **Unsetting `private` moves three guards at once** (required-checks' derived published set,
  its temporary pin, and 40 lines of `ci.yml` prose). A green PR check does not see this —
  `pull_request` runs against a stale merge commit, and this is precisely the class
  `CLAUDE.md` warns reds `main` from an innocent diff.
- **The VS Code half is doc-derived by operator decision.** Every enforcement claim there is
  unverified. The risk is not that it is wrong — it is that it stops _reading_ as unverified
  once it is shipping code. The separate fixture directory, the `verified` column and the
  `SKILL.md` sentence are the three things that keep it honest; weakening any one of them
  loses the property.

**Medium**

- **Cold-store cost inside `preToolUse`'s 30 s.** First `openLocalDatabase` plus a full
  migration on a fresh home is charged to the hook's budget. If it approaches 30 s on a
  contended machine the host allows by timeout and the call goes **unscanned**. Measure it;
  do not assume 30 s is generous.
- **`emit` is outside the watchdog race.** An oversized `toolArgs` past the pipe buffer has
  no deadline, and `process.exit(0)` on that path is unreachable. Same limit as Antigravity;
  do not describe the explicit allow as unconditional.
- **The coverage floor is a placeholder at 99.** A real suite will not hit it. Re-measuring
  is a task (K5), not an afterthought — and the number goes _down_, which is a deliberate
  edit `coverage-config.test.js` pins as an exact set.
- **Double capture with the Claude Code plugin** when `chat.useClaudeHooks` is on. Shipped
  default is false; detect and dedupe rather than assuming it away.
- **`postToolUse.toolResult.resultType` is a trap** — the recorded `false` command reports
  `"success"`. Anything reading it as an exit status is wrong and will look right.
- **The `npm view` sweep count.** Giving the registry entry a `pluginRef` silently changes
  the passive update notice's outbound call count, which three documents state in prose.
  The file-drop-only shape avoids it; the plugin channel does not.

**Low / watch**

- `~/.copilot` exists on machines with no CLI (VS Code writes it). Inventory must not infer
  installation from it.
- `permissionRequest.permissionSuggestions` was recorded **empty** under `--allow-all`.
  Nothing may depend on its contents.
- Repo hooks under `-p` are gated by `GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS` and folder
  trust; user hooks are unstated. If user hooks fire under `-p`, the judge re-enters AKA's
  own hooks unless the throwaway home suppresses them.
- A 1 MB minified file through `apply_patch` reaches `extractFileEgress`, which §5 requires
  to be **linear in file length**, not merely free of catastrophic regexes.
- An explicit allow becomes a _policy weakening_ if a future CLI build reads it as overriding
  a user's own deny rule. The e2e **enforcement** rows would catch that; the fault rows
  would not.

---

## Testing strategy

**Unit** — `dialect.ts` (all three branches including the no-match one), `event-name.ts`
(valid, unknown, absent argv), `pre-tool-use-decision.ts` across both dialects at all four
enforcement levels plus the degraded-executable-redact path, `tool-response.ts`,
`stop-payload.ts`, `build-info.ts`'s argv offset, `capabilities.ts`.

**Wrapper** — `test/hooks/fail-open-wrapper.test.ts`, driving `runHookFailOpen` directly:
throw, undecided body, watchdog win, a late rejection that must not become an unhandled
rejection (which would exit non-zero, i.e. deny, by a route the wrapper never writes to), the
synchronous-block limit pinned as behaviour, and **one** JSON object — two concatenated
objects do not parse, so a second write is a deny exactly like silence.

**Compile-time** — `hook-output-shapes.test.ts`'s two-direction pins plus the
`emit`-narrows pin. A new union variant must fail to compile until the map names it.

**E2E against built scripts** — `fail-open.e2e.test.ts` with **both halves**, and the
distinction is the whole point: the **fault** rows (empty, malformed, truncated, scalar,
null, binary, oversized stdin, unopenable store) prove `preToolUse` emits exactly one
explicit allow and every other hook emits nothing; the **enforcement** rows (block, redact,
warn, monitor on a real finding) are the positive control without which every absence
assertion on the silent hooks is satisfied vacuously by `''`.

**Integration** — backfill and the setup wizard against a captured `session-state` corpus,
asserting producer attribution skips foreign sessions; the judge asserting the real
`~/.copilot` directory listing is **identical before and after**; the installer asserting a
foreign-entry-seeded `aka.json` is **byte-identical** after install+uninstall.

**Provenance and docs** — `fixture-provenance.test.ts` (a recording with no README
paragraph fails), `capability-matrix.test.ts` (matrix vs `SKILL.md`), and the `CLAUDE.md`
guards that already exist (`claude-md.test.js`'s §3 table and count word,
`privacy-claim-coverage.test.js`'s README classification, `host-plugin-verbs.test.js` if a
host verb ever gets spelled outside the table).

**Regression-sensitive, and worth naming explicitly**

- The prompt-before-`sessionStart` ordering (E1) — drive the recorded order, not the
  intuitive one.
- `resultType` vs exit code (E3) — drive the recorded `false` command.
- `preToolUse` + `permissionRequest` both firing for one call (E4) — assert **one** event.
- The unknown-tool fast path (D3) — assert it emits the allow **and** that no store was
  opened.
- Existing suites that will move: `inventory-assets` (B1–B4), `security` repository
  (`SCAN_COVERAGE`), `required-checks` and `coverage-config` (K3–K5).

**Not** a timing gate. The watchdog property is drivable in milliseconds because
`watchdogMs` is a parameter; assert the _outcome_, never an elapsed wall clock.

---

## Definition of done

1. Every surface × event row in the card's table is confirmed by a fixture or corrected in a
   README, with doc-derived VS Code rows marked unverified and **physically separated** from
   the recordings.
2. The capability matrix is derived from the fixtures, not restated, and a test fails when it
   and `SKILL.md`'s Known limitations disagree.
3. `plugins/copilot/test/e2e/fail-open.e2e.test.ts` drives the **built** scripts and passes
   both halves — fault rows proving exactly one explicit allow on `preToolUse` and silence
   elsewhere, enforcement rows proving block, redact, warn and monitor each emit their
   expected shape.
4. `hook-output-shapes` pins both dialects against the narrowed `emit` union in both
   directions; a new variant fails to compile until the map names it.
5. No hook exits non-zero by any path, and none exits 2.
6. `aka plugins install copilot` and its uninstall are idempotent over a pre-existing
   `~/.copilot/hooks/aka.json` carrying foreign entries, proven byte-for-byte.
7. Backfill and the wizard run against a captured `session-state` corpus, attribute by
   producer, and the judge leaves the real `~/.copilot` unchanged — asserted before and after.
8. The inventory card for Copilot carries its own config assets, and `SCAN_COVERAGE`'s row is
   above zero with its argument recorded in the tree.
9. `HarnessId`, `HARNESS_LABELS`, `TITLE_NEEDLES` and **`resolveHarnessId`** all carry Copilot,
   the last proven by a test rather than by the compiler.
10. `CLAUDE.md` is true again: §3's eleventh row and its count word, §4's new egress item, the
    hook-contract bullets, the dependency graph, the layout block and the bundling rules.
11. `release-plugin-copilot.yml` exists on `plugin-copilot-v*`, and its smoke test asserts the
    explicit allow on `preToolUse` and silence on every other hook.
12. `private` is unset; the temporary Windows pin and the `ci.yml` prose that justified it are
    resolved in the same change.
13. The coverage floor is **measured**, one point below what the suite reports, with the
    measurement beside it.
14. `pnpm lint && pnpm typecheck && pnpm turbo run test` green on macOS and Linux, plus the
    Windows leg, with the no-network runtime guard, the derived non-package-file coverage
    check, the test-only-seam audit and the derived `[^egress]` footnote count all green.
15. **No version bump.** Pre-1.0.0 versions are chosen ad hoc at the scheduled release.

---

## Notes for the implementer

Four places where the spec and the tree disagree, resolved in the tree's favour:

1. The spec says steps 1–7 of the new-package checklist are satisfied. They are — but the
   package declares only three `@akasecurity/*` devDeps. `persistence`, `scanner` and
   `setup-wizard` are missing and every sibling carries them. Task A1.
2. The spec says `COVERAGE_FLOORS` needs an entry added. It already has one, at **99**, and
   the work is to bring it **down**. Task K5.
3. The spec does not mention that `argv[2]` is already spoken for by the siblings'
   `build-info.ts` manifest read. The event token displaces it to `argv[3]`. Task A5.
4. The spec says the `[^egress]` footnote count "MUST move". It moves only if `EGRESS_PATHS`
   gains a **row**, and a fourth judge may belong to the existing `setup calibration` class.
   Decide it explicitly (G6) rather than assuming either way.

Ordering advice that is not in the dependency graph: land A+B as one PR (it is all
scaffolding and vocabulary, and it makes the tree compile with a Copilot harness that renders
nothing), then C+D as the second (the wrapper and the wire are the load-bearing half and
deserve review on their own), then everything else. Do **not** put K3 in the first PR — an
unbuilt non-private package is a worse state than a built private one.
