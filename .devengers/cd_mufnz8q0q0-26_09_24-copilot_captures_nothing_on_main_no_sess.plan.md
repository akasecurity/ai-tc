---
card: cd_mufnz8q0q0
title: Copilot captures nothing on main — no SessionStart, UserPromptSubmit or PostToolUse
stage: plan
created: 2026-09-24
---

Every dependency betrays you eventually. This one already has: seven files exist,
they compile against contracts that no longer exist, and the gate that would have
caught the drift is a `toEqual(['preToolUse'])` in a test nobody has had to move yet.
So: no cherry-pick, four vertical slices, and each slice moves its own gate in the
same commit.

## Relevant existing architecture

**The adapter, `plugins/copilot/` (all of it on `main` today):**

- `hooks.json` — one event: `preToolUse`, command
  `node "${PLUGIN_ROOT}/scripts/pre-tool-use.js" preToolUse "${PLUGIN_ROOT}/plugin.json"`,
  `timeoutSec: 30`. `plugin.json` points `hooks` at `./hooks.json`.
- `src/hooks/event-name.ts` — `CLI_EVENTS` (15 recorded camelCase names), `VSCODE_EVENTS`
  (8 doc-derived PascalCase names), `readEventName(argv = process.argv)` reading **argv[2]**
  only. An unknown/absent token answers `undefined` and that is *not* a decline.
- `src/hooks/dialect.ts` — `Dialect = 'cli' | 'vscode'`, `detectDialect(payload: unknown)`,
  `readSessionId(dialect, input)`, `readCwd(_dialect, input)`, `readToolCall(dialect, input)`.
  **Dialect-first argument order.** `detectDialect` rejects arrays via a private `isRecord`.
- `src/hooks/shared.ts` — `WATCHDOG_MS = 24_000`, `readStdin`, `parseJson` (rejects arrays),
  `getString`, `emit(output: HookOutput)` (awaited flush), `writeNotice(message, write?)`
  (**the stderr channel**), `runHookFailOpen(main, failOpen?, watchdogMs?)` with an
  **optional** fail-open payload and a guarded emit, `baseMetadata(dialect, input)` (no
  `process.cwd()` fallback on `vscode`). `HookOutput` is a **six**-member union:
  `CliPermissionDecisionOutput` (`permissionDecision: 'deny'` only), `CliModifiedArgsOutput`,
  `CliModifiedResultOutput`, `VsCodePreToolUseOutput`, `VsCodeBlockOutput`,
  `SystemMessageOutput`.
- `src/hooks/pre-tool-use-decision.ts` — `ScannableField`, `CLI_SCANNABLE_FIELDS`,
  `VSCODE_SCANNABLE_FIELDS`, `scannableFieldsFor(dialect)`, `denyOutput`,
  `PreToolUseOutput`, and the **two-channel** `PreToolUseDecision { output: PreToolUseOutput | null; notice?: string }`.
- `src/hooks/store-health.ts` — `openGatewayOrNull`, `storeUnavailableMessage`,
  `claimStoreUnavailableWarning`, `warnIfStoreRedirected`.
- `src/hooks/pre-tool-use.ts` — the one entry. `OWN_EVENTS = new Set(['preToolUse','PreToolUse'])`,
  ends `await runHookFailOpen(main)` with **no** fail-open payload.
- `src/build-info.ts` — `PLUGIN_PACKAGE`, `MANIFEST_ARGV_INDEX = 3`, `pluginBuild()`,
  `harnessVersionFromArgv(argv)`. **Both of the last two are already written and unused** —
  they exist for exactly the SessionStart entry this card restores.
- `src/capabilities.ts` — `CAPABILITY_MATRIX` (11 rows), `Channel = 'block'|'rewrite'|'warn'|'none'`,
  `capabilitiesFor`, `surfaceIsVerified`. Rendered into `skills/setup/SKILL.md` by a test.
- `src/exception-guidance.ts` — `blockMessage`, `exceptionPointer`, `withheldBanner`,
  `withheldToolText`. All four already exist; the response path needs the last two.
- `tsup.config.ts` — entries `{ 'pre-tool-use', 'scan-worker' }`, `outDir: 'scripts'`,
  `noExternal: [/^@akasecurity\//, 'zod']`, plus `normalizeSqliteSpecifier` and the
  triage-rubric copy in `onSuccess`.

**Shared packages it stands on:**

- `@akasecurity/plugin-runtime` — `handleSessionStart(input, config)` does the whole
  once-per-session pass (`claimSessionStart` → `resolveDataGateway` → `resolveInventoryContext`
  → `ensureInventory` → `buildSessionRoot` → `resolveProjectFiles` → `resolveConfigInventory`
  → maintenance) and then fires **three detached children resolved as siblings of the running
  script**: `triggerPolicySync` (`scripts/sync.js`), `triggerHistorySync`
  (`scripts/history-sync.js`), `triggerContentRetention` (`scripts/content-retention.js`).
  Also `resolveDataGateway`, `runContentRetentionPass`.
  `SessionStartInput.tool` is typed `SourceTool`, so it is a compile-time check.
- `@akasecurity/plugin-sdk` — `loadConfig(base?, resolveProviderFn?)`, `createPluginRuntime`,
  `PluginRuntime.capture(input, opts)`, `claimOnboardingNudge`, `uniqueRuleIds`,
  `provider.ts` / `provider-codex.ts` / `provider-antigravity.ts`. `PluginConfig['provider']`
  is a three-member union today.
- `@akasecurity/schema` — `SOURCE_TOOL.Copilot = 'copilot'`, `HARNESS.Copilot = 'github-copilot'`,
  and `TOOL_TO_HARNESS[SOURCE_TOOL.Copilot]` **already exist**. No §2 registry edit is needed.

**The gates that will move, and what each reads:**

| Gate | Reads | What breaks when an event is added |
|---|---|---|
| `test/hooks-manifest.test.ts` | `hooks.json`, `tsup.config.ts` text, `event-name.ts`, `WATCHDOG_MS`, `build-info.ts` | `expect(Object.keys(MANIFEST.hooks)).toEqual(['preToolUse'])` |
| `test/capability-matrix.test.ts` | `src/capabilities.ts` + `skills/setup/SKILL.md` | row-for-row render; `/Only the pre-tool-use event is wired/u` |
| `test/hook-output-shapes.test.ts` | `shared.ts` prose + `HookOutput` + **`CLAUDE.md`** | the "six shapes" sentence if the union widens |
| `test/fixture-provenance.test.ts` | both fixture dirs + `VSCODE_EVENTS` | only if fixtures are added |
| `test/cli-fixture-shapes.test.ts` | `test/fixtures/cli/*` + its README | only if fixtures are added |
| `test/e2e/fail-open.e2e.test.ts` | the **built** `scripts/*.js` | new scripts are not covered until rows are added |
| `test/vitest/coverage.ts` | per-package floor, `'@akasecurity/ai-tc-copilot': 83` | new source moves the measured number |
| `CLAUDE.md` line ~898 | prose | "registers the camelCase event **alone**" becomes false |

## Existing patterns

Extend these; do not invent.

- **Codex is the template for all three entries.** `plugins/codex/src/hooks/session-start.ts`
  (read stdin → `loadConfig(undefined, <hostResolver>)` → `warnIfStoreRedirected` →
  `handleSessionStart` → stale notice to stderr), `user-prompt-submit.ts` (guard empty prompt →
  gateway → `createPluginRuntime` → `runtime.capture({ kind: 'prompt' })` in try/finally →
  emit), and the **three-module PostToolUse split**: `tool-response.ts` (pure field table +
  path read/replace), `scan-response.ts` (pure orchestration + payload shaping, takes a
  `capture` callback), `post-tool-use.ts` (stdio glue only). The split exists because a hook
  entry runs `main()` on import and would hang vitest collection — keep it.
- **Antigravity is the template for the tail.** `await runHookFailOpen(main)`, not Codex's
  `try/catch + process.exit(0)`. Copilot's `shared.ts` already carries that wrapper.
- **`plugins/codex/src/{sync,history-sync,content-retention}.ts`** — 38/22/22 lines each, the
  three detached children `handleSessionStart` spawns by sibling filename. Copy shape verbatim.
- **`packages/plugin-sdk/src/provider-codex.ts`** — the twin shape a `provider-copilot.ts`
  follows, minus the env read. Its `n/no-process-env` opt-out lives in
  `packages/plugin-sdk/eslint.config.mjs` as a file-scoped block; **`provider-copilot.ts`
  needs no such block and no CLAUDE.md §3 row**, because it reads no environment.
- **`decidePreToolUse`'s two-channel return** is the pattern the prompt and response paths must
  copy: `{ output: HookOutput | null; notice?: string }`. On the CLI `systemMessage` is not an
  output field, so a message goes to `writeNotice`; on VS Code it goes on stdout.
- **`plugins/copilot/test/helpers/no-echo.ts` does not exist yet.** The package has no raw-value
  helper; `plugins/codex/test/helpers/no-echo.ts` + its `no-echo.test.ts` is the pair to copy
  (both files, including the control assertions).

## Implementation strategy

**Rewrite, do not port.** The member branch's `shared.ts`/`dialect.ts`/`pre-tool-use-decision.ts`
are an *earlier generation* that `main` has since retracted. The three concrete traps, confirmed
by reading both refs:

1. **Argument order is flipped.** Branch: `readSessionId(payload, dialect)`,
   `baseMetadata(input, dialect)`. Main: `readSessionId(dialect, input)`, `baseMetadata(dialect, input)`.
   Both compile if you get it wrong in a way that typechecks — the values are both strings in
   some call shapes. Read every call site.
2. **The branch emits `systemMessage` on the CLI, and main says that field does not exist there.**
   `promptEmitPayload` and `responseEmitPayload` both return a bare `SystemMessageOutput` for
   either dialect. On main that is a payload the host drops. Every such site becomes a
   two-channel return whose CLI half goes to `writeNotice`.
3. **The branch has `allowPayload` and a *required* `failOpen`; main has neither.** Main's whole
   fail-open guarantee is the **exit code**, and silence is the no-opinion. Nothing ported may
   manufacture a payload on a path that reached no verdict.

Plus two manifest-level rewrites: `${AKA_COPILOT_ROOT:-$HOME/...}` → `${PLUGIN_ROOT}`, and
**camelCase keys only** — the branch registers both casings for every event, which on the one
shipped host spawns each script twice per event, the second time with a payload the other
dialect's table has no row for (commit `801cc2c6`). A VS Code registration belongs in the file
VS Code reads, not here.

**Four slices, each independently shippable and each moving its own gate:**

- **A — `provider-copilot.ts`.** The one file that ports essentially verbatim (it imports
  nothing from the adapter). Widen `PluginConfig['provider']` to include
  `ResolvedCopilotProvider`, export from the SDK index, add the SDK's own unit test. No eslint
  block, no §3 table row — it reads no env, and its module comment must keep saying so.
- **B — SessionStart.** `session-start-payload.ts` (pure) + `session-start.ts` (entry) +
  the three detached-child entries `handleSessionStart` spawns. Register `sessionStart` only.
- **C — UserPromptSubmit.** `user-prompt-payload.ts` (pure) + `user-prompt-submit.ts` (entry).
  Register `userPromptSubmitted` only — **not** `userPromptTransformed`, whose payload
  re-carries the same `prompt` verbatim, so registering both double-counts every prompt. Keep
  the transformed token in the reader's table so a later registration is a manifest-only change.
- **D — PostToolUse.** `tool-response.ts` + `scan-response.ts` (both pure) +
  `post-tool-use.ts` (entry). Register `postToolUse` only.

**The enforcement decision, stated once so it is not re-litigated per file.**
Slices C and D **capture and scan; they do not enforce.** Three reasons, all from evidence in
the tree:

- Prompts have **no channel**. On the CLI only `preToolUse` is fail-closed, and
  `userPromptSubmitted.modifiedPrompt` is listed under "Not measured" in
  `test/fixtures/cli/README.md`. On VS Code the block channel is **exit 2**, and
  `shared.ts` guarantees no path exits non-zero and none exits 2 — a guarantee
  `hook-output-shapes.test.ts` pins against `CLAUDE.md`. Changing it is a different card.
- Tool results have **no verified channel**. `postToolUse.modifiedResult` is also under
  "Not measured". Emitting one and recording a withhold would let the audit trail claim a
  redaction that never happened — the exact failure `rewritable: false` exists to prevent.
- So **every capture on these two paths passes `rewritable: false`**, which resolves a `redact`
  to `settings.redactFallback` *inside the runtime*, where the decision, `findings.actionTaken`
  and the ledger read one answer. The hook never escalates for itself.

The user-visible consequence is a **notice**: stderr on the CLI, `systemMessage` on VS Code.
The capability rows therefore stay `channel: 'none'` — which keeps
`capability-matrix.test.ts`'s data assertion (`acting events == ['pretooluse']`) green — but
their `note` changes from "Not wired" to a statement that the text is captured and scanned and
that nothing can be withheld. The SKILL.md sentence and its regex must change to match.

**Ordering evidence that must be encoded, not assumed.** `test/fixtures/cli/README.md` records
that the CLI stamps `userPromptSubmitted` at `…858031` and `sessionStart` at `…858051` — the
session root opens **20 ms after** the first prompt it started with. A prompt capture therefore
lands before its root exists. That is fine (the root is content-addressed on the session id and
`claimSessionStart` makes repeats a no-op) but it is the kind of fact that rots, so it gets a
test of its own.

## File-level changes

**Create — `packages/plugin-sdk/`**

- `src/provider-copilot.ts` — `CopilotProvider = 'unknown'`, `ResolvedCopilotProvider`,
  `resolveCopilotProvider()`. Port the branch file's text; keep the paragraph explaining why
  there is deliberately no `copilotProviderFromModelId`.
- `test/provider-copilot.test.ts` — the shape, the constant answer, and a case pinning that the
  module source contains no `process.env` read (that absence is what keeps it off §3's table).

**Modify — `packages/plugin-sdk/`**

- `src/config.ts` — widen the `resolveProviderFn` parameter type and `PluginConfig['provider']`
  to include `ResolvedCopilotProvider`; extend the comment listing the per-host resolvers.
- `src/index.ts` — export the type trio and `resolveCopilotProvider`.

**Create — `plugins/copilot/src/`**

- `hooks/session-start-payload.ts` — `SessionStartFacts`, `harnessInterfaceFor(dialect)`,
  `readSessionStartFacts(input)`. Rewritten against main's `readSessionId(dialect, input)` /
  `readCwd(dialect, input)` order.
- `hooks/session-start.ts` — entry. `OWN_EVENTS = new Set(['sessionStart','SessionStart'])`,
  `loadConfig(undefined, resolveCopilotProvider)`, `handleSessionStart({ sessionId, cwd,
  tool: SOURCE_TOOL.Copilot, harnessVersion: harnessVersionFromArgv() ?? pluginBuild()?.version,
  harnessInterface, pluginBuild })`, stale notice via `writeNotice`, tail
  `await runHookFailOpen(main)` returning `undefined` always (this hook emits nothing).
- `hooks/user-prompt-payload.ts` — `PromptEvent`, `PromptCapture`, `readPromptCapture`,
  `promptPersist`, and a **two-channel** `promptDecision(event, dialect, result):
  { output: HookOutput | null; notice?: string }`.
- `hooks/user-prompt-submit.ts` — entry, `OWN_EVENTS = new Set(['userPromptSubmitted',
  'userPromptTransformed','UserPromptSubmit'])`, capture `kind: 'prompt'` with
  `rewritable: false`.
- `hooks/tool-response.ts` — `ScannableResponseField`, `responseKey(dialect)`,
  `scannableResponseFields(dialect, response)`, `replaceResponseField`. Envelope table:
  `cli → { key: 'toolResult', paths: [['textResultForLlm']] }`,
  `vscode → { key: 'tool_response', paths: [[]] }`. Reads `resultType` **never** — it reports
  whether the invocation succeeded, not the command's exit code.
- `hooks/scan-response.ts` — `ResponseScanOutcome`, `scanResponseFields(toolName, fields, capture)`,
  and a two-channel `responseDecision(dialect, outcome)`.
- `hooks/post-tool-use.ts` — entry, `OWN_EVENTS = new Set(['postToolUse','PostToolUse'])`,
  capture `kind: 'response'`, `{ persist: 'with-findings', rewritable: false }`.
- `sync.ts`, `history-sync.ts`, `content-retention.ts` — the three detached children, copied
  from their `plugins/codex/src/` counterparts.

**Create — `plugins/copilot/test/`**

- `hooks/session-start-payload.test.ts`, `hooks/user-prompt-payload.test.ts`,
  `hooks/tool-response.test.ts`, `hooks/scan-response.test.ts`, `hooks/session-start-order.test.ts`
  (real temp store, `handleSessionStart`, the 20 ms ordering fact, the once-per-session claim).
- `helpers/no-echo.ts` + `helpers/no-echo.test.ts` — copied from `plugins/codex/test/helpers/`,
  both files, control assertions included.

**Modify — `plugins/copilot/`**

- `hooks.json` — three new **camelCase-only** entries: `sessionStart` → `scripts/session-start.js`,
  `userPromptSubmitted` → `scripts/user-prompt-submit.js`, `postToolUse` → `scripts/post-tool-use.js`.
  Each `node "${PLUGIN_ROOT}/scripts/<name>.js" <event> "${PLUGIN_ROOT}/plugin.json"`,
  `timeoutSec: 30`, `type: 'command'` — the manifest path on **every** entry, because
  `hooks-manifest.test.ts` checks `MANIFEST_ARGV_INDEX` per entry (the branch omitted it on all
  but session-start).
- `tsup.config.ts` — six new entry keys: `session-start`, `user-prompt-submit`, `post-tool-use`,
  `sync`, `history-sync`, `content-retention`.
- `src/capabilities.ts` — rewrite the `note` on the `cli/userPromptSubmitted/prompt`,
  `cli/postToolUse/toolResult`, `vscode/UserPromptSubmit/prompt` and `vscode/PostToolUse/tool_response`
  rows; add rows for `cli/sessionStart` and `vscode/SessionStart` (subject `session`,
  channel `none`, `verified: true` for CLI / `false` for VS Code).
- `skills/setup/SKILL.md` — re-render the table; rewrite the "Only the pre-tool-use event is
  wired" paragraph into "Only the pre-tool-use event **enforces**", stating plainly that prompts
  and tool results are now recorded, that neither can be stopped or rewritten, and that there is
  still no history backfill.
- `test/hooks-manifest.test.ts` — move `toEqual(['preToolUse'])` to the new exact four-key list.
- `test/capability-matrix.test.ts` — move the prose regex to the new sentence.
- `test/e2e/fail-open.e2e.test.ts` — drive the three new built scripts through the fault rows
  and add a positive control per script.
- `vitest.config.ts` — only if the store-backed order test needs a timeout above 20 s; prefer
  keeping it under (a raise moves `hook-timeout-ratchet.test.js` and must be deliberate).

**Modify — repo root**

- `CLAUDE.md` — line ~898, "registers the camelCase event **alone**" → the plural form naming
  the four events; keep the "spawns the hook twice per call" argument intact, because
  `hook-output-shapes.test.ts` matches that phrase.
- `test/vitest/coverage.ts` — re-measure `'@akasecurity/ai-tc-copilot'` and set the floor one
  point below the measured number, with the measurement in the comment beside it.

**Out of scope, deliberately:** `~/.copilot/session-state/<uuid>/events.jsonl` history/backfill
(no recording exists; a parser tested against a fixture written to match it proves nothing),
any VS Code hook-file registration, and any change to the "no path exits non-zero, none exits 2"
guarantee.

## Ordered implementation tasks

- [x] 1. Add `packages/plugin-sdk/src/provider-copilot.ts`, ported from the member branch, with its "no env read, therefore no §3 row" paragraph intact.
- [x] 2. Widen `PluginConfig['provider']` and `loadConfig`'s `resolveProviderFn` type in `packages/plugin-sdk/src/config.ts` to include `ResolvedCopilotProvider`; export the trio from `src/index.ts`.
- [x] 3. Add `packages/plugin-sdk/test/provider-copilot.test.ts`, including a case asserting the module source contains no `process.env`.
- [x] 4. Run `pnpm --filter @akasecurity/plugin-sdk test typecheck lint` and `pnpm lint` at the root; confirm no new §3 row is demanded by `effective-config.test.js` or `inline-disables.test.js`.
- [x] 5. Add `plugins/copilot/src/hooks/session-start-payload.ts`, rewritten against main's dialect-first argument order.
- [x] 6. Add `plugins/copilot/test/hooks/session-start-payload.test.ts`, driven from the existing `cli/sessionStart.json` and `vscode-provisional/SessionStart.json` fixtures plus a `null` and a wrong-casing case.
- [x] 7. Add `plugins/copilot/src/{sync,history-sync,content-retention}.ts`, copied from their `plugins/codex/src/` counterparts.
- [x] 8. Add `plugins/copilot/src/hooks/session-start.ts` — dialect-resolved facts, `loadConfig(undefined, resolveCopilotProvider)`, `handleSessionStart`, stale notice through `writeNotice`, `await runHookFailOpen(main)` with no fail-open payload.
- [x] 9. Add the four `tsup.config.ts` entries for slice B (`session-start`, `sync`, `history-sync`, `content-retention`) and register `sessionStart` in `hooks.json` with the manifest path at argv[3].
- [x] 10. Add `plugins/copilot/test/hooks/session-start-order.test.ts` — a real temp store; assert the recorded 20 ms prompt-before-session ordering, that a capture preceding the root still carries `root_session_id`, and that three `handleSessionStart` calls leave exactly one session row.
- [x] 11. Update `test/hooks-manifest.test.ts`'s exact key list to `['preToolUse','sessionStart']`; run `pnpm --filter @akasecurity/ai-tc-copilot test` and confirm the build-driven manifest cases pass against the real emitted scripts.
- [x] 12. Copy `plugins/codex/test/helpers/no-echo.ts` **and** `no-echo.test.ts` into `plugins/copilot/test/helpers/`, adapting the masked-preview control to call `maskMatch` rather than a literal.
- [x] 13. Add `plugins/copilot/src/hooks/user-prompt-payload.ts` with a two-channel `promptDecision` — `writeNotice` text on `cli`, `systemMessage` on `vscode`, `null` output on both when there is nothing to say.
- [x] 14. Add `plugins/copilot/test/hooks/user-prompt-payload.test.ts`, including the discriminating case that `userPromptTransformed` re-carries `prompt` verbatim, and `expectNoEchoOf` on every message built from a finding.
- [x] 15. Add `plugins/copilot/src/hooks/user-prompt-submit.ts` (capture `kind: 'prompt'`, `rewritable: false`, onboarding nudge on the clean path), add its `tsup` entry, and register `userPromptSubmitted` only in `hooks.json`.
- [x] 16. Add `plugins/copilot/src/hooks/tool-response.ts` with the per-dialect envelope table, and `test/hooks/tool-response.test.ts` — including the `resultType`-is-not-an-exit-code trap case and the comment-stripped source assertion that the module never reads it.
- [x] 17. Add `plugins/copilot/src/hooks/scan-response.ts` — `scanResponseFields` plus a two-channel `responseDecision` that emits **no** `modifiedResult` and **no** `decision: 'block'`, and says honestly that the result reached the model.
- [x] 18. Add `plugins/copilot/test/hooks/scan-response.test.ts` with a high-entropy non-credential-shaped fixture, `expectNoEchoOf` on every banner, and a per-dialect difference case.
- [x] 19. Add `plugins/copilot/src/hooks/post-tool-use.ts` (capture `kind: 'response'`, `{ persist: 'with-findings', rewritable: false }`), add its `tsup` entry, and register `postToolUse` in `hooks.json`.
- [x] 20. Update `test/hooks-manifest.test.ts`'s exact key list to the final four and confirm no PascalCase key was introduced.
- [x] 21. Extend `test/e2e/fail-open.e2e.test.ts` to drive `session-start.js`, `user-prompt-submit.js` and `post-tool-use.js` through every fault row (empty, malformed, truncated, scalar, binary, oversized stdin; unopenable store) asserting exit 0, and add one positive control per script so the absence assertions are not vacuous.
- [x] 22. Update `src/capabilities.ts` — new `sessionStart`/`SessionStart` rows, rewritten notes on the four prompt/result rows.
- [x] 23. Re-render the table in `skills/setup/SKILL.md` and rewrite the "Only the pre-tool-use event is wired" paragraph; update the matching regex in `test/capability-matrix.test.ts`.
- [x] 24. Update `CLAUDE.md` line ~898 to the plural event list, leaving the "spawns the hook twice per call" sentence intact; re-run `pnpm --filter @akasecurity/ai-tc-copilot test` so `hook-output-shapes.test.ts` re-reads it.
- [x] 25. Re-measure the package's coverage, update `'@akasecurity/ai-tc-copilot'` in `test/vitest/coverage.ts` to one point below the measured number, and record the measurement in the comment.
- [x] 26. Full sweep: `pnpm lint && pnpm typecheck && pnpm test`, then `pnpm --filter @akasecurity/ai-tc-copilot build` and re-run that package's suite against the freshly emitted `scripts/`.

## Dependencies

- Tasks 1–4 (slice A) gate task 8: `session-start.ts` cannot compile without
  `resolveCopilotProvider` and the widened `PluginConfig['provider']`.
- Task 7 gates task 9 and must not be skipped: `handleSessionStart` spawns
  `scripts/{sync,history-sync,content-retention}.js` as siblings of the running script. Two are
  attached-only, but `triggerContentRetention` is gated on `bodyRetention.enabled` alone — so a
  machine with body expiry switched on would spawn a script that does not exist. Ship the
  entries with the hook, not after it.
- Task 9 gates task 11, and task 19 gates task 20: `hooks-manifest.test.ts` asserts the exact
  key set, so the manifest edit and the test edit land in the same commit or `main` goes red.
- Task 12 gates tasks 14 and 18: those suites assert with `expectNoEchoOf`, which does not exist
  in this package yet.
- Tasks 15 and 19 gate 22–23: the capability rows describe what is wired, so they move after the
  wiring, not before.
- Task 21 requires every `tsup` entry to exist — it drives the **built** scripts.
- Task 25 is last among the source tasks: the floor is measured, and measuring it before the
  final test files land gives a number that is wrong in the direction that fails CI.
- Slices B, C and D are otherwise independent of each other and can be reviewed separately.

## Risks

- **The flipped argument order is the silent one.** `readSessionId(payload, dialect)` vs
  `readSessionId(dialect, input)` — both parameters are consumed as values, and a wrong-order
  call can typecheck at some call shapes. Symptom: every capture lands with no `sessionId`, so
  the dashboard shows events under no session and the defect looks identical to the one this
  card is fixing. Mitigation: the payload readers are pure and unit-tested against the real
  fixtures before any entry imports them (tasks 6, 14, 16 precede 8, 15, 19).
- **A PascalCase key creeps back in.** The branch's manifest registers both casings for all four
  events. Registering both here spawns every script twice per event on the one shipped host,
  the second time with a payload whose `tool_name`/`toolName` the other table has no row for —
  a wasted 30 s-budget process per event that scans nothing. `hooks-manifest.test.ts` catches
  it; do not weaken that case to "no more than two keys".
- **`${AKA_COPILOT_ROOT:-$HOME/...}` creeping back in.** `hooks-manifest.test.ts` does **not**
  assert the `${PLUGIN_ROOT}` prefix — it matches only the `scripts/<name>.js` and `plugin.json`
  tails. A pasted branch command would pass every case and install wrong. Check by eye, or add
  the assertion while you are in that file.
- **Emitting a payload on a no-verdict path.** The branch's `runHookFailOpen` takes a *required*
  fail-open payload and always emits; main's is optional and guards the emit. A ported entry
  that passes one re-introduces the pre-approval `801cc2c6` removed. Pass nothing.
- **`systemMessage` on the CLI.** Three ported functions do this. It is not an output field on
  that host, so the message is dropped and the user sees nothing while the tests — which assert
  on the returned object — stay green. Every CLI-side message goes through `writeNotice`.
- **The `HookOutput` union must not widen.** If a design turn needs a seventh variant, the
  "six shapes" sentence in `shared.ts` and the map in `hook-output-shapes.test.ts` move
  together, and the compile-time `EveryVariantNamed` / `EveryNameEmitted` pair will say so.
  Prefer not widening: everything slices B–D need is already in the union.
- **The store-backed order test is the slowest thing in the package.** `testTimeout`/`hookTimeout`
  are pinned at 20 s each by `hook-timeout-ratchet.test.js`. Keep the fixture small (a handful of
  rows); a raise is a deliberate edit to that ratchet, not a fix for a slow test.
- **Coverage floor.** ~700 new source lines land at once. The floor is 83 and is measured, not
  estimated. A number taken on macOS can read lower on the Windows leg — if CI disagrees with
  the local measurement, re-take it on the platform that reports lowest rather than widening.
- **`resolveConfigInventory` and `resolveProjectFiles` now run for Copilot sessions.** They walk
  the workspace and the host config dir. The adversarial-corpus guards cover the walkers
  themselves, but this is the first time a Copilot hook opens the store on a non-tool event —
  expect the `preToolUse` fast path (return before `loadConfig`) to no longer be the package's
  only cheap path, and keep each new entry's own early return equally early.
- **`cwd` may be absent under VS Code.** `SessionStartInput.cwd` is required and `baseMetadata`
  deliberately does not fall back to `process.cwd()` on that dialect, because a VS Code hook's
  spawn cwd defaults to the home directory. A session-start entry with no `cwd` must **return
  without opening the store**, never resolve a repo from `~`.

## Testing strategy

- **Unit, pure modules (the bulk).** `session-start-payload`, `user-prompt-payload`,
  `tool-response`, `scan-response` are all I/O-free and driven directly. Every payload reader is
  driven from the **existing recorded fixtures** (`cli/sessionStart.json`,
  `cli/userPromptSubmitted.json`, `cli/userPromptTransformed.json`, `cli/postToolUse.json`) and
  their `vscode-provisional/` counterparts — never from literals written to match the table, for
  the reason that directory's README gives.
- **Raw-value hygiene.** Every message a finding produces is asserted with `expectNoEchoOf`, run
  by run, from the newly-copied `plugins/copilot/test/helpers/no-echo.ts`. Each assertion is
  paired with a positive control naming what the message *does* say, or the absence check goes
  vacuous. Fixtures are high-entropy and **not** credential-shaped — this repository is public.
- **Integration, real store.** `session-start-order.test.ts` opens a real `node:sqlite` store in
  a temp dir and asserts: the recorded prompt-before-session ordering; that a capture written
  before the root still hangs off `root_session_id`; that repeated `handleSessionStart` calls
  leave one session row; and that the root's attributes carry `harness: 'github-copilot'`,
  `harness_interface`, and `provider: 'unknown'`.
- **E2E, built scripts.** `test/e2e/fail-open.e2e.test.ts` gains the three new scripts across
  every fault row, asserting exit 0 — plus, per script, one **positive control** that a real
  finding produces the shape that script is supposed to emit. Without the control every "wrote
  nothing" row is satisfied by a script that emits nothing ever.
- **Manifest/build coupling.** `hooks-manifest.test.ts` runs after the real build (globalSetup),
  so it proves each registered script is a `tsup` entry *and* was emitted. Its exact-key case is
  the regression guard for the double-casing defect; keep it exact.
- **Doc/data coupling.** `capability-matrix.test.ts` re-renders `SKILL.md` row for row;
  `hook-output-shapes.test.ts` re-reads `CLAUDE.md`. Both fail on a prose edit that drifts from
  the code, which is the point.
- **Regression-sensitive.** Re-run `plugins/copilot`'s **whole** existing suite after every
  slice — particularly `pre-tool-use-decision.test.ts`, `shared.test.ts` and `dialect.test.ts`,
  since the new entries import those modules and any convenience change to them is a change to
  the one enforcing hook that already ships.
- **Not tested here, and said so out loud:** VS Code behaviour (no live install — every new
  VS Code capability row stays `verified: false`), `modifiedResult` and `modifiedPrompt` (both
  unmeasured, both deliberately unused), and session history/backfill (no recording exists).

## Definition of done

- `plugins/copilot/hooks.json` registers exactly four events — `sessionStart`,
  `userPromptSubmitted`, `preToolUse`, `postToolUse` — all camelCase, each naming an emitted
  `${PLUGIN_ROOT}/scripts/<name>.js`, passing its own event token at argv[2] and
  `${PLUGIN_ROOT}/plugin.json` at argv[3], with `timeoutSec: 30`.
- A Copilot CLI session opens a session root in `~/.aka/data/aka.db`, records its prompt as a
  `prompt` event and its tool result as a `response` event, and the dashboard's Activity and
  Security pages render that session the way they render a Codex one.
- `provider-copilot.ts` ships, reads no environment, adds no row to CLAUDE.md §3's table, and
  the session root carries `provider: 'unknown'`.
- No hook path exits non-zero, none exits 2, and none emits an allow on the CLI —
  `hook-output-shapes.test.ts` and `e2e/fail-open.e2e.test.ts` both green over all four scripts.
- `HookOutput` is still a six-member union.
- `src/capabilities.ts`, `skills/setup/SKILL.md` and `CLAUDE.md` all describe the wiring that
  now exists, with every VS Code row still `verified: false`, and the three tests that read
  those files pass without their assertions having been weakened.
- `pnpm lint && pnpm typecheck && pnpm test` green at the root, including the re-measured
  coverage floor and the unchanged `hook-timeout-ratchet` entry.
- History/backfill remains unimplemented and is stated as such in `skills/setup/SKILL.md`'s
  Known limitations.
