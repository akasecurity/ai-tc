---
card: cd_mufnz8q0q0
title: Copilot captures nothing on main — no SessionStart, UserPromptSubmit or PostToolUse
stage: implement
---

# Implementation journal

No previous THE MECHANIC attempt existed on this branch — the plan landed with every
checkbox unticked and no journal file, so this is a fresh start from task 1.

## Environment note

The container ships **Node v22.23.2** while the repo's `engines` floor is `>=24` and
`.nvmrc` says 24. No Node 24 is installed and nothing may be downloaded, so every
command here runs with `npm_config_engine_strict=false` and the repo-root
`node_modules/.bin/` binaries directly rather than through `pnpm --filter`. This affects
nothing the suites assert — vitest transpiles with its own pipeline — but it is recorded
because a `pnpm test` run reproduced verbatim will refuse to start.

---

## Slice A — `provider-copilot.ts` (tasks 1–4)

### Task 1 — `packages/plugin-sdk/src/provider-copilot.ts`

Ported verbatim from the member branch
(`origin/devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io`). The file
imports nothing from the adapter, so it needed no rewrite against main's contracts. Its
"reads NO environment … which is why this file carries no `n/no-process-env` opt-out and is
absent from CLAUDE.md §3's table" paragraph and the
"THERE IS DELIBERATELY NO `copilotProviderFromModelId` HERE" paragraph are both intact.

### Task 2 — widen `PluginConfig['provider']` and `loadConfig`

`packages/plugin-sdk/src/config.ts`: added `ResolvedCopilotProvider` to the four places the
three-member union appeared (`PluginConfig['provider']`, `loadConfig`'s `resolveProviderFn`
parameter, and both halves of `resolveProviderSafe`'s signature). Extended the two comment
blocks that enumerate the per-host resolvers so they name the Copilot one and say why it
reads no env.

`packages/plugin-sdk/src/index.ts`: exported `CopilotProvider`, `ResolvedCopilotProvider`
and `resolveCopilotProvider`, in the alphabetical slot after the Codex trio.

### Task 3 — `packages/plugin-sdk/test/provider-copilot.test.ts`

Seven cases: the constant answer; that it stays constant with all three siblings' env vars
stubbed (the discriminating case — a resolver that accidentally keyed off `OPENAI_BASE_URL`
would pass the first case and fail this one); no `gatewayHost`; a fresh object per call;
and the §3 group — the **comment-stripped** source contains no `process.env`, and contains
no `import` either (an env read reached through a helper would be invisible to a plain text
match). Comment-stripping is load-bearing: the module comment itself names three env vars
and the string "environment", so an unstripped match would be satisfied by prose.
A positive control asserts the stripped file still carries the two things it is supposed to.

### Task 4 — gates

- `plugin-sdk` `tsc --noEmit`: clean.
- `plugin-sdk` `eslint src test`: clean.
- `provider-copilot.test.ts`: 7 passed.
- `packages/eslint-config` `effective-config.test.js` + `inline-disables.test.js`:
  **787 passed** — so no new §3 row is demanded, which is the assertion task 4 asks for.

Commit: see `chore(plugin-sdk): resolve the Copilot provider as unknown` below.

---

## Slice B — SessionStart (tasks 5–11)

### Task 5 — `src/hooks/session-start-payload.ts`

Rewritten against main's **dialect-first** argument order: the member branch's
`readSessionId(input, dialect)` / `readCwd(input, dialect)` became
`readSessionId(dialect ?? 'cli', input)` / `readCwd(dialect ?? 'cli', input)`. On main the
first parameter is typed `Dialect`, so the flip is a compile error here rather than a
silent value swap — but the module comment states the order anyway, because the failure it
produces (every capture landing with no session id) is exactly the defect this card fixes.

One deliberate difference from the member file: `cwd` is reported ABSENT rather than
defaulted. The entry needs to tell "no workspace" from "the home directory", because under
VS Code the hook process's own cwd IS the home directory.

### Task 6 — `test/hooks/session-start-payload.test.ts`

9 cases, driven from the recorded `cli/sessionStart.json` and provisional
`vscode-provisional/SessionStart.json` fixtures, never from literals. Added beyond the
member's version: a case asserting the two fixtures spell the session id in DIFFERENT keys
and that each dialect resolves to its own — which is what makes that fixture pair
discriminating rather than decorative — and a case pinning that an absent `cwd` is reported
as `undefined` rather than substituted.

### Task 7 — the three detached children

`src/{sync,history-sync,content-retention}.ts`, copied from their `plugins/antigravity` /
`plugins/codex` counterparts with `SOURCE_TOOL.Copilot` and `aka status` (this plugin ships
no `/aka:status` slash command). `@akasecurity/scanner` was already a devDependency here.

### Task 8 — `src/hooks/session-start.ts`

Rewritten, not ported. Against main's contracts:

- `await runHookFailOpen(main)` with **no** fail-open payload (the member branch's wrapper
  took a required one; main's guards the emit and silence is the no-opinion).
- `main(): Promise<undefined>` — returns `undefined` on every path, so this entry
  structurally cannot emit.
- The stale-binary notice goes through `writeNotice` rather than a direct
  `process.stderr.write`.
- `OWN_EVENTS = {'sessionStart','SessionStart'}` checked against `readEventName()`, which
  the member file omitted — and it matters here more than on `preToolUse`, because
  `sessionEnd` carries the SAME envelope, so nothing in the payload would catch the miswire.
- A payload with no `cwd` returns **before `loadConfig`**, so the store is never opened.

### Task 9 — build entries and `hooks.json`

Four `tsup` entries (`session-start`, `sync`, `history-sync`, `content-retention`) and one
camelCase-only `sessionStart` registration, `${PLUGIN_ROOT}`-anchored, manifest at argv[3],
`timeoutSec: 30`.

### Task 10 — `test/hooks/session-start-order.test.ts`

Real `node:sqlite` store in a temp dir. Three cases: the recorded 20 ms ordering asserted
against the fixtures' own timestamps (plus that both stamps are from the SAME session, or
their ordering says nothing); that a prompt captured BEFORE the root still carries
`root_session_id`; and that three `handleSessionStart` calls leave exactly one session row
with the prompt still attached. `attrs.harness` is asserted as `HARNESS.Copilot`
(`'github-copilot'`) — the member branch asserted `'copilot'`, which is the WIRE id, and
`buildSessionRoot` writes the DISPLAY id through `harnessFromTool`.

### Task 11 — `hooks-manifest.test.ts`

Exact key list → `['sessionStart','preToolUse']`. Added a `${PLUGIN_ROOT}` case, which the
plan's risk section flags as the one thing this file could not previously catch: every other
assertion matches only the `scripts/<name>.js` and `plugin.json` TAILS, so a command
anchored at `${AKA_COPILOT_ROOT:-$HOME/…}` passed all of them and installed wrong.

### Coverage floor, moved early rather than at task 25

The plan puts the re-measure last. Leaving it there would have made every slice-B commit red
on its own package gate, so the floor moved now and is finalized at task 25.

Measured: baseline **86.68% (306/353)** before this slice, **82.10% (312/380)** after — the
denominator grew by 27 lines (four entry scripts that the e2e suite runs as CHILD
PROCESSES, which the parent's v8 coverage cannot see). Windows loses 8 further covered lines
to three unprivileged symlink skips, so the Windows reading is 304/380 = **80.00** and the
floor is **79**, one below the platform that reads lowest.

### Slice B gates

- `plugins/copilot` full suite: **20 files, 287 passed**.
- `plugins/copilot` `tsc --noEmit` and `eslint src test *.config.*`: clean.
- `packages/eslint-config` `coverage-config.test.js`: 17 passed.

---

## Slice C — UserPromptSubmit (tasks 12–15)

### Task 12 — `test/helpers/no-echo.{ts,test.ts}`

Copied from `plugins/codex/test/helpers/` — **both** files, control assertions included.
Two adaptations: the peer list now names all eight copies (it was three files out of date),
and limit 3's wording was rewritten because it named a codex-only suite. The masked-preview
control already calls `maskMatch` rather than a literal, which is what task 12 asked for.

Added one case beyond the codex copy: `maskMatch`'s **email** branch reveals the whole
domain, so it fills the window on purpose and `expectNoEchoOf` refuses it. That boundary is
written down here rather than re-derived, so a suite that binds the helper to a pii preview
reads as out of scope rather than as a leak it found. 11 passed.

### Task 13 — `src/hooks/user-prompt-payload.ts`

`PromptEvent`, `PromptCapture`, `readPromptCapture`, `promptPersist`, and a **two-channel**
`promptDecision(event, dialect, result) → { output, notice? }`. Three rewrites against main:

- The member branch's `promptEmitPayload` returned a bare `SystemMessageOutput` for BOTH
  dialects. On main `systemMessage` is not an output field on the CLI, so that object is a
  payload the host drops — the user is told nothing while the test, which asserts on the
  returned object, stays green. The CLI half now comes back as `notice` for stderr.
- `HookEventName` → main's `HookEvent`.
- `uniqueRuleIds` takes a mutable array on main, so the readonly findings are spread.

`userPromptTransformed` keeps its row in the field table and is deliberately absent from
`hooks.json`: the set says what the script can HANDLE, the manifest says what it is SPAWNED
for, so wiring it later is a manifest-only change.

### Task 14 — `test/hooks/user-prompt-payload.test.ts`

18 cases. The discriminating one asserts from the FIXTURES that
`userPromptTransformed.prompt` equals `userPromptSubmitted.prompt` verbatim and that the
transformed text is a strict superset — which is what makes the double-count argument
checkable rather than quoted. The two-channel case asserts the CLI notice and the VS Code
`systemMessage` are the same string on different channels, so a decision returning one
object for both dialects fails. Every message built from a finding is run through
`expectNoEchoOf` with a positive control (`toContain('generic.secret')`) on the same bytes,
and the block/redact cases refuse the words `blocked`, `redacted`, `never reached` and
`withheld` — the enforcement claims this surface cannot make.

Fixture is high-entropy and deliberately **not** credential-shaped (public repository).

### Task 15 — `src/hooks/user-prompt-submit.ts`

Entry. `kind: 'prompt'`, `rewritable: false`, `persist` from `promptPersist`, onboarding
nudge on the clean path routed per dialect, `await runHookFailOpen(main)` with no fail-open
payload. `baseMetadata(dialect, input)` and `readSessionId(dialect, input)` — the member
branch called both with the arguments flipped. Registered `userPromptSubmitted` only.

### Slice C gates

- `plugins/copilot` full suite: **22 files, 316 passed**.
- `tsc --noEmit` + `eslint src test`: clean.
- Coverage floor moved 79 → **74** (330/429 = 76.92 here; Windows ≈ 75.06). Finalized at
  task 25.
