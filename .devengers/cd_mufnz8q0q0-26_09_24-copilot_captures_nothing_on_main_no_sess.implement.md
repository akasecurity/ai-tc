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
