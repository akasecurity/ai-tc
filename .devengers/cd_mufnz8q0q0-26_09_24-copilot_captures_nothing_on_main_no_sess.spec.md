# Copilot captures nothing on main — no SessionStart, UserPromptSubmit or PostToolUse

> **This specification was supplied with the card rather than written by THE SORCERER.**
> It was filed automatically from a defect in a release’s verification round (`integrate:copilot_captures_nothing_on_main_no_sess`), and reproduces that defect’s write-up. It is reproduced below exactly as it was given, and no hero has
> reviewed, expanded or corrected it.

Filed from the release "AI TC copilot plugin" (cd_mu5m4ugj6vs) after integration.
THE CAPTAIN could not complete the integration because: the release's stated intent is unmet; Copilot enforces on tool calls but records no session, prompt or tool result.
Attributed to member "GitHub Copilot: cover the CLI, VS Code agent mode, and the cloud coding agent" (cd_mu3ykpbj1io). the hooks exist only on that member's branch, on a superseded base.

Issue: Copilot captures nothing on main — no SessionStart, UserPromptSubmit or PostToolUse

card: `cd_mu3ykpbj1io` — the hooks exist only on that member's branch, on a superseded base.
blocking: the release's stated intent is unmet; Copilot enforces on tool calls but records no session, prompt or tool result.

`main`'s Copilot adapter registers **one** event, `preToolUse`. It therefore blocks and
redacts tool calls and does nothing else: no session root is opened, no prompt is captured,
no tool result is scanned. Everything the dashboard reads for other harnesses — sessions,
prompts, responses — is empty for Copilot.

The missing pieces are written and exist on branch
`devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io`: `src/hooks/session-start.ts`,
`session-start-payload.ts`, `user-prompt-submit.ts`, `user-prompt-payload.ts`,
`post-tool-use.ts`, `tool-response.ts` and `scan-response.ts`, with 7 matching test files,
plus `packages/plugin-sdk/src/provider-copilot.ts` (which answers `'unknown'`
unconditionally, reads no environment, and so adds no row to CLAUDE.md §3's opt-out table).

They cannot be cherry-picked. They are written against that branch's own `shared.ts`,
`dialect.ts` and `pre-tool-use-decision.ts`, all three of which differ substantially from
`main`'s. Porting them means rewriting each against `main`'s contracts — its two-channel
decision shape, its single-casing event registration, and its `${PLUGIN_ROOT}` install
convention — and registering each new event **once**, in camelCase only, for the reason
commit `801cc2c6` gives. A VS Code entry belongs in the file that host reads, not in
`plugins/copilot/hooks.json`.

Two constraints inherited from the member's journal that whoever picks this up should know
before starting. `PostToolUse` response scanning needs the host to deliver a tool result;
confirm against `test/fixtures/cli/README.md` which questions the vendor reference actually
settles before writing a parser. And session history/backfill — the member's steps E5 and F —
is blocked on a `~/.copilot/session-state/<uuid>/events.jsonl` fixture that no one has been
able to capture, because it needs a live Copilot CLI session; that part should stay out of
scope until a recording exists, since a parser written from documentation and tested against
a fixture written to match it proves nothing.
