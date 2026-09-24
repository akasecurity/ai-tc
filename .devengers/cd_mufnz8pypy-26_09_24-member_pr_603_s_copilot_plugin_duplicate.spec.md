# Member PR #603's Copilot plugin duplicates PR #558 and cannot be merged

> **This specification was supplied with the card rather than written by THE SORCERER.**
> It was filed automatically from a defect in a release’s verification round (`integrate:member_pr_603_s_copilot_plugin_duplicate`), and reproduces that defect’s write-up. It is reproduced below exactly as it was given, and no hero has
> reviewed, expanded or corrected it.

Filed from the release "AI TC copilot plugin" (cd_mu5m4ugj6vs) after integration.
THE CAPTAIN could not complete the integration because: the release's only member cannot go in, so there is no release candidate at all.
Attributed to member "GitHub Copilot: cover the CLI, VS Code agent mode, and the cloud coding agent" (cd_mu3ykpbj1io). the member is the duplicate; PR #558 landed the same package first.

Issue: Member PR #603's Copilot plugin duplicates PR #558 and cannot be merged

card: `cd_mu3ykpbj1io` — the member is the duplicate; PR #558 landed the same package first.
blocking: the release's only member cannot go in, so there is no release candidate at all.

`plugins/copilot/` exists twice. It reached `main` on 2026-09-16 via PR #558
(`feat/copilot-plugin-scaffold`, merge `aa4381d1`), and branch
`devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io` (PR #603) builds
the same package independently from merge base `271d32c1`, which predates all 7 of `main`'s
copilot commits.

Merging the two gives 44 conflicts, 38 of them add/add under `plugins/copilot/`, and the two
trees differ by 4237 insertions / 3522 deletions across 57 files. This is not a conflict that
wants careful resolution — there is no third tree that is the merge of both. It is a choice
between two implementations, and resolving it file by file inside a merge commit would bury
that choice where no reviewer would find it.

`main`'s copy is the better-tested one on the surface they share: its
`pre-tool-use-decision.test.ts` is 472 lines against the member's 362, its
`fail-open-wrapper.test.ts` 471 against 324, its `hook-output-shapes.test.ts` 318 against
187, and it has 5 test files the member lacks (`present.test.ts`, `hooks/shared.test.ts`,
`exception-guidance.test.ts`, `setup-frame-json.test.ts`, `setup-show.test.ts`). It also
carries two corrections made _after_ the member's base, both of which the member's side would
revert:

- `801cc2c6` — registers the camelCase event **alone**. The member registers both casings of
  all 5 events (9 entries), which the vendor reference resolves as **two hook spawns per tool
  call**, the second carrying a payload the snake_case field table cannot read.
- `ac9330a5` — splits the CLI's warn onto **stderr**, because `systemMessage` is not one of
  the three `preToolUse` output fields the CLI documents and a notice put on stdout there is
  silently dropped. The member has no such channel.

The member also resolves its hook commands through
`${AKA_COPILOT_ROOT:-$HOME/.copilot/plugins/aka-copilot}` where `main` uses the
host-provided `${PLUGIN_ROOT}` — a different installation contract that nothing has decided
between.

What resolves this: retire PR #603 as superseded, keeping its branch until the card below is
done, since that branch is the only place the work in it exists. Do not attempt the merge
again; it will produce the same 44 conflicts and the same choice.
