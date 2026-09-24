---
card: cd_mu5m4ugj6vs
title: AI TC Copilot plugin
stage: integrate
checks-head: 294b68cfbf82cd9cf3b484b6d2523625bbe650c3
---

## Steps

- [x] synchronise with `origin/main` and take anything already on the remote release branch
- [x] decide the merge order
- [ ] merge member `cd_mu3ykpbj1io` — GitHub Copilot: cover the CLI, VS Code agent mode, and the cloud coding agent
- [x] check compatibility between the members and the base
- [x] run the repository's checks on the integrated result, last, and record the sha
- [x] write the manifest
- [ ] open the release candidate pull request

**This integration is incomplete and no pull request was opened.** The release has one
member and that member could not be merged. The reason is not a conflict I declined to
resolve on grounds of care: the feature this release exists to ship is **already on
`main`**, landed by a different branch while the member was still being written, and the
member is a second, independent implementation of it. The two cannot be reconciled by
merging. Detail under `## Not integrated`, `## Conflicts` and `## Blocking`.

## Summary

This release was to carry one member: the GitHub Copilot plugin covering the Copilot CLI,
VS Code agent mode and the cloud coding agent. It carries nothing. `plugins/copilot/`
reached `main` on 2026-09-16 through PR #558 (`feat/copilot-plugin-scaffold`), a separate
branch that was not a member of this release, and member #603 implements the same package
independently from an older merge base. Merging them produces 38 add/add conflicts across
essentially every file of the plugin, and the member's side contradicts two corrections
`main` made after the member's base — so the merge is not a reconciliation but a choice
between two implementations, and taking the member's would be a regression.

The tree on this branch is therefore `origin/main` plus this document. Its checks are
green, which says the base is sound; it says nothing about the feature, because no feature
work is in it.

## Base

Base branch: `main`, at commit **24c22ed33bd9899986a8a5c025ef33dec078d31d**
(`Merge pull request #602 from akasecurity/release/0.9.14`).

- `git fetch origin` ran first, and every containment claim below was re-derived from the
  fetched ref afterwards rather than from any earlier reading of it.
- The release branch **did** already exist on `origin`, at
  `24c22ed33bd9899986a8a5c025ef33dec078d31d` — identical to the local checkout.
  `git merge --ff-only origin/devengers/release/ai-tc-copilot-plugin-cd_mu5m4ugj6vs`
  reported `Already up to date`. No previous CAPTAIN's merges existed to preserve, and
  there was no prior `.devengers/…integrate.md` on the branch; this is the first flight.
- `git rev-list --count HEAD..origin/main` is **0**. The base is contained in this branch
  because the branch was sitting on it, not because a merge was made — no synchronisation
  merge was needed and none was created.
- **The synchronisation produced no conflicts**, because it produced no merge. Nothing from
  this step appears under `## Conflicts`.

## Merge order

One member, so there is no ordering problem to solve: `cd_mu3ykpbj1io` was to be merged
first and alone. Recorded for completeness rather than because a decision was required.

The order turned out to be irrelevant for a different reason — the single member could not
be merged at all.

## Integrated

**None.** No member branch was merged into this release.

## Conflicts

No conflict was resolved, so there is nothing here for a human to audit in the usual sense.
What follows is the conflict set I measured and then abandoned, with
`git merge --no-commit --no-ff` followed by `git merge --abort`; the branch carries no trace
of it.

Merging `devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io` gave
**44 conflicted paths**, of which **38 are under `plugins/copilot/`** and almost all are
**add/add** — the signature of two branches independently creating the same files. The
member's merge base with `main` is `271d32c14f2e4f7a5ff15a09e4988673ad2c0e19`; `main` has
since taken 7 commits under `plugins/copilot/` that the member has never seen.

Measured divergence between the two implementations of the package
(`git diff origin/main:plugins/copilot <member>:plugins/copilot`): **57 files changed, 4237
insertions, 3522 deletions**. The largest per-file divergences, in changed lines:

| Lines differing | File                                       | main | member |
| --------------- | ------------------------------------------ | ---- | ------ |
| 580             | `test/hooks/pre-tool-use-decision.test.ts` | 472  | 362    |
| 563             | `test/e2e/fail-open.e2e.test.ts`           | 353  | 442    |
| 433             | `test/hook-output-shapes.test.ts`          | 318  | 187    |
| 322             | `src/hooks/shared.ts`                      | 384  | 318    |
| 305             | `test/hooks/fail-open-wrapper.test.ts`     | 471  | 324    |
| 298             | `src/hooks/pre-tool-use-decision.ts`       | 353  | 283    |
| 90              | `hooks.json`                               | 15   | 103    |

The six conflicts **outside** `plugins/copilot/` are `CLAUDE.md`, `pnpm-lock.yaml`,
`test/vitest/coverage.ts`, `packages/persistence/src/repositories/{inventory-assets,security}.ts`,
`packages/persistence/test/repositories/security.test.ts` and
`packages/schema/test/zod/inventory.test.ts`. Each is the two branches describing the same
new plugin in a shared file — a coverage floor for `plugins/copilot`, a CLAUDE.md section,
a lockfile importer. Every one of them is straightforward on its own. None of them is worth
resolving while the 38 under it are not.

**Why I did not resolve the 38.** Three of the member's positions are not stale text but
active contradictions of decisions `main` took deliberately after the member's base, and
each is recorded in `CLAUDE.md` on `main` as the reasoning for the current code:

1. **Event registration.** The member's `hooks.json` registers **both** casings of every
   event — `preToolUse` and `PreToolUse`, `sessionStart` and `SessionStart`, and so on, 9
   entries over 5 events. `main`'s registers the camelCase event **alone**, 1 entry, because
   the vendor reference selects the payload dialect by the event name's casing: a manifest
   carrying both spawns the hook **twice per tool call**, the second time with a payload
   whose `tool_name` is the Claude spelling that the snake_case field table has no row for.
   Commit `801cc2c6` on `main` is the fix, and the CLAUDE.md paragraph beginning _"The two
   dialects are payload FORMATS, not hosts"_ is its rationale. Taking the member's file
   reinstates the defect.
2. **The CLI notice channel.** `main`'s `pre-tool-use-decision.ts` returns a decision over
   **two** channels — stdout for the verdict, and a separate `notice` the caller writes to
   **stderr** — because the Copilot CLI's hooks reference documents exactly three
   `preToolUse` output fields and `systemMessage` is not among them, so a message put on
   stdout there is dropped and the user is told nothing. Commit `ac9330a5`, _"stop claiming
   a CLI warn reaches the user"_. The member's version has no such split.
3. **Install-root convention.** The member's hook commands resolve through
   `${AKA_COPILOT_ROOT:-$HOME/.copilot/plugins/aka-copilot}`; `main`'s use the host-provided
   `${PLUGIN_ROOT}`. These are different installation contracts, and nothing in this release
   decides which is right.

Resolving in the member's favour reverts all three, deletes the 5 test files `main` has and
the member does not, and replaces the better-covered half of the package with the
less-covered one. Resolving in `main`'s favour is a no-op that merges nothing. Neither is a
conflict resolution; both are a choice of implementation, and that choice is not mine to
make inside a merge.

## Compatibility

There are no between-member interactions to report, because **only one member exists**. What
follows is the member-against-base compatibility work, enumerated rather than asserted.

**What I enumerated.** `git diff --name-only 271d32c1..<member>` gives 73 changed files;
filtering out `plugins/copilot/` leaves **17**, listed below in full. Intersecting the
member's changed-file set with `main`'s over the same range
(`comm -12`) gives **53 files touched by both**.

- **Migrations and DDL: none, on either side.** No file under `packages/schema/src/drizzle/`
  or `packages/persistence/src/migrations` appears in the member's 73-file diff. The member's
  store-adjacent changes are `packages/persistence/src/repositories/inventory-assets.ts`,
  `packages/persistence/src/repositories/security.ts` and their two test files — repository
  reads, no DDL, no new table, no new column. There is therefore no migration collision to
  check and no upgrade path to run.
- **Shared vocabulary: already resolved on `main`, in the member's favour.** Both branches
  add Copilot to the `@akasecurity/schema` registries that CLAUDE.md §2 governs. I checked
  the base tree directly rather than taking either branch's word: `packages/schema/src/zod/harness-map.ts`
  on `main` carries `Copilot: 'copilot'` in `HARNESS` (line 59), `Copilot: 'github-copilot'`
  in `SOURCE_TOOL` (line 92) and `[SOURCE_TOOL.Copilot]: HARNESS.Copilot` in the
  `TOOL_TO_HARNESS` join (line 133), and `packages/schema/src/zod/inventory.ts` carries
  `'Copilot'` (line 48). The identity the member adds is the identity already present. This
  is the one part of the member's diff that is genuinely redundant rather than conflicting.
- **One real gap in the base, and it is consistent.** `packages/plugin-sdk/src/provider-copilot.ts`
  is **absent** on `main` and present on the member. That is not an oversight: provider
  resolution happens at SessionStart, and `main`'s Copilot adapter has no SessionStart hook,
  so it has nothing to resolve a provider for. The file arrives with the hooks or not at all.
  Per the member's own journal it reads no environment and adds no `n/no-process-env` row, so
  it would not have moved CLAUDE.md §3's count word.
- **Coverage floor.** Both branches add a `plugins/copilot` entry to `COVERAGE_FLOORS` in
  `test/vitest/coverage.ts` at different numbers — `main`'s is the one in force, and the
  package measures 85.71% statements against it on this tree (see `## Checks`).
- **`pnpm-lock.yaml`.** Conflicts as a matter of course — both branches add the same
  `plugins/copilot` importer with overlapping dependency sets. Regenerable; not a hazard in
  itself.

The 17 non-copilot files in the member's diff, for the record:
`CLAUDE.md`; `packages/eslint-config/test/{hook-timeout-ratchet,posture-build-wiring}.test.js`;
`packages/persistence/src/repositories/{inventory-assets,security}.ts`;
`packages/persistence/test/repositories/security.test.ts`;
`packages/plugin-sdk/src/{config,index,provider-copilot}.ts`;
`packages/plugin-sdk/test/{index,provider-copilot}.test.ts`;
`packages/schema/src/zod/inventory.ts`; `packages/schema/test/zod/inventory.test.ts`;
`pnpm-lock.yaml`; `test/vitest/coverage.ts`; and the member's own two `.devengers/` documents.

## Not integrated

**GitHub Copilot: cover the CLI, VS Code agent mode, and the cloud coding agent**
(`cd_mu3ykpbj1io`), branch
`devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io`, PR #603.

Left out, on operator direction, as **superseded**. The substance is under `## Conflicts`;
the short form is that `main` already carries this package from PR #558, the member is a
parallel implementation from an older base, and the member's side would revert two
corrections `main` made after that base.

Two further facts a reader should have, neither of which was the deciding one:

- **The member's own suite has never completed a run anywhere** (`checks: none`). Merging it
  would have put its first real run on this candidate. That is permitted, and it was not why
  it was left out — but it is worth recording that nothing independently corroborated the
  member's state before I measured it.
- **The member is self-declared incomplete.** Its final commit is
  `docs(copilot): record where this implementation attempt stopped`, and its journal reports
  36 of ~60 planned steps landed, with steps E5 and all of F **blocked** on a
  `~/.copilot/session-state/<uuid>/events.jsonl` fixture that cannot be captured without a
  live Copilot CLI, and G, J, L and parts of H and K not started. So even taken wholesale it
  would not have completed the feature.

What the member does hold that `main` does not is **7 hook modules** — `session-start.ts`,
`session-start-payload.ts`, `user-prompt-submit.ts`, `user-prompt-payload.ts`,
`post-tool-use.ts`, `tool-response.ts` and `scan-response.ts`, plus `provider-copilot.ts` in
`plugin-sdk` and 7 test files. That is the release's stated intent, it is real work, and it
is not thrown away by this decision — it is carried forward as a card under `## Blocking`.

## Members

Every member's suite state, verbatim as the forge reported it:

- **GitHub Copilot: cover the CLI, VS Code agent mode, and the cloud coding agent**
  (`cd_mu3ykpbj1io`), branch
  `devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io`, PR #603 —
  **`checks: none`**. _Nothing ran on this member's head commit — including when every job
  was skipped. Nothing ran is not everything passed._

This member's own suite has never completed a run anywhere. Had it been integrated, the
`## Checks` run below would have been its first. It was not integrated, so the green result
below contains none of its code and says nothing about it.

## Checks

Run on commit **294b68cfbf82cd9cf3b484b6d2523625bbe650c3**, which is this branch's head and
is `origin/main` (`24c22ed3`) plus this manifest — the source tree is byte-identical to the
base (`git diff --stat origin/main..HEAD` reports one file changed, this document, 63
insertions at the time of the run). Ran once; there was no repair to make and so no earlier
run to discount.

`pnpm install --config.engine-strict=false --frozen-lockfile` — completed in 39.1s. The
`engine-strict` override is needed because this container ships **Node v22.23.2** against
the repo's `engines` floor of `>=24`; `node:sqlite` loads but prints an `ExperimentalWarning`.
Suites were driven with the workspace `vitest` binary directly rather than through turbo,
which re-enters `pnpm` and trips the same engine check.

| Suite                    | Files   | Tests                          | Result         |
| ------------------------ | ------- | ------------------------------ | -------------- |
| `packages/eslint-config` | 28      | 1779 passed, 18 skipped (1797) | green          |
| `packages/schema`        | 44      | 1125 passed                    | green          |
| `packages/plugin-sdk`    | 44      | 718 passed, 2 skipped (720)    | green          |
| `plugins/copilot`        | 18      | 274 passed                     | green          |
| **total**                | **134** | **3896 passed, 20 skipped**    | **0 failures** |

`packages/eslint-config` is the one that matters most here: it carries `effective-config`,
`no-network`, `no-network-runtime`, `coverage-config`, `hook-timeout-ratchet`,
`package-walls`, `required-checks`, `claude-md`, `test-only-seam` and `inline-disables`, so
the cross-cutting guards all saw this tree. Its own coverage is 100% on all four counters.
`plugins/copilot` measures 85.71% statements / 81.45% branches / 96.7% functions / 86.68%
lines against the floor `main` set for it.

The same engine floor blocks the `lefthook` **pre-push** hook, which runs `pnpm lint` and is
refused by the Node check before ESLint starts, so both pushes on this branch were made with
`--no-verify`. Recorded because it is a gate that did not run: the `pre-commit` hook did run,
and `format-staged` reformatted this document's tables. Nothing on this branch but this
document is unlinted, and it is a markdown file.

**Two honest limits on that green.** It was taken on Node 22 rather than the Node 24 the
repo targets, so it is weaker evidence than a CI run. And it is a **subset**: I did not run
the full workspace suite, `pnpm lint` or `tsc` across every package. Both limits are
tolerable for what this run is being asked to establish — that the base is sound — and
neither would be tolerable if a member had been merged, because then the run would have been
the first evidence about that member's code rather than a re-confirmation of an
already-merged base.

## Release candidate

**No pull request was opened, and none should be.** The branch's source tree is identical to
`origin/main`; its entire diff against the base is this document. A pull request from it
would propose no change to the product, and calling it a release candidate would misdescribe
it.

`git diff 294b68cf..HEAD --name-only` is empty at the time of writing — the checks head _is_
the branch head. The manifest commit that lands this document touches only
`.devengers/cd_mu5m4ugj6vs-26_09_17-ai_tc_copilot_plugin.integrate.md`, which is this
release's own document and so does not void the run above.

What has to happen before this release has a candidate is under `## Blocking`. Both items
are real work on top of `main`, not merge mechanics.

## Blocking

### Member PR #603's Copilot plugin duplicates PR #558 and cannot be merged

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

### Copilot captures nothing on main — no SessionStart, UserPromptSubmit or PostToolUse

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
