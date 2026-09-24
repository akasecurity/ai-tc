---
card: cd_mufnz8pypy
title: Member PR #603's Copilot plugin duplicates PR #558 and cannot be merged
stage: plan
created: 2026-09-24
---

> **Read this first.** This card lands **no product change**. Its whole output is a
> retirement decision, recorded where the next person to touch `plugins/copilot/` will
> trip over it. If you find yourself editing a file under `plugins/copilot/`,
> `packages/`, `web-ui/` or `cli/`, you have left the card. Stop and re-read
> `## Implementation strategy`.

## Premise check — re-derived, not trusted

Every claim the specification makes was re-measured against the fetched refs before this
plan was written. Results, so THE MECHANIC does not have to pay for them again:

| Claim | Re-derived | Verdict |
| --- | --- | --- |
| PR #603 is open and unmergeable | `state: OPEN`, `mergeable: CONFLICTING`, base `main` | confirmed |
| PR #558 landed the package | `state: MERGED`, merge commit `aa4381d1`, `mergedAt 2026-09-18T19:56:26Z` | confirmed, **date corrected** — the spec says 2026-09-16; that is the branch's commit dates, not the merge |
| Member head | `372e6526` (`docs(copilot): record where this implementation attempt stopped`) | confirmed |
| Member merge base | `271d32c1` | confirmed |
| Member is 16 commits ahead of `main` | `git rev-list --count origin/main..<member>` → 16 | confirmed |
| 44 conflicts | `git merge-tree --write-tree --name-only` → **44** conflicted paths | confirmed |
| 38 of them under `plugins/copilot/` | re-derived count is **36** under the plugin, 8 outside | **discrepancy — record it, do not repeat the 38** |
| `main` uses `${PLUGIN_ROOT}`, member uses `${AKA_COPILOT_ROOT:-$HOME/.copilot/plugins/aka-copilot}` | `plugins/copilot/hooks.json` on both sides | confirmed. `main` = 1 entry, member = 9 entries over 5 events |

The 8 conflicts outside the plugin: `CLAUDE.md`, `pnpm-lock.yaml`, `test/vitest/coverage.ts`,
`packages/persistence/src/repositories/{inventory-assets,security}.ts`,
`packages/persistence/test/repositories/security.test.ts`,
`packages/schema/test/zod/inventory.test.ts`, and the member's own `.devengers/…plan.md`.

**`git merge-tree --write-tree` is the only sanctioned way to re-measure this.** It writes
no working tree, leaves no `MERGE_HEAD`, and needs no `--abort`. The specification says "do
not attempt the merge again"; that instruction is about `git merge`, and `merge-tree` is how
you honour it while still checking the numbers.

## Relevant existing architecture

Nothing here is a runtime subsystem — the surface this card touches is the repository's own
bookkeeping — but the decision being recorded is about real contracts, and the record is
worthless if it misnames them.

- **`plugins/copilot/` on `main`** — the package PR #558 landed. One hook entry
  (`preToolUse`), one emitted script plus `scan-worker`, 18 test files, registered in every
  cross-cutting gate: `COVERAGE_FLOORS` (`test/vitest/coverage.ts:125`, floor 83),
  `EXPECTED_WORKSPACE_PACKAGE_NAMES` and `EXPECTED_VITEST_PACKAGES`
  (`packages/eslint-config/test/{effective-config,no-network-runtime}.test.js`),
  `hook-timeout-ratchet.test.js`, `package-walls.test.js`, and `ci.yml`'s per-package test
  filter at line 907. It is `"private": true` on purpose, and
  `required-checks.test.js:919-937` pins that as **temporary** with the Windows leg's reason
  written beside it.
- **`plugins/copilot/hooks.json` on `main`** — `${PLUGIN_ROOT}`, camelCase event alone.
  CLAUDE.md's Copilot bullet is the rationale ("The two dialects are payload FORMATS, not
  hosts"); commit `801cc2c6` is the fix, `ac9330a5` the stderr-notice split. Both post-date
  the member's base and both would be reverted by taking the member's side.
- **The member branch** `devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io`
  @ `372e6526` — the only place 19 files exist. Manifest in `## The salvage manifest` below.
- **GitHub state that makes retirement safe** — `delete_branch_on_merge: false` on the
  repository (re-derived via `gh api`), and **no workflow in `.github/workflows/` deletes a
  ref**. Closing a PR therefore does not delete its branch; only a human clicking *Delete
  branch* in the closed-PR UI does.
- **Issue #411** ("GitHub Copilot: cover the CLI, VS Code agent mode, and the cloud coding
  agent"), open, under epic **#410**. This is the feature's durable tracking home and it
  survives PR #603's retirement — which is the single most important fact in this plan,
  because it is what stops "retired as superseded" reading as "abandoned".
- **The sibling card `cd_mufnz8q0q0`** ("Copilot captures nothing on main") — filed from the
  same integration, branch `devengers/copilot-captures-nothing-on-main-no-sessionstart-cd_mufnz8q0q0`
  carries only its spec. That card owns the **port**; this card owns the **retirement**.
  Keeping them apart is deliberate: one is a decision, the other is a week of work against
  `main`'s contracts.

## Existing patterns

Extend these; invent nothing.

- **`.devengers/<card>.<stage>.md` is the repository's record.** `spec` → `plan` →
  `implement`, all in that directory, all committed. That is the only in-tree home for a
  decision record here, and it is the one CLAUDE.md's "Documentation" rule tolerates —
  planning docs, decision records and roadmaps do **not** go anywhere else in this public
  tree. Do not create `docs/`, an ADR directory, or a note at the repo root.
- **A `.devengers/`-only diff is established precedent.** The release branch
  `devengers/release/ai-tc-copilot-plugin-cd_mu5m4ugj6vs` landed three commits
  (`294b68cf`, `e3ccc9da`, `2de9c675`) whose entire diff against `main` is one document, and
  said so explicitly under its own `## Release candidate`. This card's PR is the same shape.
  Nobody needs to be talked into it; point at that branch.
- **The integrate document's own structure** — `## Conflicts` / `## Not integrated` /
  `## Blocking`, each enumerating rather than asserting. The implement document this card
  produces mirrors it: measured numbers, named commits, named files.
- **Pushing under a refused pre-push gate.** This container runs **Node v22.23.2** against
  the repo's `engines: >=24`, so lefthook's `pre-push` (`pnpm lint`) is refused before ESLint
  starts. Commit `2de9c675` is the precedent: push with `--no-verify` **and record in the
  implement document that the gate did not run**. Recording it is the pattern, not the
  `--no-verify`.
- **`gh` is present and authenticated** (v2.97.0, account `aka-auto` via `GITHUB_TOKEN`). Use
  it. Do not read a token out of the environment and do not put one in a remote URL.

## Implementation strategy

Retire PR #603 as superseded, and make the retirement **findable from every direction someone
might approach it from**. That is the whole job, and the reason it is not a one-line `gh pr
close` is that a closed PR with no comment is indistinguishable from an abandoned one — the
next CAPTAIN re-measures the same 44 conflicts and makes the same choice again, which is
exactly what the specification forbids.

Four surfaces carry the record, and they are chosen because they are the four places someone
lands:

1. **PR #603 itself** — closed, labelled `duplicate`, with a comment that names #558 as the
   landing PR, states the three contradictions by commit, carries the salvage manifest, names
   issue #411 as where the work continues, and says in as many words: *do not re-attempt this
   merge; `git merge-tree` reproduces the same 44 paths without touching a working tree.*
2. **Issue #411** — a comment linking the retirement, so the feature's tracking home records
   why its PR closed unmerged and where the remaining 16 files live.
3. **The member branch** — preserved, and preserved by something a stray click cannot undo
   (task 6). A branch is one button away from deletion in the closed-PR UI, and the
   specification's own sentence is "that branch is the only place the work in it exists".
4. **`.devengers/cd_mufnz8pypy-…implement.md`** — the in-tree record, and the only file this
   card writes to the repository.

**What this card deliberately does not do**, each with its reason:

- **It does not merge, rebase, cherry-pick or `git merge` anything.** Re-measure with
  `merge-tree` only.
- **It does not port the member's hooks.** That is card `cd_mufnz8q0q0` / issue #411. Porting
  needs each module rewritten against `main`'s two-channel decision shape, its single-casing
  registration and its `${PLUGIN_ROOT}` convention — a code change with its own test surface,
  and mixing it into a retirement buries the decision inside a large diff, which is the
  failure mode the specification names in its third paragraph.
- **It does not decide the install-root contract.** `${PLUGIN_ROOT}` is what `main` ships and
  therefore what is in force; whether it is *right* is undecided, and deciding it here would
  be a product call made inside a bookkeeping PR. **Record it as an open question on #411**
  and move on.
- **It does not delete the member branch, and does not ask anyone to.** The branch stays until
  #411's port has landed the 16 files.
- **It does not touch the release's `.integrate.md`.** That is card `cd_mu5m4ugj6vs`'s
  document. Reaching into another card's record to tick its box is how two records start
  disagreeing.

### The salvage manifest

19 paths exist only on `372e6526`. This is the list, and it is the payload of the retirement
comment — because the moment PR #603 is closed, this list is the only thing standing between
that work and somebody concluding it was thrown away.

**16 claimed by card `cd_mufnz8q0q0` / issue #411** (7 hook modules, 7 tests, the provider and
its test):

```
plugins/copilot/src/hooks/session-start.ts
plugins/copilot/src/hooks/session-start-payload.ts
plugins/copilot/src/hooks/user-prompt-submit.ts
plugins/copilot/src/hooks/user-prompt-payload.ts
plugins/copilot/src/hooks/post-tool-use.ts
plugins/copilot/src/hooks/tool-response.ts
plugins/copilot/src/hooks/scan-response.ts
plugins/copilot/test/hooks/session-start-order.test.ts
plugins/copilot/test/hooks/session-start-payload.test.ts
plugins/copilot/test/hooks/user-prompt-payload.test.ts
plugins/copilot/test/hooks/tool-response.test.ts
plugins/copilot/test/hooks/scan-response.test.ts
plugins/copilot/test/hooks/permission-request.test.ts
plugins/copilot/test/e2e/scan-worker-bundle.e2e.test.ts
packages/plugin-sdk/src/provider-copilot.ts
packages/plugin-sdk/test/provider-copilot.test.ts
```

**3 claimed by nobody** — the member's own journal, which is where the reasoning behind all 16
lives, including the two decisions the implement document says the next attempt inherits:

```
.devengers/cd_mu3ykpbj1io-26_09_16-github_copilot_cover_the_cli_vs_code_age.spec.md
.devengers/cd_mu3ykpbj1io-26_09_16-github_copilot_cover_the_cli_vs_code_age.plan.md
.devengers/cd_mu3ykpbj1io-26_09_16-github_copilot_cover_the_cli_vs_code_age.implement.md
```

**One item in that manifest is mis-filed and should be flagged on #411 rather than silently
carried.** `plugins/copilot/test/e2e/scan-worker-bundle.e2e.test.ts` is not a capture-hook
test. `main` already emits `scan-worker` from `plugins/copilot/tsup.config.ts` and **nothing
on `main` pins it** — CLAUDE.md §5 is explicit that a worker URL resolved against a source
path "works in the repo and under vitest and fails only once installed", and names the
claude-code sibling of exactly this file as what pins it. So `main` carries a live §5 property
with no guard, today, independent of whether the capture hooks are ever ported. Say that on
#411 so it is not lost when the port gets scoped to hooks. **Do not implement it here** — a
new e2e test in a retirement PR is scope creep, and it belongs to the package's own gate
story.

For symmetry, the five test files `main` has that the member does not — `present.test.ts`,
`hooks/shared.test.ts`, `exception-guidance.test.ts`, `setup-frame-json.test.ts`,
`setup-show.test.ts` — are named in the comment too. They are half the answer to "why `main`'s
side won", and a retirement that only lists what is being retired reads as a loss.

## File-level changes

**Created (one file — the only write to this repository):**

- `.devengers/cd_mufnz8pypy-26_09_24-member_pr_603_s_copilot_plugin_duplicate.implement.md`
  — the implement record. Mirrors the integrate document's shape: the re-derived premise
  table (including the 36-vs-38 correction and the 09-18-vs-09-16 correction), the salvage
  manifest, the four surfaces and what was written to each, the exact `gh` commands run with
  their output, the preserved-ref evidence, the `${PLUGIN_ROOT}` question recorded as open,
  and a note that the pre-push lint gate did not run and why.

**Modified: none. Deleted: none.**

Specifically **not** touched, and a diff naming any of them is a failed implementation:

- anything under `plugins/copilot/`
- `test/vitest/coverage.ts`, `CLAUDE.md`, `pnpm-lock.yaml`
- `packages/eslint-config/test/*.js`, `.github/workflows/*`
- `.devengers/cd_mu5m4ugj6vs-26_09_17-ai_tc_copilot_plugin.integrate.md` (another card's record)
- any file on the member branch

**Outside the repository tree** (GitHub state, no commit):

- PR #603 → `closed`, label `duplicate` added, retirement comment posted.
- Issue #411 → comment posted.
- A preservation ref for `372e6526` (task 6).

## Ordered implementation tasks

- [x] **1. Fetch and re-derive the premise table.** `git fetch origin --prune`, then re-run
      every row of `## Premise check` against the freshly fetched refs — `gh pr view 603`,
      `gh pr view 558`, `git rev-parse` / `rev-list` / `merge-base` on the member ref, and
      `git merge-tree --write-tree --name-only origin/main <member>` for the conflict count.
      Record the numbers you get, not the ones in this plan. If any row disagrees with this
      plan, **stop and report it** — a premise that moved between planning and execution is
      the one thing that can make retirement the wrong call.
- [x] **2. Confirm the branch cannot be deleted by automation.** Re-check
      `gh api repos/akasecurity/ai-tc --jq .delete_branch_on_merge` is `false`, and grep
      `.github/workflows/` for any ref deletion. Both were clean at plan time; re-confirm,
      because task 4 is irreversible from the UI's point of view and this is the check that
      makes it safe.
- [ ] **3. Draft the retirement comment.** One comment body, written to a scratch file (not
      committed), containing: PR #558 (`aa4381d1`) as the landing PR; the re-derived conflict
      count with the 36-vs-38 correction stated; the three contradictions by commit
      (`801cc2c6` event registration, `ac9330a5` the stderr notice channel, and the
      `${PLUGIN_ROOT}` vs `${AKA_COPILOT_ROOT:-…}` install contract, the last named as
      **undecided** rather than as a defect); the five test files `main` has that the member
      lacks; the full 19-path salvage manifest split 16/3; the member head SHA `372e6526`;
      issue #411 as where the work continues; and the sentence *do not re-attempt this merge —
      `git merge-tree --write-tree` reproduces the same conflict set without a working tree.*
- [ ] **4. Post the comment, label, and close PR #603 — in that order.**
      `gh pr comment 603 --body-file <scratch>`, then `gh pr edit 603 --add-label duplicate`,
      then `gh pr close 603` **without** `--delete-branch`. Order matters: a PR closed before
      its comment lands is, for however long the gap is, a silently abandoned PR — and that is
      the reading this whole card exists to prevent. `duplicate` already exists in the
      repository's label set; do not create a new label.
- [ ] **5. Comment on issue #411.** Name the retirement of #603, link it, restate the salvage
      manifest, and add the two items this card deliberately declines to decide: the install-root
      contract, and the unpinned `scan-worker` build entry described under `## The salvage
      manifest`. Do **not** close #411 — the feature is unshipped.
- [ ] **6. Preserve `372e6526` against a stray click.** Push an annotated tag,
      `git tag -a archive/pr-603-copilot-member-cd_mu3ykpbj1io 372e6526 -m "…" && git push
      origin archive/pr-603-copilot-member-cd_mu3ykpbj1io`. A tag is not offered for deletion
      by the closed-PR UI and is not reachable by the *Delete branch* button, which is the
      exact failure this guards. **Check first that the tag name is free**, and note in the
      implement document that this introduces a seventh tag prefix — it creates no GitHub
      Release (only the API does that) and matches no `bin-v*`/`cli-v*` glob any workflow
      reads, so `release-binaries.yml`'s `bin-latest` election is untouched. **If the operator
      vetoes a new ref namespace**, the fallback is a branch-protection ruleset on the member
      branch name; if that is also vetoed, record `372e6526` in the implement document and in
      the PR comment as the recovery point and say plainly that the branch is unprotected.
- [ ] **7. Write `.devengers/cd_mufnz8pypy-…implement.md`.** Sections as listed under
      `## File-level changes`. Paste the real `gh` output, not a summary of it. Include the
      premise corrections. State that this card lands no product change and why.
- [ ] **8. Prove the diff.** `git diff origin/main --name-only` must name **exactly one**
      file, this card's implement document (plus this plan, if it has not merged yet). Any
      other path is a failed implementation — revert it and re-run.
- [ ] **9. Commit and push.** `docs(copilot): retire PR #603 as superseded by #558` or
      similar Conventional Commit (commitlint runs on `commit-msg` and *will* reject a bare
      subject). The pre-push `pnpm lint` gate is refused by the Node 22 container against the
      `>=24` floor, so push with `--no-verify` **and record that the gate did not run** in the
      implement document, exactly as `2de9c675` did. Nothing in this diff is lintable source,
      which is what makes that tolerable here and would not make it tolerable for a code change.
- [ ] **10. Open this card's PR** against `main`, body naming: no product change, the closed
      #603, the preserved ref, and issue #411. Link it back from the #603 comment thread if
      the number was not known when task 4 ran.

## Dependencies

- **1 → everything.** Nothing is done on unverified refs. If task 1's numbers disagree with
  this plan, no later task runs until the disagreement is explained.
- **2 → 4.** Closing the PR is safe only once branch-deletion automation is ruled out. Reverse
  that order and the branch may be gone before anyone notices it mattered.
- **3 → 4.** The comment is written before the close, and posted before the close. See task 4.
- **6 → 4 is *not* required, but 6 → 10 is.** The tag may be pushed before or after the close;
  it must exist before this card's PR claims the work is preserved. Pushing it *before* task 4
  is the more paranoid ordering and costs nothing.
- **4, 5, 6 → 7.** The implement document records what actually happened, including real
  command output. It cannot be written first.
- **7 → 8 → 9 → 10.** Prove the diff before committing; commit before pushing; push before
  opening the PR.
- **This card does not block and is not blocked by `cd_mufnz8q0q0`.** They can run in
  parallel. But if the port lands *first*, task 3's manifest should say so rather than
  describing already-ported files as member-only.

## Risks

- **The branch gets deleted anyway.** GitHub offers *Delete branch* on every closed PR, one
  click, no confirmation beyond the click. `delete_branch_on_merge: false` does not cover it —
  that setting is about merges. This is the card's single largest risk and task 6 is the whole
  mitigation. Treat a vetoed task 6 as a material weakening and say so in the implement doc.
- **"Retired as superseded" gets read as "abandoned".** The 16 files are real work that the
  release's stated intent still depends on. Mitigation is tasks 3 and 5 — the manifest and the
  #411 link — and the reason the comment is posted *before* the close rather than after.
- **Somebody re-attempts the merge.** Exactly what the specification forbids, and the cost is
  a fresh 44-path conflict set and the same choice made again, possibly differently. Mitigation
  is the explicit sentence in task 3 plus naming `merge-tree` as the non-destructive way to
  re-check.
- **Scope creep into the port.** The member's work is sitting right there and it is tempting to
  "just bring across" one file. Every one of the 16 is written against the member's `shared.ts`,
  `dialect.ts` and `pre-tool-use-decision.ts`, all three of which differ substantially from
  `main`'s — the sibling spec says they cannot be cherry-picked, and it is correct. A partial
  port that compiles is worse than none, because the gates are per-package and a half-wired
  hook reads as a shipped one.
- **The 36-vs-38 discrepancy gets papered over.** Two prior documents say 38 under
  `plugins/copilot/`; `merge-tree` says 36. The difference is almost certainly the merge base
  the measurement was taken from, but *almost certainly* is not a finding. Record both numbers
  and the command that produced each. A record that quietly restates a number it did not
  measure is how the next reader gets a precise-looking figure nobody can reproduce.
- **A `.devengers/`-only PR reads as empty.** Reviewers scanning the diff see one markdown file
  and may bounce it. Mitigation: task 10's PR body leads with "no product change, by design"
  and points at `294b68cf`/`e3ccc9da`/`2de9c675` as the same shape.
- **`--no-verify` becomes a habit.** It is justified here *only* because the diff contains no
  lintable source. Write that reason down; a future flight that carries the flag onto a code
  change will cite this one.
- **Label or permission friction.** `gh pr edit --add-label` fails if the token lacks write on
  issues; `duplicate` exists but the account may not. If labelling fails, do not create labels
  and do not retry with a different name — record the failure in the implement doc and carry
  on. The comment is the load-bearing part; the label is convenience.
- **Issue #411 is the wrong home.** It is open, it is the feature's tracking issue, and epic
  #410 sits above it — but if the operator's process routes follow-ups elsewhere, task 5's
  target is wrong. Cheap to check, expensive to guess: confirm #411 is still open in task 1.

## Testing strategy

There is no product change, so there is no unit, integration or UI tier to run — and claiming
otherwise would be the same class of error as a benchmark wearing a test's name. What is
verifiable here is **state**, and each item below is a command with an expected answer.

- **The diff is what it claims.** `git diff origin/main --name-only` names only this card's
  `.devengers/` documents. This is task 8 and it is the one check that catches scope creep
  mechanically.
- **No source was touched.** `git diff origin/main --name-only -- plugins/ packages/ cli/
  web-ui/ tools/ .github/ test/` is empty.
- **The premise still holds at execution time.** Task 1's re-derivation *is* the regression
  test for this card: a spec whose numbers have moved is a spec that has to be re-read.
- **The preserved ref resolves.** `git rev-parse archive/pr-603-copilot-member-cd_mu3ykpbj1io^{commit}`
  → `372e6526`, and `git ls-remote origin refs/tags/archive/pr-603-copilot-member-cd_mu3ykpbj1io`
  is non-empty. Check the remote, not the local ref — a tag that never left the container
  preserves nothing.
- **The member branch still exists on the remote, after the close.**
  `git ls-remote --heads origin devengers/github-copilot-cover-the-cli-vs-code-agent-mode-cd_mu3ykpbj1io`
  is non-empty. Run this *after* task 4, not before; before, it proves nothing about what the
  close did.
- **The 19 member-only paths are all reachable from the preserved ref.** Loop the manifest
  through `git cat-file -e <ref>:<path>`. A manifest with a typo in it is a manifest that sends
  the port card looking for a file that is spelled differently — and that is discovered months
  later, by which point nobody remembers the branch.
- **The GitHub state is as intended.** `gh pr view 603 --json state,labels,comments` reports
  `CLOSED`, carries `duplicate`, and holds the retirement comment. `gh issue view 411 --json
  state` still reports `OPEN`.
- **Regression-sensitive behaviour on `main`: none, and that is assertable.** `main`'s
  `plugins/copilot` suite is untouched by this card — the integrate flight measured it at 18
  files / 274 tests green with 85.71% statements against a floor of 83. If you have a working
  Node 24 (this container does not), a confirmatory `vitest run` under `plugins/copilot` is
  cheap; if you do not, say so rather than reporting a run you did not take. **Nothing ran is
  not everything passed** — the integrate document's own words about this same member.

## Definition of done

- [ ] Every row of `## Premise check` re-derived against freshly fetched refs, with any
      movement reported rather than absorbed.
- [ ] PR #603 is `CLOSED`, unmerged, labelled `duplicate`, carrying a comment that names
      #558/`aa4381d1`, the three contradictions by commit, the re-derived conflict count with
      the 36-vs-38 correction stated, the full 19-path salvage manifest split 16/3, the member
      head `372e6526`, issue #411, and an explicit instruction not to re-attempt the merge.
- [ ] The member branch still exists on `origin`, verified *after* the close.
- [ ] `372e6526` is preserved by a pushed tag — or, if that was vetoed, the veto and the
      resulting unprotected state are recorded in plain words in the implement document.
- [ ] Issue #411 carries a comment linking the retirement, the manifest, and the two questions
      this card declined to decide (the install-root contract; the unpinned `scan-worker` build
      entry).
- [ ] Issue #411 is still **open**.
- [ ] `.devengers/cd_mufnz8pypy-26_09_24-member_pr_603_s_copilot_plugin_duplicate.implement.md`
      exists, carries real command output rather than summaries, records both conflict counts
      and both merge dates, states that no product change was made and why, and records that the
      pre-push lint gate did not run and why.
- [ ] `git diff origin/main --name-only` names only this card's `.devengers/` documents.
- [ ] No merge, rebase or cherry-pick was performed against the member branch; any
      re-measurement used `git merge-tree --write-tree`.
- [ ] The branch is pushed and this card's PR is open against `main`, its body stating up front
      that it carries no product change.
