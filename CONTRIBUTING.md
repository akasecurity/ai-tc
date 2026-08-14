# Contributing to AI Traffic Control

Thanks for your interest in contributing to `ai-tc`. This guide covers how to get
set up, the conventions we enforce, and how to contribute detection rules.

## Getting started

```bash
pnpm setup                 # install deps + git hooks
pnpm test                  # run the test suite
pnpm typecheck && pnpm lint
pnpm bench                 # benchmarks — advisory, never a merge gate
```

Requires Node.js 24+ and pnpm. The core product is local-first — it runs on Node
and SQLite with no other services.

`pnpm bench` is not part of the checks above and does not need to pass before you open a
PR — it records a performance **trend**, which a nightly job on `main` collects as a
workflow artifact. Nothing here gates a merge on wall-clock: CI runners are too noisy for
that, and a timing check that fails for reasons unrelated to your diff is one everyone
learns to re-run until it goes green. Performance limits that genuinely must hold are
written as ordinary tests with generous upper bounds, and those do run in `pnpm test`.

## Conventions (enforced by CI)

- **TypeScript strict mode, ESM everywhere.** Types come from `@akasecurity/schema`
  — reuse them rather than redefining local shapes.
- **Conventional Commits** (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`)
  — checked by commitlint.
- **Formatting** via Prettier and **lint** via ESLint (`pnpm lint`, `pnpm format:check`).
  Everything is `error`, nothing `warn`.
- **Package boundaries** — no forbidden imports across package walls (see the
  dependency rules in `CLAUDE.md`).

### Comment style

Comments explain **what** a piece of code does and any non-obvious local mechanics
— not the history of _why a decision was made_. Keep them short and local; link to a
doc rather than narrating a decision inline. This repository is public, so keep
comments factual and reader-facing — no internal narration.

## Dependency advisories and waivers

Two security workflows run alongside the main build:

- **Dependency audit** (`.github/workflows/audit.yml`, gate logic in
  `tools/audit-gate`) — two audits on every PR and daily against `main`. The
  **workspace audit** runs `pnpm audit` over the workspace lockfile. The **artifact
  audit** runs `npm audit` over the resolution an end user gets from installing the
  published `@akasecurity/cli`: it resolves the CLI's runtime `dependencies` with npm
  in a temp dir, so advisories reachable only through the published ranges (e.g.
  next's own pins) are caught too. In both, any **high or critical** advisory fails
  the check; moderate and below are listed in the run summary but do not block. A
  failing daily run opens (or updates) an issue labeled `security-advisory`, so an
  advisory published between merges is surfaced without waiting for the next PR — and
  it only adds a comment when a **new** advisory id appears, so a known long-lived
  finding does not ping daily.
- **CodeQL** (`.github/workflows/codeql.yml`) — static analysis of the TypeScript
  workspace and the workflow files on every PR (including a PR stacked on another
  branch) and weekly; findings appear under the repository's **Security** tab.

When the workspace audit fails, fix first: upgrade the dependency, or raise its floor
via `pnpm.overrides` in the root `package.json` (the existing entries there are exactly
such floors). Note that overrides cover the **workspace lockfile only**; end-user
installs of the published packages resolve the published dependency ranges, which
overrides do not reach — that consumer-side exposure is what the artifact audit gates.
When the **artifact audit** fails, the fix is raising the affected range in
`cli/package.json` `dependencies` so a fresh `npm install` resolves a patched release;
a copy nested under another package (npm keeps e.g. next's exact pins under
`node_modules/next/node_modules/`) can only be fixed by bumping that package once
upstream raises its own pin. Only when an advisory has **no fixed release** reachable
from our dependency tree, add a waiver to `.github/audit-waivers.json`:

```json
{
  "waivers": [
    {
      "advisory": "GHSA-xxxx-xxxx-xxxx",
      "scope": "workspace",
      "module": "left-pad",
      "reason": "Why this is unfixable today and why the exposure is acceptable.",
      "expires": "2026-08-31"
    }
  ]
}
```

- `advisory` is the GHSA id (preferred) or a CVE id. The artifact audit (npm's v2
  report format) exposes only GHSA ids, so an artifact-scoped waiver must use the
  GHSA id.
- `scope` is **required**: `"workspace"` or `"artifact"`, naming the audit the waiver
  applies to. An advisory hitting both audits takes one entry per scope. Scoping keeps
  stale-waiver detection exact — each run judges only its own waivers.
- `module` is optional but recommended: it pins the waiver to one package name, so the
  same advisory id resurfacing through a different package is not silently suppressed.
- `expires` is **required** — keep it short (about 30 days). The date is **inclusive**
  and compared in UTC: a waiver dated `2026-08-31` still suppresses on the 31st and
  lapses at UTC midnight after it. A lapsed waiver stops suppressing automatically, so
  the advisory fails CI again and forces a fresh look for a fix. Waivers that no longer
  match anything are flagged as stale in the audit report; remove them.
- `class` is an optional annotation for the rare advisory that is a **false positive**
  (for example the registry matching a workspace importer name against an unrelated
  public package). Set `"class": "false-positive"`, say so plainly in `reason`, and a
  longer expiry is acceptable there.
- **Anyone may open a waiver PR; only a maintainer may approve one.** A waiver is a
  decision to ship a known advisory, so it needs the same approval as any other change
  to `main` — which branch protection already requires. Say in the PR description what
  you tried before reaching for it.
- `auditConfig.ignoreCves` / `ignoreGhsas` is **not** an approved suppression route:
  pnpm-native ignores carry no expiry, no reason, and no report row. The gate refuses
  to run — exit 3, the same code as a malformed waiver file — when `auditConfig` is set
  in **either** place pnpm reads it from: the root `package.json` (`pnpm.auditConfig`)
  or `pnpm-workspace.yaml` (top-level `auditConfig`). It is read off disk rather than
  detected in pnpm's output, because pnpm removes a muted advisory from `advisories`,
  decrements the severity counts to match and leaves `muted` **empty** — so a muted run
  is indistinguishable from a clean one by its result alone.

## Contributing detection rules

Detection rules live in [`rules/`](rules/). Every rule ships with **at least 2 positive
and 2 negative fixtures**; a rule PR below that bar will not pass CI. See
`skills/write-detection-rule/SKILL.md` for the format.

Rules merged here are published as **first-party, verified** packs, so rule PRs get
extra review — please make matchers precise and include realistic negative fixtures
so we don't ship false positives.

## Pull requests

1. Fork and branch from `main`.
2. Keep PRs focused; write a clear description.
3. Ensure `pnpm typecheck`, `pnpm lint`, `pnpm test`, and `pnpm format:check` pass.
4. Be responsive to review feedback.

### Checks that gate `main`

Merging to `main` needs an approving review and these status checks. The names are the
job names GitHub reports, and they are what branch protection matches on — **a renamed
job silently stops being required**, because protection keeps waiting for a check name
nothing produces any more. So renaming a job here means updating this table in the same
PR; `packages/eslint-config/test/required-checks.test.js` reads this table and fails when
a name in it no longer belongs to a real job.

| Check                                     | Workflow     |
| ----------------------------------------- | ------------ |
| `Lint · Typecheck · Test · Build`         | `ci.yml`     |
| `No-network · Full suite, egress blocked` | `ci.yml`     |
| `macOS · Full suite`                      | `ci.yml`     |
| `Windows · Unit tests (shipped surface)`  | `ci.yml`     |
| `Windows · Lint`                          | `ci.yml`     |
| `Dependency audit`                        | `audit.yml`  |
| `CodeQL (javascript-typescript)`          | `codeql.yml` |
| `CodeQL (actions)`                        | `codeql.yml` |

Whether each is _actually_ enforced lives in repository settings, not in this tree, so
this table cannot assert it — but the state is readable without admin, which is worth
knowing since the branch-protection REST endpoint 404s to non-admins and reads like
"no protection at all":

```bash
gh api graphql -f query='{repository(owner:"akasecurity",name:"ai-tc"){pullRequest(number:PR){commits(last:1){nodes{commit{statusCheckRollup{contexts(first:50){nodes{... on CheckRun{name isRequired(pullRequestNumber:PR)}}}}}}}}}}'
```

**Measured 2026-08-12: only two of the eight are actually required** —
`Lint · Typecheck · Test · Build` and `Windows · Unit tests (shipped surface)`. The other
six run on every PR and block nothing. Two of those six are asserted as enforced
elsewhere in this repository: CLAUDE.md presents `No-network · Full suite, egress blocked`
as one of the three gates gating the no-network guarantee, and describes `Dependency
audit` as the reason a high or critical advisory "will not merge". Neither holds until an
admin marks them required — a PR that reaches the network on a shell-out, or that carries
a critical advisory, goes red there and stays mergeable.

This paragraph is a hand-recorded observation, not something the tree derives, so it goes
stale in the safe direction only until someone fixes the setting. Re-run the query above
rather than trusting it.

### Branch freshness

A `pull_request` check does not run against your branch. It runs against a merge commit
GitHub builds by merging your branch into `main` — and GitHub rebuilds that commit when
the **branch** is pushed, never when `main` moves. A branch that has sat for a few hours
is therefore checked against a `main` that no longer exists, and its green tick describes
a tree nobody will ever merge.

For most changes that is harmless, because two diffs touching different files compose. It
stops being harmless for the guards here that **derive** their expectations from the tree
at run time instead of carrying a hardcoded list. Several do, and the list below is
illustrative rather than complete — `packages/eslint-config/test/` enumerates workspace
packages, lintable non-package files and inline disables straight out of `git ls-files`;
`tools/portability-gate` scans the tracked test and bench trees; and the fixture bar in
`packages/detections/test/engine.test.ts` fails at collection time when a rule ships
without fixtures. Deriving is precisely what makes those guards worth having — a pinned
list stays green through the drift they exist to catch — and it is also what makes them
read a base that has moved.

So: add a workspace package on one branch, and on another add a file that the package
guard would judge. Neither diff contains the mismatch. Both PRs go green, both merge, and
the first run that ever sees both trees is the post-merge run on `main`. Review cannot
catch it, because there is nothing in either diff to review.

Two repository settings close it, and they are settings — nothing in this tree can
enforce either:

| Mechanism                                               | What it does                                                                                                                                                       |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Merge queue** on `main`                               | Tests each entry against `main`'s tip plus everything queued ahead of it, then merges only what passed that exact tree. Contributors never update a branch by hand |
| Branch protection's _Require branches to be up to date_ | Blocks the merge button until the branch has been updated, so the checks re-run against the current `main`. Every merge invalidates every other open PR            |

**Mechanism in use: merge queue.**

Chosen for the merge rate here: with several PRs landing on a busy day, the up-to-date
setting turns every merge into an update-and-re-run for each remaining open PR, while the
queue does that work with nobody in the loop.

Two consequences follow for `.github/workflows/`, and
`packages/eslint-config/test/required-checks.test.js` holds both against this section. It
applies them to every **gating** workflow — one that runs both on `pull_request` and on a
push to `main` — rather than to the workflows named in the required-check table above. The
table lists more checks than are actually required, so it is neither the enforced set nor
a superset of the workflows a queue affects; `internal-path-guard.yml` is absent from it
and is the workflow where being skipped leaks an internal path into a public repository
rather than merely losing a verdict.

- **A gating workflow triggers on `merge_group`.** The queue reaches a workflow through
  that event and no other. A required check missing it does not fail in the queue — it
  never reports at all, so the entry waits on it indefinitely instead of being rejected.
  That is a wedged queue rather than a degraded one. A guard that is not required but is
  meant to gate has the worse failure: the queue merges a tree it never inspected.
- **A `push` or `merge_group` run is never cancelled or queued by a later one.** These
  workflows used to key their concurrency group on `github.ref`, which every push to
  `main` shares, so a merge landing a couple of minutes behind another cancelled the
  earlier commit's run outright — leaving that commit with no verdict, and making the
  first red run on `main` carry a SHA whose own change was not the cause. Switching
  cancelling off is only half of it: with the group still keyed on the ref the second run
  is queued rather than dropped, and waits out the first in full. Non-PR events are keyed
  by `github.sha` instead, so each merged commit gets a group of its own — and by the
  event name too, since the queue advances `main` to the merge-group commit and so the
  `merge_group` run and the `push` that follows it carry the same SHA.

Enabling the queue also multiplies the work each change costs: a queued entry re-runs
every gating workflow against the queued tree, on top of the `pull_request` run and the
post-merge `push` run. CodeQL is the one to watch, since it is two matrix legs with a
45-minute budget each and sits on the critical path of every merge.

Turning the queue on needs repository-admin rights and cannot be done from a PR. It is
also only as strong as the set of checks that are actually required — the measured gap
noted above — since the queue merges an entry once the required checks pass, and a check
that is not required is not one of them. Enabling it while only two of the eight are
required buys the freshness guarantee for those two and nothing else. Raising that set is
tracked separately.

To verify the setting once an admin has made it, from any account:

```bash
gh api graphql -f query='{repository(owner:"akasecurity",name:"ai-tc"){mergeQueue{id}}}'
```

By contributing you agree that your contributions are licensed under the
repository's [LICENSE](LICENSE). Please also read our
[Code of Conduct](CODE_OF_CONDUCT.md).
