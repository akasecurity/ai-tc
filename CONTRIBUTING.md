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

Detection rules live in [`rules/`](rules/). Every rule ships with **positive and
negative fixtures**; a rule PR without fixtures will not pass CI. See
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

By contributing you agree that your contributions are licensed under the
repository's [LICENSE](LICENSE). Please also read our
[Code of Conduct](CODE_OF_CONDUCT.md).
