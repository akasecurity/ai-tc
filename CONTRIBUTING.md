# Contributing to AI Traffic Control

Thanks for your interest in contributing to `ai-tc`. This guide covers how to get
set up, the conventions we enforce, and how to contribute detection rules.

## Getting started

```bash
pnpm setup                 # install deps + git hooks
pnpm test                  # run the test suite
pnpm typecheck && pnpm lint
```

Requires Node.js 24+ and pnpm. The core product is local-first — it runs on Node
and SQLite with no other services.

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
  `tools/audit-gate`) — `pnpm audit` on every PR and daily against `main`. Any **high or
  critical** advisory fails the check; moderate and below are listed in the run summary
  but do not block. A failing daily run opens (or updates) an issue labeled
  `security-advisory`, so an advisory published between merges is surfaced without
  waiting for the next PR — and it only adds a comment when a **new** advisory id
  appears, so a known long-lived finding does not ping daily.
- **CodeQL** (`.github/workflows/codeql.yml`) — static analysis of the TypeScript
  workspace and the workflow files on every PR to `main` and weekly; findings appear
  under the repository's **Security** tab.

When the audit fails, fix first: upgrade the dependency, or raise its floor via
`pnpm.overrides` in the root `package.json` (the existing entries there are exactly such
floors). Note that overrides — and the audit itself — cover the **workspace lockfile**;
end-user installs of the published packages resolve the published dependency ranges,
which overrides do not reach. Only when an advisory has **no fixed release** reachable from our dependency
tree, add a waiver to `.github/audit-waivers.json`:

```json
{
  "waivers": [
    {
      "advisory": "GHSA-xxxx-xxxx-xxxx",
      "module": "left-pad",
      "reason": "Why this is unfixable today and why the exposure is acceptable.",
      "expires": "2026-08-31"
    }
  ]
}
```

- `advisory` is the GHSA id (preferred) or a CVE id.
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
- Waivers are reviewed like any other code change.
- `pnpm.auditConfig.ignoreCves` / `ignoreGhsas` is **not** an approved suppression
  route: pnpm-native ignores carry no expiry, no reason, and no report row, so the gate
  refuses to run while anything is muted.

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

By contributing you agree that your contributions are licensed under the
repository's [LICENSE](LICENSE). Please also read our
[Code of Conduct](CODE_OF_CONDUCT.md).
