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
