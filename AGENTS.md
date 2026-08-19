# AGENTS.md — ai-tc

**The conventions live in [`CLAUDE.md`](CLAUDE.md). Read that first, every session.**

This repo inverts the usual layout. Elsewhere in the org `AGENTS.md` carries the substance and
`CLAUDE.md`/`GEMINI.md` point at it; here `CLAUDE.md` is canonical, because it is referenced by
name from ESLint rule messages, test assertions, and `CONTRIBUTING.md` — including section
citations like "CLAUDE.md §4". Renaming it would break those references, so it stays put and this
file points at it.

`CLAUDE.md` is not optional background: the conventions in it are enforced by ESLint and CI, so code
that violates them fails to merge. In particular the no-network rule, the package-dependency and
Drizzle walls, and the fail-open requirement for plugin hooks are all machine-checked.

@./CLAUDE.md
