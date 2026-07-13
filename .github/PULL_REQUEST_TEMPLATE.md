<!-- Thanks for contributing to AI Traffic Control! See CONTRIBUTING.md for the full guide. -->

## Summary

<!-- What does this PR change, and why? Keep the PR focused on one thing. -->

## Checklist

- [ ] `pnpm format:check` passes
- [ ] `pnpm lint` passes
- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` passes
- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`)

### Detection-rule changes only (`rules/`)

- [ ] Every added/changed rule ships **positive and negative fixtures** (a rule PR without fixtures will not pass CI)
- [ ] `manifest.json` version bumped for the changed pack
- [ ] Sample text in fixtures is fabricated — never real secrets or personal data
