# Skill: write-detection-rule

This skill teaches Claude Code how to write detection rules for the AI Traffic Control rule engine. Read this before creating or modifying anything in `rules/`. The full rule schema is `Rule` in `packages/schema/src/zod/rule.ts` — it is the source of truth for every field below.

## Rule file format (specVersion 1)

Every rule is a JSON file named `<rule-name>.json` inside a pack directory:

```json
{
  "specVersion": 1,
  "id": "<pack-id>/<rule-name>",
  "name": "Human-readable name",
  "category": "pii|financial|secret|phi|code_context|code_flaw|custom|config",
  "severity": "critical|high|medium|low",
  "matcher": { ... },
  "postValidators": ["luhn"],
  "examples": ["example matching string"]
}
```

### Matcher types

**keyword** — fast literal or phrase match, good for high-recall low-precision terms:

```json
{ "type": "keyword", "keywords": ["password", "secret", "api_key"], "caseSensitive": false }
```

**regex** — pattern match with optional capture group:

```json
{ "type": "regex", "pattern": "\\bAKIA[A-Z0-9]{16}\\b", "flags": "g" }
```

`captureGroup` (integer) extracts a subgroup as the matching span.

### Optional gating fields

**appliesTo** — language/file scoping: `{ "appliesTo": { "extensions": [".py", ".ts"] } }`.
When present, the rule only runs against text whose file extension is listed — and still
runs when there is no file context at all (live prompt/response hooks).

**requiresNearby** — co-occurrence gate: a match is kept only if corroborated by another
match (by `categories` or `ruleIds`) or by one of `labels` appearing within `windowChars`
of its span. Use it to suppress context-free false positives.

### Post-validators

A post-validator is a checksum or heuristic (not a standalone matcher, used via `postValidators`). Each runs against the matched span (or `captureGroup` if set) and must pass for the match to become a finding. Reference one as a bare name, or as `{ "name": ..., "config": { ... } }` for per-rule tuning.

The engine (`packages/detections/src/engine.ts`) implements exactly two:

- `luhn` — credit/debit card number check digit
- `entropy` — Shannon entropy >= 3.5 over a run of 20+ characters (distinguishes random secrets from low-entropy words; pair it with a `captureGroup` so entropy is measured on the token, not surrounding context). Config: `threshold`, `minLength`.

**Do not reference any other validator name.** Unknown names are silently ignored — the rule still fires, but the missing validator is a no-op, so the false-positive guard you thought you added does nothing.

## Pack structure

```
rules/<pack-id>/
  manifest.json         # required: { specVersion, id, name, version, rules: ["name1", ...] }
  <rule-name>.json      # one file per rule listed in manifest.rules
  fixtures/
    <rule-name>.json    # REQUIRED: array of { label, text, shouldMatch: bool }
```

**A rule without fixtures will be rejected by CI.**

## Fixture requirements

Every rule must have labeled **positive** fixtures (where `shouldMatch: true`) and **negative** fixtures (where `shouldMatch: false`). Aim for at least 2 of each. Negatives are as important as positives — they prove your pattern doesn't over-match.

```json
[
  { "label": "exact match", "text": "AKIAIOSFODNN7EXAMPLE", "shouldMatch": true },
  { "label": "too short", "text": "AKIASHORT", "shouldMatch": false },
  { "label": "wrong prefix", "text": "XKIAIOSFODNN7EXAMPLE", "shouldMatch": false }
]
```

Two optional fixture fields (schema: `RuleFixture` in `packages/schema/src/zod/rule.ts`):

- `filePath` — simulated file context for the scan, so fixtures can assert `appliesTo`
  gating (e.g. prove a Python-only pattern does NOT fire when `filePath` ends in `.ts`).
- `expectedSpans` — array of `{ start, end }` pinning exactly which characters the
  finding must cover. Add these whenever the rule redacts a value (via `captureGroup`),
  so the span provably covers the value itself, not just a label next to it.

## Writing a good rule

1. Start with a regex that matches the full valid format
2. Use negative lookahead/lookbehind for adjacent-character exclusions (e.g., `(?!000)`)
3. Add `postValidators` for mathematical checks (Luhn, entropy) rather than making the regex more complex
4. Write negative fixtures that capture common false-positive patterns in code (variable names, comments, documentation examples)
5. Test locally: `pnpm test --filter @akasecurity/detections` — all fixtures must pass before opening a PR

## Adding a new pack

1. Create `rules/<pack-id>/manifest.json`
2. Create each `rules/<pack-id>/<rule>.json`
3. Create `rules/<pack-id>/fixtures/<rule>.json` (mandatory)
4. Run `pnpm test --filter @akasecurity/detections` and verify all fixtures pass
5. Regenerate the bundled-pack snapshot: `pnpm --filter @akasecurity/plugin-sdk gen:bundled-packs`
   rewrites `packages/plugin-sdk/src/bundled-packs.generated.ts` from the `rules/` tree — that
   generated module is how packs reach the shipped plugin and CLI (rule JSON is inlined at
   build time; there is no runtime pack download). The drift test
   `packages/plugin-sdk/src/rule-packs.test.ts` fails CI if you forget this step.

## Severity guide

Calibrated against the shipped packs:

| Severity | When to use                                                                                                                                                      |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| critical | Immediate credential/key leak (cloud API key, private key) or a directly exploitable code flaw (command/SQL injection, JWT verification disabled)                |
| high     | High-risk PII with fraud potential (SSN, passport, credit card) or a risky code pattern (embedded credential, TLS verification disabled, unsafe deserialization) |
| medium   | Moderate-risk PII (email, phone, name+address combinations) or a weak-crypto / debug-left-on code pattern                                                        |
| low      | Low-risk contextual data (internal hostnames, file paths, feature flags, DB table names)                                                                         |
