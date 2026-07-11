# Detection Engine

The detection engine lives in `packages/detections`. It is intentionally **pure** — no I/O, no Node-specific APIs, no network calls. It runs identically everywhere it is embedded: the plugin hooks (in-process), the `aka` CLI, and the web dashboard, so every surface scans the same way.

## Public API

```typescript
import { scan, redact, registerPack, getLoadedRules } from '@akasecurity/detections';

// Scan a text string against all loaded rules (or a specific set)
const findings = scan(text, rules?);

// Replace matched spans with [REDACTED:CATEGORY] placeholders
const sanitized = redact(text, findings);

// Register a rule pack at startup
registerPack({ id: 'core-pii', rules: [...] });

// Inspect what's loaded
const rules = getLoadedRules();
```

## How `scan()` works

```
scan(text, rules)
  │
  ├─ for each rule:
  │    ├─ rule.matcher.type === 'keyword' → KeywordMatcher.match()
  │    ├─ rule.matcher.type === 'regex'   → RegexMatcher.match()
  │    └─ rule.matcher.type === 'validator' → (future)
  │
  └─ returns MatchResult[] with:
       ruleId, category, severity, span {start, end}, rawMatch, confidence
```

Matchers return zero or more `{start, end}` spans within the text. The engine wraps each span into a `MatchResult` with the rule's metadata attached.

## Matcher types

### keyword

Checks for literal keyword presence. Case-insensitive by default.

```json
{
  "type": "keyword",
  "keywords": ["password", "secret", "api_key", "private_key"],
  "caseSensitive": false
}
```

### regex

Applies a regular expression with optional flags.

```json
{
  "type": "regex",
  "pattern": "\\b(AKIA|ASIA)[A-Z0-9]{16}\\b",
  "flags": "g"
}
```

!!! note "Statement-level patterns"

    Use `\b` word boundaries in regex patterns to avoid false positives from substrings.

### validator (coming soon)

Runs a named validator function (Luhn check for card numbers, Shannon entropy for secrets, SSN checksum). The current schema accepts `postValidators` as an array of validator names — the engine will apply them as post-match filters in a future release.

## How `redact()` works

Spans are sorted in **descending order** before replacement so that earlier replacements don't shift the indices of later ones:

```typescript
const sorted = findings.sort((a, b) => b.span.start - a.span.start);
for (const f of sorted) {
  const placeholder = `[REDACTED:${f.category.toUpperCase()}]`;
  result = result.slice(0, f.span.start) + placeholder + result.slice(f.span.end);
}
```

The placeholder encodes the category (`PII`, `SECRET`, `FINANCIAL`, etc.) so downstream systems know what was removed.

## MatchResult shape

```typescript
interface MatchResult {
  ruleId: string; // e.g. "secrets/aws-access-key"
  category: string; // e.g. "secret"
  severity: string; // "critical" | "high" | "medium" | "low"
  span: { start: number; end: number };
  rawMatch: string; // the actual matched text
  confidence: number; // 0.0–1.0 (regex matches default to 0.9)
}
```

## Loading rule packs

Rule packs are loaded at startup. In the plugin, every pack under `rules/` is bundled into the hook scripts at build time and registered via `registerBundledPacks()` (`packages/plugin-sdk/src/rule-packs.ts`); at scan time the effective ruleset is the **installed snapshot** in the local store (`installed_packs`, enabled packs only), so pack versions and the enable/disable toggle genuinely control what runs. In tests (like the fixture-driven Vitest suite), packs are loaded directly from the `rules/` directory.

```typescript
// From the detection engine test setup:
const rule = JSON.parse(fs.readFileSync('rules/core-pii/email.json'));
const findings = scan(text, [Rule.parse(rule)]);
```

## Fixture-driven testing

Every rule **must** have a `fixtures/` directory with positive and negative test cases. The Vitest test at `packages/detections/src/engine.test.ts` auto-discovers all rule packs and runs their fixtures.

A fixture file is a JSON array:

```json
[
  { "label": "plain email", "text": "contact user@example.com", "shouldMatch": true },
  { "label": "no TLD", "text": "not-an-email@localhost", "shouldMatch": false }
]
```

CI fails if any fixture assertion fails. See [Writing Rules](../rules/writing-rules.md) for the full format.

## Adding a new matcher type

1. Create `packages/detections/src/matchers/<type>.ts` implementing `match(text, rule): Span[]`
2. Register it in `engine.ts` under the appropriate `rule.matcher.type` branch
3. Add a corresponding `type` literal to the `Matcher` discriminated union in `packages/schema/src/zod/rule.ts`
4. Write fixtures

## Validators (built-in, not yet wired)

The validator functions exist in `packages/detections/src/validators/`:

| Validator       | File         | What it checks                        |
| --------------- | ------------ | ------------------------------------- |
| Luhn            | `luhn.ts`    | Credit/debit card number checksum     |
| Shannon entropy | `entropy.ts` | High-entropy strings (likely secrets) |

These are used today as standalone utilities. Post-match validator wiring is on the roadmap.
