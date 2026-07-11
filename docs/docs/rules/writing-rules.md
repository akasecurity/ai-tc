# Writing Detection Rules

A detection rule is a JSON file describing a single pattern to look for. Rules are organized into **rule packs** — directories with a `manifest.json` and one or more rule files, each with mandatory fixture files.

## Rule file format

Every rule file must conform to `specVersion: 1`:

```json
{
  "specVersion": 1,
  "id": "pack-name/rule-name",
  "name": "Human-readable name",
  "category": "secret",
  "severity": "critical",
  "matcher": {
    "type": "regex",
    "pattern": "\\bghp_[A-Za-z0-9]{36}\\b",
    "flags": "g"
  },
  "postValidators": ["entropy"],
  "examples": ["ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"]
}
```

### Required fields

| Field         | Type     | Description                                                             |
| ------------- | -------- | ----------------------------------------------------------------------- |
| `specVersion` | `1`      | Always `1` for now                                                      |
| `id`          | `string` | Kebab-case path: `pack/rule`. Must match `rules/<pack>/<rule>.json`     |
| `name`        | `string` | Human-readable label shown in findings                                  |
| `category`    | enum     | `pii` \| `financial` \| `secret` \| `phi` \| `code_context` \| `custom` |
| `severity`    | enum     | `critical` \| `high` \| `medium` \| `low`                               |
| `matcher`     | object   | How to detect — see below                                               |

### Optional fields

| Field            | Type                            | Description                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `postValidators` | `(string \| {name, config?})[]` | Validators to run after a match (e.g. `"entropy"`, `"luhn"`). The object form passes per-rule config — e.g. `{"name": "entropy", "config": {"minLength": 8, "threshold": 3.0}}` tunes the entropy gate for short password-shaped values (defaults are `minLength: 20`, `threshold: 3.5`, tuned for API keys)                                                                     |
| `appliesTo`      | `{extensions: string[]}`        | Language/file scoping: run the rule only against text from files with one of these dot-prefixed extensions (e.g. `[".py"]`). When the scanned text has **no** file context (live prompt/response hooks) the rule still runs — pasted code has no knowable language. Use for language-specific APIs (`pickle.loads`, `ObjectInputStream`) to avoid cross-language false positives |
| `examples`       | `string[]`                      | Positive examples used in documentation and tooling                                                                                                                                                                                                                                                                                                                              |

## Matcher types

### keyword

```json
{
  "type": "keyword",
  "keywords": ["password", "secret", "api_key"],
  "caseSensitive": false
}
```

Matches if any keyword appears in the text. Case-insensitive by default.

### regex

```json
{
  "type": "regex",
  "pattern": "\\b[A-Z0-9]{20}\\b",
  "flags": "g",
  "captureGroup": 0
}
```

- `pattern`: JavaScript-compatible regex string. Double-escape backslashes in JSON.
- `flags`: Regex flags string. Default `"gi"`. Common: `"g"` (global), `"gi"` (global + case-insensitive).
- `captureGroup`: Optional. Which capture group to use as the matched span (0 = full match).

!!! tip "Testing your regex"

    Use [regex101.com](https://regex101.com) with the JavaScript flavour to test patterns before writing the fixture.

## Pack structure

```
rules/
└── my-pack/
    ├── manifest.json          ← required
    ├── rule-one.json
    ├── rule-two.json
    └── fixtures/
        ├── rule-one.json      ← required for each rule
        └── rule-two.json
```

### manifest.json

```json
{
  "specVersion": 1,
  "id": "my-pack",
  "name": "My Detection Pack",
  "version": "0.1.0",
  "rules": ["rule-one", "rule-two"]
}
```

`version` is a semver string and is the unit of publishing: the [publishing flow](publishing.md)
treats each published `(pack, version)` as immutable. Bump it whenever you change a rule's content.

The following manifest fields are optional and surface as attribution on a published pack:

| Field         | Type                         | Purpose                               |
| ------------- | ---------------------------- | ------------------------------------- |
| `description` | string                       | One-line summary shown in the catalog |
| `author`      | `{ name, email?, url? }`     | Who authored/maintains the pack       |
| `license`     | string (SPDX id, e.g. `MIT`) | Usage terms                           |
| `sourceUrl`   | string (URL)                 | Link to the pack's source             |

## Fixture format

Every rule file **must** have a corresponding fixture file in `fixtures/<rule-name>.json`. CI rejects rules without fixtures.

A fixture is a JSON array of test cases:

```json
[
  {
    "label": "standard case",
    "text": "The token is ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 here",
    "shouldMatch": true
  },
  {
    "label": "too short",
    "text": "ghp_short",
    "shouldMatch": false
  },
  {
    "label": "no prefix",
    "text": "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd",
    "shouldMatch": false
  }
]
```

### Fixture rules

- **Every rule must have at least one positive and one negative fixture.**
- Fixture text must be realistic enough to verify the pattern works in context (not just the bare value).
- For regex rules: count characters carefully. Off-by-one is the most common fixture bug.
- Negative fixtures should cover: too-short values, missing prefix, embedded in longer strings.
- A fixture may set an optional `filePath` to simulate file context. Rules with
  `appliesTo` must include a negative fixture whose `filePath` has an
  out-of-scope extension, proving the gate works (and positives without
  `filePath` prove the rule still fires when no file context exists).

## Example: writing a new rule

Let's write a rule to detect Stripe secret keys (`sk_live_...`).

**Step 1** — Create the rule file `rules/payments/stripe-secret-key.json`:

```json
{
  "specVersion": 1,
  "id": "payments/stripe-secret-key",
  "name": "Stripe Secret Key",
  "category": "secret",
  "severity": "critical",
  "matcher": {
    "type": "regex",
    "pattern": "\\bsk_live_[A-Za-z0-9]{24}\\b",
    "flags": "g"
  },
  "postValidators": ["entropy"],
  "examples": ["sk_live_aBcDeFgHiJkLmNoPqRsTuVwXy"]
}
```

**Step 2** — Create fixtures `rules/payments/fixtures/stripe-secret-key.json`:

```json
[
  {
    "label": "live key in config",
    "text": "STRIPE_KEY=sk_live_aBcDeFgHiJkLmNoPqRsTuVwXy",
    "shouldMatch": true
  },
  {
    "label": "test key (not live)",
    "text": "STRIPE_KEY=sk_test_aBcDeFgHiJkLmNoPqRsTuVwXy",
    "shouldMatch": false
  },
  {
    "label": "too short",
    "text": "sk_live_short",
    "shouldMatch": false
  }
]
```

**Step 3** — Add to manifest `rules/payments/manifest.json`:

```json
{
  "specVersion": 1,
  "id": "payments",
  "name": "Payments Secrets",
  "version": "0.1.0",
  "rules": ["stripe-secret-key"]
}
```

**Step 4** — Run the tests:

```bash
pnpm --filter @akasecurity/detections test
```

The fixture-driven test auto-discovers your new rule and runs all fixtures. Fix until green.

## Testing a draft rule

Rules are tested **locally** against their fixtures — no server, no network. The
fixture-driven suite in `@akasecurity/detections` auto-discovers every rule under `rules/`
and replays its fixtures through the same pure engine the plugin and CLI use:

```bash
# Run the whole detection suite (all packs, all fixtures):
pnpm --filter @akasecurity/detections test
```

Both commands report each fixture's outcome against its `shouldMatch` expectation, so a
mismatched regex or an off-by-one span fails loudly. Iterate on the rule + fixtures
until green before committing. Once a rule pack is installed, you can also point the CLI
at real content with `aka scan <path>` to see it fire in context.

## Severity guidelines

| Severity   | When to use                                                                   |
| ---------- | ----------------------------------------------------------------------------- |
| `critical` | Credentials, private keys, tokens — immediate exfiltration risk               |
| `high`     | PII that could enable identity theft (SSN, passport numbers)                  |
| `medium`   | PII that's sensitive but not immediately dangerous (email, phone)             |
| `low`      | Context that's worth noting but not blocking (internal file paths, usernames) |

## Category meanings

| Category       | Examples                                                         |
| -------------- | ---------------------------------------------------------------- |
| `secret`       | API keys, tokens, passwords, private keys                        |
| `pii`          | Email, phone, name, address, date of birth                       |
| `financial`    | Credit card numbers, bank account numbers, IBAN                  |
| `phi`          | Protected health information (medical record numbers, diagnoses) |
| `code_context` | Internal paths, hostnames, repo names not meant to leave the org |
| `custom`       | Organisation-specific patterns                                   |
