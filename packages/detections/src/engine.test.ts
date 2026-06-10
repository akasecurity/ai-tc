import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import type { Rule, RuleFixture } from '@akasecurity/schema';
import { Rule as RuleSchema, RuleFixture as RuleFixtureSchema } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { redact, scan } from './engine.ts';
import type { MatchResult } from './types.ts';

function loadRule(packDir: string, ruleFile: string): Rule {
  const raw = JSON.parse(readFileSync(resolve(packDir, `${ruleFile}.json`), 'utf-8')) as unknown;
  return RuleSchema.parse(raw);
}

type Fixture = RuleFixture;

function loadFixtures(packDir: string, ruleFile: string): Fixture[] {
  const fixturePath = resolve(packDir, 'fixtures', `${ruleFile}.json`);
  if (!existsSync(fixturePath)) {
    throw new Error(
      `Missing fixture file for rule "${ruleFile}" — expected at ${fixturePath}. ` +
        'Every rule must have a fixture file per skills/write-detection-rule/SKILL.md.',
    );
  }
  const raw = JSON.parse(readFileSync(fixturePath, 'utf-8')) as unknown;
  return (raw as unknown[]).map((f) => RuleFixtureSchema.parse(f));
}

const RULES_DIR = resolve(__dirname, '../../../rules');

// Auto-discover all packs, rules, and fixtures
const packDirs = readdirSync(RULES_DIR, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name);

interface DiscoveredRule {
  packDir: string;
  ruleFile: string;
  rule: Rule;
  fixtures: Fixture[];
}

const discovered: DiscoveredRule[] = [];
for (const packDir of packDirs) {
  const manifestPath = resolve(RULES_DIR, packDir, 'manifest.json');
  if (!existsSync(manifestPath)) continue;

  const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as { rules: string[] };

  for (const ruleFile of manifest.rules) {
    const rule = loadRule(resolve(RULES_DIR, packDir), ruleFile);
    const fixtures = loadFixtures(resolve(RULES_DIR, packDir), ruleFile);
    discovered.push({ packDir, ruleFile, rule, fixtures });
  }
}

// The full loaded ruleset across every pack. Rules that declare `requiresNearby`
// need corroborating signals (other rules' matches) to fire, so their fixtures
// must be scanned against the whole ruleset rather than the rule in isolation.
const allRules = discovered.map((d) => d.rule);

for (const { packDir, ruleFile, rule, fixtures } of discovered) {
  // A gated rule is scanned against the full ruleset so its proximity gate is
  // actually exercised; ungated rules keep the original isolation behavior.
  const gated = rule.requiresNearby !== undefined;
  const ruleset = gated ? allRules : [rule];

  describe(`${packDir}/${ruleFile}`, () => {
    it('has at least one fixture', () => {
      expect(fixtures.length).toBeGreaterThan(0);
    });

    for (const fixture of fixtures) {
      it(fixture.label, () => {
        const context = fixture.filePath ? { filePath: fixture.filePath } : undefined;
        const findings = scan(fixture.text, ruleset, context);
        // For gated rules other rules in the set may also match the fixture
        // text, so assert specifically on THIS rule's findings.
        const own = gated ? findings.filter((f) => f.ruleId === rule.id) : findings;
        if (fixture.shouldMatch) {
          expect(own.length).toBeGreaterThan(0);
        } else {
          expect(own).toHaveLength(0);
        }
        // When the fixture pins exact spans, assert them — this is how span
        // boundaries (e.g. a path match stopping at adjacent shell syntax)
        // are locked in, not just match/no-match.
        if (fixture.expectedSpans) {
          expect(own.map((f) => f.span)).toEqual(fixture.expectedSpans);
        }
      });
    }
  });
}

describe('postValidators', () => {
  const entropyRule = RuleSchema.parse({
    specVersion: 1,
    id: 'test/entropy',
    name: 'entropy test',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: '\\b[A-Za-z0-9+/]{40}\\b', flags: 'g' },
    postValidators: ['entropy'],
  });

  it('drops low-entropy matches that satisfy the regex', () => {
    expect(scan('x'.repeat(40), [entropyRule])).toHaveLength(0);
  });

  it('keeps high-entropy matches', () => {
    const findings = scan('AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMIK7MDENG', [entropyRule]);
    expect(findings.length).toBeGreaterThan(0);
  });

  const luhnRule = RuleSchema.parse({
    specVersion: 1,
    id: 'test/luhn',
    name: 'luhn test',
    category: 'financial',
    severity: 'critical',
    matcher: { type: 'regex', pattern: '\\b\\d{16}\\b', flags: 'g' },
    postValidators: ['luhn'],
  });

  it('drops Luhn-invalid numbers', () => {
    expect(scan('card 1234567890123456 end', [luhnRule])).toHaveLength(0);
  });

  it('keeps Luhn-valid numbers', () => {
    expect(scan('card 4111111111111111 end', [luhnRule]).length).toBeGreaterThan(0);
  });

  it('ignores unknown validator names', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/unknown',
      name: 'unknown validator',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'keyword', keywords: ['hello'], caseSensitive: false },
      postValidators: ['does-not-exist'],
    });
    expect(scan('hello world', [rule]).length).toBeGreaterThan(0);
  });
});

describe('requiresNearby (co-occurrence gating)', () => {
  // A simple date rule used as the gated candidate across these tests.
  const dateMatcher = { type: 'regex', pattern: '\\b\\d{4}-\\d{2}-\\d{2}\\b', flags: 'g' } as const;
  const nameRule = RuleSchema.parse({
    specVersion: 1,
    id: 'test/name',
    name: 'name signal',
    category: 'pii',
    severity: 'medium',
    matcher: { type: 'keyword', keywords: ['my name is'], caseSensitive: false },
  });

  it('keeps a gated match corroborated by a label keyword in the window', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/dob-label',
      name: 'dob (label)',
      category: 'pii',
      severity: 'high',
      matcher: dateMatcher,
      requiresNearby: { labels: ['date of birth'], windowChars: 160 },
    });
    const findings = scan('Date of birth: 1985-03-22', [rule]);
    expect(findings.filter((f) => f.ruleId === 'test/dob-label')).toHaveLength(1);
  });

  it('drops a gated match with no nearby corroboration', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/dob-label',
      name: 'dob (label)',
      category: 'pii',
      severity: 'high',
      matcher: dateMatcher,
      requiresNearby: { labels: ['date of birth'], windowChars: 160 },
    });
    expect(scan('Renewal scheduled 1985-03-22', [rule])).toHaveLength(0);
  });

  it('keeps a gated match corroborated by a nearby category match', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/dob-cat',
      name: 'dob (category)',
      category: 'pii',
      severity: 'high',
      matcher: dateMatcher,
      requiresNearby: { categories: ['pii'], windowChars: 160 },
    });
    const findings = scan('my name is Alice, born 1985-03-22', [rule, nameRule]);
    expect(findings.filter((f) => f.ruleId === 'test/dob-cat')).toHaveLength(1);
  });

  it('drops a gated match when the category signal is outside the window', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/dob-cat',
      name: 'dob (category)',
      category: 'pii',
      severity: 'high',
      matcher: dateMatcher,
      requiresNearby: { categories: ['pii'], windowChars: 10 },
    });
    const far = `my name is Alice.${' '.repeat(200)}1985-03-22`;
    expect(scan(far, [rule, nameRule]).filter((f) => f.ruleId === 'test/dob-cat')).toHaveLength(0);
  });

  it('keeps a gated match corroborated by a nearby ruleId match', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/dob-rid',
      name: 'dob (ruleId)',
      category: 'financial',
      severity: 'high',
      matcher: dateMatcher,
      requiresNearby: { ruleIds: ['test/name'], windowChars: 160 },
    });
    const findings = scan('my name is Alice, born 1985-03-22', [rule, nameRule]);
    expect(findings.filter((f) => f.ruleId === 'test/dob-rid')).toHaveLength(1);
  });

  it('applies confidenceBoost when a gated match is corroborated', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/dob-boost',
      name: 'dob (boost)',
      category: 'pii',
      severity: 'high',
      matcher: dateMatcher,
      requiresNearby: { labels: ['dob'], windowChars: 160, confidenceBoost: 0.05 },
    });
    const findings = scan('dob 1985-03-22', [rule]).filter((f) => f.ruleId === 'test/dob-boost');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBeCloseTo(0.95, 5);
  });

  it('does not let a same-rule match satisfy category corroboration', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/dob-cat',
      name: 'dob (category)',
      category: 'pii',
      severity: 'high',
      matcher: dateMatcher,
      requiresNearby: { categories: ['pii'], windowChars: 160 },
    });
    // Two dates from the SAME rule sit near each other; neither may corroborate
    // the other, so both are dropped.
    const findings = scan('1985-03-22 and 1990-07-01', [rule]);
    expect(findings.filter((f) => f.ruleId === 'test/dob-cat')).toHaveLength(0);
  });

  it('matches labels on word boundaries, not as substrings', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/dob-label',
      name: 'dob (label)',
      category: 'pii',
      severity: 'high',
      matcher: dateMatcher,
      requiresNearby: { labels: ['state'], windowChars: 160 },
    });
    // "estate" must NOT corroborate the label "state"…
    expect(scan('real estate sold 1985-03-22', [rule])).toHaveLength(0);
    // …but a standalone "state" does.
    const ok = scan('state file 1985-03-22', [rule]).filter((f) => f.ruleId === 'test/dob-label');
    expect(ok).toHaveLength(1);
  });

  it('rejects a requiresNearby with no criteria or blank labels', () => {
    const base = {
      specVersion: 1,
      id: 'test/x',
      name: 'x',
      category: 'pii',
      severity: 'low',
      matcher: dateMatcher,
    };
    expect(() => RuleSchema.parse({ ...base, requiresNearby: {} })).toThrow();
    expect(() => RuleSchema.parse({ ...base, requiresNearby: { labels: [''] } })).toThrow();
    expect(() => RuleSchema.parse({ ...base, requiresNearby: { labels: [] } })).toThrow();
  });

  it('leaves ungated rules unchanged regardless of neighbors', () => {
    const ungated = RuleSchema.parse({
      specVersion: 1,
      id: 'test/date-ungated',
      name: 'date (ungated)',
      category: 'pii',
      severity: 'low',
      matcher: dateMatcher,
    });
    // No corroboration present, yet an ungated rule still fires as before.
    const findings = scan('Renewal scheduled 1985-03-22', [ungated]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe(0.9);
  });
});

describe('redact', () => {
  it('replaces findings with category placeholders', () => {
    const raw = JSON.parse(
      readFileSync(resolve(RULES_DIR, 'core-pii', 'email.json'), 'utf-8'),
    ) as unknown;
    const rule = RuleSchema.parse(raw);
    const text = 'Contact user@example.com for help';
    const findings = scan(text, [rule]);
    const result = redact(text, findings);
    expect(result).not.toContain('user@example.com');
    expect(result).toContain('[REDACTED:PII]');
  });

  // Shorthand for the span-shape tests below — only span/category/severity vary.
  function finding(
    start: number,
    end: number,
    category: MatchResult['category'] = 'pii',
    severity: MatchResult['severity'] = 'low',
  ): MatchResult {
    return {
      ruleId: 'test/x',
      category,
      severity,
      span: { start, end },
      rawMatch: '',
      confidence: 1,
    };
  }

  it('replaces disjoint findings independently', () => {
    const result = redact('hello world', [finding(0, 5), finding(6, 11)]);
    expect(result).toBe('[REDACTED:PII] [REDACTED:PII]');
  });

  it('keeps adjacent (touching, non-overlapping) spans as separate placeholders', () => {
    const result = redact('helloworld!', [finding(0, 5), finding(5, 10)]);
    expect(result).toBe('[REDACTED:PII][REDACTED:PII]!');
  });

  it('merges identical spans into one placeholder', () => {
    const result = redact('PRIVATE_KEY=abcdef', [
      finding(12, 18, 'secret', 'high'),
      finding(12, 18, 'secret', 'high'),
    ]);
    expect(result).toBe('PRIVATE_KEY=[REDACTED:SECRET]');
  });

  it('merges partially overlapping spans into one region', () => {
    const result = redact('abcdefghij tail', [finding(0, 6), finding(4, 10)]);
    expect(result).toBe('[REDACTED:PII] tail');
  });

  it('merges a contained span into its container', () => {
    const result = redact('abcdefghij tail', [finding(0, 10), finding(3, 6)]);
    expect(result).toBe('[REDACTED:PII] tail');
  });

  it('names a merged region after its most severe finding', () => {
    const result = redact('abcdefghij', [
      finding(0, 6, 'pii', 'low'),
      finding(4, 10, 'secret', 'critical'),
    ]);
    expect(result).toBe('[REDACTED:SECRET]');
  });

  // These secret-shaped inputs and expectations are assembled at runtime so this
  // source file never contains a credential-shaped literal itself.
  it('masks the VALUE of an env-style secret assignment, not just the key', () => {
    const raw = JSON.parse(
      readFileSync(resolve(RULES_DIR, 'secrets-infra', 'env-key-value.json'), 'utf-8'),
    ) as unknown;
    const rule = RuleSchema.parse(raw);
    const value = ['aBc123XyZ789', 'kLmNoPqRsTuVwXyZ', '1234567890'].join('');
    const text = ['API_SECRET', '=', value].join('');
    const findings = scan(text, [rule]);
    expect(findings.length).toBeGreaterThan(0);
    const redacted = redact(text, findings);
    expect(redacted).not.toContain(value);
    expect(redacted).toBe(['API_SECRET', '=', '[REDACTED:SECRET]'].join(''));
  });

  it('masks the VALUE of a JSON password field, not just the label', () => {
    const raw = JSON.parse(
      readFileSync(resolve(RULES_DIR, 'secrets-infra', 'password-field.json'), 'utf-8'),
    ) as unknown;
    const rule = RuleSchema.parse(raw);
    const text = ['{"password', '": "', 'hunter2', '"}'].join('');
    const findings = scan(text, [rule]);
    expect(findings.length).toBeGreaterThan(0);
    const redacted = redact(text, findings);
    expect(redacted).not.toContain('hunter2');
    expect(redacted).toBe(['{"password', '": "', '[REDACTED:SECRET]', '"}'].join(''));
  });
});

describe('captureGroup span location', () => {
  it('locates the captured group even when its text repeats earlier in the match', () => {
    const rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/cap-span',
      name: 'capture span',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: 'ref \\w+ code (\\d{3})', flags: 'g', captureGroup: 1 },
    });
    // The captured "123" also occurs earlier inside the overall match; the span
    // must point at the group's own offset, not the first occurrence.
    const text = 'ref 123 code 123';
    const findings = scan(text, [rule]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.span).toEqual({ start: 13, end: 16 });
    expect(redact(text, findings)).toBe('ref 123 code [REDACTED:CUSTOM]');
  });
});

describe('bundled-rule regex performance (adversarial inputs)', () => {
  // Regression guard for patterns that used to backtrack quadratically and
  // stall the synchronous hook path on large pastes. Budgets are far above
  // the expected linear-time cost (<50ms) but far below the old quadratic
  // cost (>1400ms at 40KB).
  it('email rule scans repeated near-miss tokens in linear time', () => {
    const rule = loadRule(resolve(RULES_DIR, 'core-pii'), 'email');
    const text = 'abc-'.repeat(10_000);
    const start = performance.now();
    expect(scan(text, [rule])).toHaveLength(0);
    expect(performance.now() - start).toBeLessThan(500);
  });

  it('internal-domain rule scans long dotted runs in linear time', () => {
    const rule = loadRule(resolve(RULES_DIR, 'core-code-context'), 'internal-domain');
    const text = 'a.'.repeat(20_000);
    const start = performance.now();
    expect(scan(text, [rule])).toHaveLength(0);
    expect(performance.now() - start).toBeLessThan(500);
  });
});

describe('rules tree hygiene', () => {
  it('lists every rule JSON on disk in its pack manifest', () => {
    for (const packDir of packDirs) {
      const manifestPath = resolve(RULES_DIR, packDir, 'manifest.json');
      // A pack directory without a manifest would be silently ignored by the
      // bundle generator, so its absence is itself a failure.
      expect(existsSync(manifestPath), `rules/${packDir} has no manifest.json`).toBe(true);
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as { rules: string[] };
      const onDisk = readdirSync(resolve(RULES_DIR, packDir), { withFileTypes: true })
        .filter((e) => e.isFile() && e.name.endsWith('.json') && e.name !== 'manifest.json')
        .map((e) => e.name.replace(/\.json$/, ''))
        .sort();
      expect(onDisk, `rules/${packDir}: manifest.rules and *.json files must agree`).toEqual(
        [...manifest.rules].sort(),
      );
    }
  });

  it('keyword-matcher keywords contain no regex escapes', () => {
    // KeywordMatcher does literal indexOf lookup — a backslash in a keyword is
    // almost certainly an escape someone expected to be interpreted.
    for (const { rule } of discovered) {
      if (rule.matcher.type !== 'keyword') continue;
      for (const kw of rule.matcher.keywords) {
        expect(
          kw.includes('\\'),
          `${rule.id} keyword ${JSON.stringify(kw)} contains a backslash`,
        ).toBe(false);
      }
    }
  });
});

describe('appliesTo extension gating', () => {
  const pyOnly = RuleSchema.parse({
    specVersion: 1,
    id: 'test/py-only',
    name: 'python-only test rule',
    category: 'code_flaw',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'pickle\\.loads', flags: 'g' },
    appliesTo: { extensions: ['.py'] },
  });

  it('runs the rule for a matching extension', () => {
    expect(scan('pickle.loads(x)', [pyOnly], { filePath: 'app/main.py' })).toHaveLength(1);
  });

  it('skips the rule for a non-matching extension', () => {
    expect(scan('pickle.loads(x)', [pyOnly], { filePath: 'src/main.ts' })).toHaveLength(0);
  });

  it('matches extensions case-insensitively', () => {
    expect(scan('pickle.loads(x)', [pyOnly], { filePath: 'APP/MAIN.PY' })).toHaveLength(1);
  });

  it('still runs the rule with no file context (live hook prompts)', () => {
    expect(scan('pickle.loads(x)', [pyOnly])).toHaveLength(1);
  });

  it('still runs the rule when the path has no recognizable extension', () => {
    expect(scan('pickle.loads(x)', [pyOnly], { filePath: 'scripts/Makefile' })).toHaveLength(1);
    expect(scan('pickle.loads(x)', [pyOnly], { filePath: 'conf/.envrc' })).toHaveLength(1);
  });

  it('leaves unscoped rules unaffected by any context', () => {
    const unscoped = RuleSchema.parse({
      specVersion: 1,
      id: 'test/unscoped',
      name: 'unscoped test rule',
      category: 'code_flaw',
      severity: 'high',
      matcher: { type: 'regex', pattern: 'pickle\\.loads', flags: 'g' },
    });
    expect(scan('pickle.loads(x)', [unscoped], { filePath: 'src/main.ts' })).toHaveLength(1);
  });
});

describe('postValidators with per-rule config', () => {
  const shortEntropyRule = RuleSchema.parse({
    specVersion: 1,
    id: 'test/entropy-config',
    name: 'configured entropy test',
    category: 'code_flaw',
    severity: 'high',
    matcher: {
      type: 'regex',
      pattern: 'pwd=\\"([^\\"]+)\\"',
      flags: 'g',
      captureGroup: 1,
    },
    postValidators: [{ name: 'entropy', config: { minLength: 8, threshold: 3.0 } }],
  });

  it('accepts values above the configured floor that the default 20-char window would drop', () => {
    // 11 chars — the default minLength: 20 would reject this outright.
    expect(scan('pwd="Tr0ub4dor&3"', [shortEntropyRule])).toHaveLength(1);
  });

  it('still drops low-entropy values', () => {
    expect(scan('pwd="changeme"', [shortEntropyRule])).toHaveLength(0);
  });

  it('still drops values below the configured minLength', () => {
    expect(scan('pwd="ab1"', [shortEntropyRule])).toHaveLength(0);
  });

  it('ignores non-numeric config values (falls back to validator defaults)', () => {
    const junkConfig = RuleSchema.parse({
      ...shortEntropyRule,
      id: 'test/entropy-junk',
      postValidators: [{ name: 'entropy', config: { minLength: 'eight', threshold: null } }],
    });
    // Defaults apply: 11 chars < 20 → dropped.
    expect(scan('pwd="Tr0ub4dor&3"', [junkConfig])).toHaveLength(0);
  });
});
