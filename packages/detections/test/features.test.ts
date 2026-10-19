import { readFileSync } from 'node:fs';

import { DetectionCategory, MatchFeatures, PostValidatorName, Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../src/engine.ts';
import { classifyPath, KNOWN_PREFIXES, matchFeatures, nameBucket } from '../src/features.ts';
import type { MatchResult } from '../src/types.ts';
import { withVariableNames } from '../src/variable-name.ts';
import { discoverBundledRuleFiles, fixturePath, loadRule } from './helpers/rules.ts';

// Values are assembled at runtime so no literal in this file looks like a secret.
const STRIPE_LIKE = ['sk', '_test_', 'Q7v', 'Lm2', 'Xk9', 'Pz4', 'Rt8', 'Wn1'].join('');
const PLACEHOLDER = ['x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x'].join('');

function rule(over: Partial<Record<string, unknown>> = {}): Rule {
  return Rule.parse({
    specVersion: 1,
    id: 'test/generic-key',
    name: 'generic key',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: '[A-Za-z0-9_]{12,}', flags: 'g' },
    ...over,
  });
}

function match(rawMatch: string, variableName?: string): MatchResult {
  return {
    ruleId: 'test/generic-key',
    category: 'secret',
    severity: 'high',
    span: { start: 10, end: 10 + rawMatch.length },
    rawMatch,
    confidence: 0.9,
    ...(variableName === undefined ? {} : { variableName }),
  };
}

describe('matchFeatures', () => {
  it('describes the rule, the value shape, the path and the name without carrying either', () => {
    const r = rule({
      postValidators: ['entropy'],
      requiresNearby: { labels: ['key'], windowChars: 40 },
    });
    const f = matchFeatures(match(STRIPE_LIKE, 'MOCK_STRIPE_KEY'), r, {
      filePath: 'services/billing/test/fixtures/keys.ts',
    });
    expect(f).toMatchObject({
      ruleId: 'test/generic-key',
      category: 'secret',
      validators: ['entropy'],
      corroborated: true,
      shape: {
        length: STRIPE_LIKE.length,
        classes: ['digit', 'lower', 'symbol', 'upper'],
        knownPrefix: 'sk_test_',
      },
      placeholder: false,
      pathClass: 'test',
      name: 'test_like',
    });
    const wire = JSON.stringify(f);
    expect(wire).not.toContain(STRIPE_LIKE);
    expect(wire).not.toContain('MOCK_STRIPE_KEY');
    expect(wire).not.toContain('billing');
  });

  it('reports no known prefix unless the value starts with one from the fixed public list', () => {
    const f = matchFeatures(match(['zzq', 'Lm2Xk9Pz4Rt8'].join('')), rule(), {});
    expect(f.shape.knownPrefix).toBeNull();
  });

  it('marks a repeated or sample-looking value as a placeholder', () => {
    expect(matchFeatures(match(PLACEHOLDER), rule(), {}).placeholder).toBe(true);
    expect(
      matchFeatures(match(['your', '_api_', 'key_here'].join('')), rule(), {}).placeholder,
    ).toBe(true);
  });

  it('does not mistake a credential in its own test mode for a placeholder', () => {
    expect(matchFeatures(match(STRIPE_LIKE), rule(), {}).placeholder).toBe(false);
  });

  it('buckets entropy coarsely', () => {
    expect(matchFeatures(match(PLACEHOLDER), rule(), {}).shape.entropyBucket).toBe('low');
    expect(matchFeatures(match(STRIPE_LIKE), rule(), {}).shape.entropyBucket).toBe('high');
  });

  it('reports no name bucket when the match has no variable name, and unknown with no path', () => {
    const f = matchFeatures(match(STRIPE_LIKE), rule(), {});
    expect(f.name).toBeNull();
    expect(f.pathClass).toBe('unknown');
    expect(f.validators).toEqual([]);
    expect(f.corroborated).toBe(false);
  });
});

describe('nearby words', () => {
  it('buckets the words on the match line, leaving out the value and its name', () => {
    const line = ['// example only: MOCK_KEY = ', STRIPE_LIKE, ' # api token'].join('');
    const start = line.indexOf(STRIPE_LIKE);
    const m = {
      ...match(STRIPE_LIKE, 'MOCK_KEY'),
      span: { start, end: start + STRIPE_LIKE.length },
    };
    const f = matchFeatures(m, rule(), { text: ['first line', line, 'last line'].join('\n') });
    expect(f.nearby).toEqual(['secret_like', 'test_like']);
    expect(JSON.stringify(f)).not.toContain('MOCK_KEY');
  });

  it('is empty without the scanned text', () => {
    expect(matchFeatures(match(STRIPE_LIKE), rule(), {}).nearby).toEqual([]);
  });

  it('parses under the wire schema', () => {
    const f = matchFeatures(match(STRIPE_LIKE, 'MOCK_KEY'), rule(), {
      filePath: 'a.ts',
      text: STRIPE_LIKE,
    });
    expect(MatchFeatures.safeParse(f).success).toBe(true);
  });
});

describe('classifyPath', () => {
  it.each([
    ['src/__tests__/auth.spec.ts', 'test'],
    ['pkg/foo_test.go', 'test'],
    ['tests/integration/run.py', 'test'],
    ['test/fixtures/keys.json', 'test'],
    ['src/__fixtures__/data.json', 'fixture'],
    ['testdata/sample.txt', 'fixture'],
    ['examples/quickstart/main.ts', 'example'],
    ['config.example.yml', 'example'],
    ['.env.sample', 'example'],
    ['docs/setup.md', 'docs'],
    ['README.md', 'docs'],
    ['.env', 'env'],
    ['.env.production', 'env'],
    ['deploy/app.yaml', 'config'],
    ['src/billing/client.ts', 'source'],
    ['C:\\repo\\tests\\unit\\a.ts', 'test'],
  ])('%s is %s', (path, cls) => {
    expect(classifyPath(path)).toBe(cls);
  });
});

describe('nameBucket', () => {
  it.each([
    ['MOCK_API_KEY', 'test_like'],
    ['exampleToken', 'test_like'],
    ['dummy_secret', 'test_like'],
    ['STRIPE_SECRET_KEY', 'secret_like'],
    ['dbPassword', 'secret_like'],
    ['auth_token', 'secret_like'],
    ['customer_id', 'other'],
  ])('%s is %s', (name, bucket) => {
    expect(nameBucket(name)).toBe(bucket);
  });
});

// Every string a feature set may hold. The output is proven content-free by
// showing each of its strings is drawn from here, so no scanned text can be in it.
const VOCABULARY = new Set<string>([
  ...DetectionCategory.options,
  ...PostValidatorName.options,
  ...KNOWN_PREFIXES,
  'digit',
  'lower',
  'symbol',
  'upper',
  'low',
  'medium',
  'high',
  'test',
  'fixture',
  'example',
  'docs',
  'env',
  'config',
  'source',
  'unknown',
  'test_like',
  'secret_like',
  'other',
]);

function strings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (value !== null && typeof value === 'object') return Object.values(value).flatMap(strings);
  return [];
}

describe('matchFeatures over every bundled rule', () => {
  it('holds only fixed-vocabulary strings, for every positive fixture of every rule', () => {
    let checked = 0;
    for (const file of discoverBundledRuleFiles()) {
      const ruleDef = loadRule(file.packDirAbs, file.ruleFile);
      const fixtures = JSON.parse(
        readFileSync(fixturePath(file.packDirAbs, file.ruleFile), 'utf8'),
      ) as { text: string; shouldMatch: boolean }[];
      for (const fx of fixtures.filter((f) => f.shouldMatch)) {
        for (const m of withVariableNames(scan(fx.text, [ruleDef]), fx.text)) {
          // The rule id is public and names the rule, not the content.
          const { ruleId, ...rest } = matchFeatures(m, ruleDef, { filePath: 'src/app.ts' });
          expect(ruleId).toBe(ruleDef.id);
          for (const str of strings(rest))
            expect(VOCABULARY.has(str), `${ruleDef.id}: ${str}`).toBe(true);
          checked += 1;
        }
      }
    }
    expect(checked).toBeGreaterThan(100);
  });
});
