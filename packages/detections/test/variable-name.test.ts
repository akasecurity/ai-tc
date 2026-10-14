import type { DetectionCategory } from '@akasecurity/schema';
import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../src/engine.ts';
import { VARIABLE_NAME_LOOKBEHIND, withVariableNames } from '../src/variable-name.ts';

function valueRule(category: DetectionCategory = 'secret'): Rule {
  return Rule.parse({
    specVersion: 1,
    id: `test/zz-${category}`,
    name: 'zz value',
    category,
    severity: 'high',
    matcher: { type: 'regex', pattern: '\\bzz[a-z]{6}\\b', flags: 'g' },
  });
}

function keywordRule(keyword: string, category: DetectionCategory): Rule {
  return Rule.parse({
    specVersion: 1,
    id: `test/keyword-${category.replace('_', '-')}`,
    name: 'keyword',
    category,
    severity: 'low',
    matcher: { type: 'keyword', keywords: [keyword] },
  });
}

const VALUE = ['zz', 'abcdef'].join('');
const EQ = '=';

function namesIn(text: string, category?: DetectionCategory): (string | undefined)[] {
  return withVariableNames(scan(text, [valueRule(category)]), text).map((f) => f.variableName);
}

function nameOf(...parts: string[]): string | undefined {
  const text = parts.join('');
  const names = namesIn(text);
  expect(names).toHaveLength(1);
  return names[0];
}

describe('variable name of an assigned secret', () => {
  it('is not computed by scan itself', () => {
    expect(scan(['MY_SECRET', EQ, VALUE].join(''), [valueRule()])[0]).not.toHaveProperty(
      'variableName',
    );
  });

  it('records the name on the left of an assignment', () => {
    expect(nameOf('MY_SECRET', EQ, VALUE)).toBe('MY_SECRET');
    expect(nameOf('export MY_SECRET ', EQ, ' "', VALUE, '"')).toBe('MY_SECRET');
    expect(nameOf('api_key', ' :', EQ, ' "', VALUE, '"')).toBe('api_key');
    expect(nameOf('connect(api_key', EQ, '"', VALUE, '")')).toBe('api_key');
  });

  it('records the last segment of a dotted target', () => {
    expect(nameOf('process.env.MY_SECRET ', EQ, ' "', VALUE, '"')).toBe('MY_SECRET');
  });

  it('records the variable of a typed declaration, not its type', () => {
    expect(nameOf('const stripeKey: string ', EQ, ' "', VALUE, '"')).toBe('stripeKey');
    expect(nameOf('STRIPE_SECRET_KEY: str ', EQ, ' "', VALUE, '"')).toBe('STRIPE_SECRET_KEY');
    expect(nameOf('val apiKey: String ', EQ, ' "', VALUE, '"')).toBe('apiKey');
    expect(nameOf('var apiKey string ', EQ, ' "', VALUE, '"')).toBe('apiKey');
    expect(nameOf('private readonly apiKey: string ', EQ, " '", VALUE, "'")).toBe('apiKey');
  });

  it('records the key of a mapping entry', () => {
    expect(nameOf('secret_key: ', VALUE)).toBe('secret_key');
    expect(nameOf('  - secret_key: "', VALUE, '"')).toBe('secret_key');
    expect(nameOf('{"stripeKey": "', VALUE, '"}')).toBe('stripeKey');
    expect(nameOf('{"a": 1, "stripeKey":"', VALUE, '"}')).toBe('stripeKey');
    expect(nameOf("{ stripeKey: '", VALUE, "' }")).toBe('stripeKey');
  });

  it('records the name of the assignment on the same line only', () => {
    expect(nameOf('MY_SECRET', EQ, '\n', VALUE)).toBeUndefined();
    expect(nameOf('MY_SECRET', EQ, '\r\n', VALUE)).toBeUndefined();
    expect(nameOf('first\r\nMY_SECRET', EQ, VALUE)).toBe('MY_SECRET');
  });

  it('never records a string literal elsewhere on the line', () => {
    const other = ['Pr0d', 'Passw0rd'].join('');
    expect(nameOf('const key ', EQ, ' isProd ? "', other, '" : "', VALUE, '";')).toBeUndefined();
    expect(nameOf('pw: env ', EQ, EQ, ' "prod" ? "', other, '" : "', VALUE, '"')).toBeUndefined();
    expect(nameOf('call("', other, '": "', VALUE, '")')).toBeUndefined();
  });

  it('never records a name in a ternary branch', () => {
    expect(nameOf('a ? b : "', VALUE, '"')).toBeUndefined();
    expect(nameOf('a ? b ', EQ, ' "', VALUE, '"')).toBeUndefined();
    expect(nameOf('a ? b : c ', EQ, ' "', VALUE, '"')).toBeUndefined();
  });

  it('records nothing for prose, log output, credentials pairs or a port', () => {
    expect(nameOf('my stripe key is: ', VALUE)).toBeUndefined();
    expect(nameOf('Here, use this: ', VALUE)).toBeUndefined();
    expect(nameOf('Invalid API Key provided: ', VALUE)).toBeUndefined();
    expect(nameOf('curl -u admin:', VALUE)).toBeUndefined();
    expect(nameOf('admin:', VALUE)).toBeUndefined();
    expect(nameOf('https://example.com:', VALUE)).toBeUndefined();
    expect(nameOf('Thanks, here: ', VALUE)).toBeUndefined();
  });

  it('records nothing when the value is not the right-hand side of an assignment', () => {
    expect(nameOf('run --with ', VALUE)).toBeUndefined();
    expect(nameOf('Authorization: Bearer ', VALUE)).toBeUndefined();
    expect(nameOf('https://user:', VALUE, '@example.invalid')).toBeUndefined();
    expect(nameOf('x ', EQ, EQ, ' "', VALUE, '"')).toBeUndefined();
  });

  it('records nothing when the name is itself a detected value', () => {
    const other = ['zz', 'ghijkl'].join('');
    expect(namesIn([other, EQ, VALUE].join(''))).toEqual([undefined, undefined]);
  });

  it('records nothing when the name overlaps a detection of any category', () => {
    const text = ['ORION_STRIPE_KEY', EQ, VALUE].join('');
    for (const category of ['custom', 'pii', 'code_context'] as const) {
      const findings = withVariableNames(
        scan(text, [valueRule(), keywordRule('ORION', category)]),
        text,
      );
      const secret = findings.find((f) => f.category === 'secret');
      expect(secret).toBeDefined();
      expect(secret).not.toHaveProperty('variableName');
    }
  });

  it('records nothing for a category other than secret', () => {
    expect(namesIn(['MY_SECRET', EQ, VALUE].join(''), 'pii')).toEqual([undefined]);
  });

  it('looks for the name only within the look-back window', () => {
    const assignment = ['MY_SECRET', EQ].join('');
    const pad = (n: number) => ' '.repeat(n);
    expect(nameOf(assignment, pad(VARIABLE_NAME_LOOKBEHIND - assignment.length), VALUE)).toBe(
      'MY_SECRET',
    );
    expect(nameOf(assignment, pad(VARIABLE_NAME_LOOKBEHIND), VALUE)).toBeUndefined();
  });

  it('records no name, rather than a truncated one, when the window cuts it', () => {
    const assignment = ['MY_SECRET', EQ].join('');
    const pad = ' '.repeat(VARIABLE_NAME_LOOKBEHIND - assignment.length + 3);
    expect(nameOf('x ', assignment, pad, VALUE)).toBeUndefined();
  });

  it('records nothing on a commented-out line', () => {
    expect(nameOf('// API_KEY', EQ, VALUE)).toBeUndefined();
    expect(nameOf('# API_KEY', EQ, VALUE)).toBeUndefined();
    expect(nameOf('  # export API_KEY ', EQ, ' "', VALUE, '"')).toBeUndefined();
    expect(nameOf('# api_key: ', VALUE)).toBeUndefined();
  });

  it('still records an assignment inside a trailing comment, as documented', () => {
    expect(nameOf('x = 1 # API_KEY', EQ, VALUE)).toBe('API_KEY');
  });

  it('records nothing behind a type annotation holding a comma or a brace, as documented', () => {
    expect(nameOf('const x: Record<string, string> ', EQ, ' "', VALUE, '"')).toBeUndefined();
    expect(nameOf('const x: { a: string } ', EQ, ' "', VALUE, '"')).toBeUndefined();
  });

  it('never records a name longer than the cap', () => {
    expect(namesIn(['A'.repeat(200), EQ, VALUE].join(''))).toEqual([undefined]);
  });
});
