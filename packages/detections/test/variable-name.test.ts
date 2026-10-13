import type { DetectionCategory } from '@akasecurity/schema';
import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../src/engine.ts';

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

const VALUE = ['zz', 'abcdef'].join('');
const EQ = '=';

function namesIn(text: string, category?: DetectionCategory): (string | undefined)[] {
  return scan(text, [valueRule(category)]).map((f) => f.variableName);
}

describe('variable name of an assigned secret', () => {
  it('records the name on the left of an assignment', () => {
    expect(namesIn(['MY_SECRET', EQ, VALUE].join(''))).toEqual(['MY_SECRET']);
  });

  it('records the last segment of a dotted target', () => {
    expect(namesIn(['process.env.MY_SECRET ', EQ, ' "', VALUE, '"'].join(''))).toEqual([
      'MY_SECRET',
    ]);
  });

  it('records the name of the assignment on the same line only', () => {
    expect(namesIn(['MY_SECRET', EQ, '\n', VALUE].join(''))).toEqual([undefined]);
  });

  it('records nothing when the value is not the right-hand side of an assignment', () => {
    expect(namesIn(['run --with ', VALUE].join(''))).toEqual([undefined]);
    expect(namesIn(['Authorization: Bearer ', VALUE].join(''))).toEqual([undefined]);
    expect(namesIn(['https://user:', VALUE, '@example.invalid'].join(''))).toEqual([undefined]);
  });

  it('records nothing when the name is itself a detected value', () => {
    const other = ['zz', 'ghijkl'].join('');
    expect(namesIn([other, EQ, VALUE].join(''))).toEqual([undefined, undefined]);
  });

  it('records nothing for a category other than secret', () => {
    expect(namesIn(['MY_SECRET', EQ, VALUE].join(''), 'pii')).toEqual([undefined]);
  });

  it('never records a name longer than the cap', () => {
    expect(namesIn(['A'.repeat(200), EQ, VALUE].join(''))).toEqual([undefined]);
  });
});
