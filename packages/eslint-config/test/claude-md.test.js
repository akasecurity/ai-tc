import { describe, expect, it } from 'vitest';

import {
  cardinalFor,
  codeSpansOf,
  CONVENTIONS_DOC,
  countWordIn,
  ordinalFor,
  readConventions,
  sectionOf,
  tableOf,
} from './helpers/claude-md.js';

// The guards in no-network.test.js and effective-config.test.js assert their
// findings by walking rows this parser returns. So every one of them passes
// vacuously if the parser ever answers "nothing here" instead of throwing —
// gutting the document would then read as the tables being correct. That is the
// exact failure mode those guards exist to remove, so the parser's refusals are
// tested here rather than assumed, and each refusal case also shows the
// walk-the-rows form it protects going green on the empty result.

/** How a caller uses the parser: collect findings by walking the rows. */
const findingsFrom = (rows) => rows.filter(([, ok]) => ok !== 'yes').map(([name]) => name);

const DOC = [
  '## Principles',
  '',
  '### 1. First',
  '',
  'Two things opt out:',
  '',
  '| Site | Mechanism |',
  '| ---- | --------- |',
  '| `a.ts` | inline |',
  '| `b.ts` (via `x.mjs`) | config |',
  '',
  '#### A deeper heading, still inside §1',
  '',
  'Adding a third site means updating this table.',
  '',
  '### 2. Second',
  '',
  '| Gate | Catches |',
  '| ---- | ------- |',
  '| lint | source  |',
  '',
  '## Elsewhere',
].join('\n');

describe('readConventions', () => {
  it('reads the real conventions doc, and it holds the sections the guards slice', () => {
    // A positive control on the I/O half: without it the parser could be pointed
    // at a file that exists, is non-empty, and is not the document at all — every
    // "section not found" throw below would then fire for the wrong reason.
    const md = readConventions();
    expect(md).toContain('### 3. `process.env` is off by default');
    expect(md).toContain('### 4. No network calls');
  });
});

describe('sectionOf', () => {
  it('returns the text under a heading, up to the next same-level one', () => {
    const section = sectionOf(DOC, '### 1. First');
    expect(section).toContain('| `a.ts` | inline |');
    expect(section).not.toContain('| Gate | Catches |');
  });

  it('runs past a DEEPER heading rather than stopping at it', () => {
    expect(sectionOf(DOC, '### 1. First')).toContain('Adding a third site');
  });

  it('stops at a higher-level heading too', () => {
    expect(sectionOf(DOC, '### 2. Second')).not.toContain('## Elsewhere');
  });

  it('throws when the heading is absent, rather than returning nothing', () => {
    const err = errorFrom(() => sectionOf(DOC, '### 9. Renamed'));
    expect(err?.message).toContain('found 0');
    // What the throw is worth: the caller's own shape would have passed.
    expect(findingsFrom([])).toEqual([]);
  });

  it('throws when the heading is not unique', () => {
    // A repeated anchor silently moves the slice to whatever the second
    // occurrence bounds, so the guard reads a section it did not mean to and
    // still goes green.
    const dup = `${DOC}\n\n### 1. First\n\nsomething else\n`;
    expect(errorFrom(() => sectionOf(dup, '### 1. First'))?.message).toContain('found 2');
  });
});

describe('tableOf', () => {
  const section = sectionOf(DOC, '### 1. First');

  it('returns one row of cells per body row', () => {
    expect(tableOf(section, ['Site', 'Mechanism'])).toEqual([
      ['`a.ts`', 'inline'],
      ['`b.ts` (via `x.mjs`)', 'config'],
    ]);
  });

  it('selects by header, not by position', () => {
    // §4 holds two tables; "the first one" would follow whichever moved up.
    expect(tableOf(sectionOf(DOC, '### 2. Second'), ['Gate', 'Catches'])).toEqual([
      ['lint', 'source'],
    ]);
  });

  it('throws when no table carries that header, rather than returning nothing', () => {
    const err = errorFrom(() => tableOf(section, ['Site', 'Allowed specifier', 'Why']));
    expect(err?.message).toContain('found 0');
    expect(findingsFrom([])).toEqual([]);
  });

  it('throws when two tables share a header', () => {
    const twice = `${section}\n\n| Site | Mechanism |\n| - | - |\n| \`c.ts\` | inline |\n`;
    expect(errorFrom(() => tableOf(twice, ['Site', 'Mechanism']))?.message).toContain('found 2');
  });

  it('throws on a header with no body rows', () => {
    const empty = '| Site | Mechanism |\n| ---- | --------- |\n';
    const err = errorFrom(() => tableOf(empty, ['Site', 'Mechanism']));
    expect(err?.message).toContain('no body rows');
    expect(findingsFrom([])).toEqual([]);
  });

  it('throws when a row has more or fewer cells than the header', () => {
    // Silently reading a column out of the wrong cell is worse than not reading
    // it: the guard keeps asserting, on the wrong text.
    const ragged = '| Site | Mechanism |\n| - | - |\n| `a.ts` | inline | extra |\n';
    expect(errorFrom(() => tableOf(ragged, ['Site', 'Mechanism']))?.message).toContain(
      'cell count differs',
    );
  });

  it('throws when the separator row is missing', () => {
    const noRule = '| Site | Mechanism |\n| `a.ts` | inline |\n';
    expect(errorFrom(() => tableOf(noRule, ['Site', 'Mechanism']))?.message).toContain(
      'no separator row',
    );
  });

  it('does not split on an escaped pipe inside a cell', () => {
    const piped = '| Site | Mechanism |\n| - | - |\n| `a.ts` | one \\| two |\n';
    expect(tableOf(piped, ['Site', 'Mechanism'])).toEqual([['`a.ts`', 'one \\| two']]);
  });
});

describe('codeSpansOf', () => {
  it('returns every backticked span in order', () => {
    expect(codeSpansOf('`b.ts` (via `x.mjs`)')).toEqual(['b.ts', 'x.mjs']);
    expect(codeSpansOf('`node:net`, `node:dgram`, `fetch` (inline)')).toEqual([
      'node:net',
      'node:dgram',
      'fetch',
    ]);
  });

  it('returns nothing for a cell with no code span', () => {
    // Callers assert on the count themselves — a row whose Site cell lost its
    // backticks is a finding, not something for the parser to guess at.
    expect(codeSpansOf('file-scoped ESLint config')).toEqual([]);
  });
});

describe('cardinalFor / ordinalFor', () => {
  it('spells the count the document spells', () => {
    expect(cardinalFor(4)).toBe('four');
    expect(cardinalFor(5)).toBe('five');
    expect(ordinalFor(5)).toBe('fifth');
    expect(ordinalFor(6)).toBe('sixth');
  });

  it('throws past the list rather than returning undefined', () => {
    // `expect(word).toBe(undefined)` would fail loudly, but a caller that spread
    // it into an allowed-values array would not — and the count would stop being
    // checked at exactly the point the table got long enough to need it.
    expect(errorFrom(() => cardinalFor(99))?.message).toContain('No cardinal word for 99');
    expect(errorFrom(() => ordinalFor(-1))?.message).toContain('No ordinal word for -1');
  });
});

describe('countWordIn', () => {
  const RE = /(\w+) things opt out/g;

  it('captures the word the sentence states, lower-cased', () => {
    expect(countWordIn('Two things opt out:', RE, 'x')).toBe('two');
  });

  it('throws when the sentence is gone', () => {
    expect(errorFrom(() => countWordIn('nothing here', RE, 'x'))?.message).toContain('found 0');
  });

  it('throws when the sentence appears twice', () => {
    // Two copies means one of them can drift while the guard reads the other.
    expect(
      errorFrom(() => countWordIn('Two things opt out. Five things opt out.', RE, 'x'))?.message,
    ).toContain('found 2');
  });
});

/**
 * The error `fn` throws, or undefined. Captured OUTSIDE a catch: a `try { fn();
 * throw new Error('expected') } catch (e) { expect(e.message)… }` asserts on its
 * own guard error and keeps passing after `fn` stops throwing entirely.
 */
function errorFrom(fn) {
  try {
    fn();
  } catch (err) {
    return /** @type {Error} */ (err);
  }
  return undefined;
}
