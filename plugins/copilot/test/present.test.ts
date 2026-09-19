// The terminal layout kit behind every read surface this plugin prints.
//
// It is pure (data → string) and ships with no dependencies, so it is testable
// directly — but the properties worth pinning are not "does it return a string".
// Three of them are load-bearing and fail SILENTLY, producing output that is
// merely wrong rather than absent:
//
//  1. `fenced` has to survive a body containing its own fence. A masked match or
//     a rule id carrying ``` would otherwise close the block early and turn
//     everything after it into rendered Markdown.
//  2. `stackedBar` allocates by largest remainder specifically so segment
//     lengths sum to the filled width. Independent rounding leaves holes inside
//     the bar, which reads as a shorter bar rather than as a bug.
//  3. Padding is computed on VISIBLE width. An ANSI span flowing into a cell
//     would otherwise push every later column out of alignment.
//
// Each of those gets a case that fails when the mechanism is removed, not just
// one that exercises the happy path.
import { describe, expect, it } from 'vitest';

import {
  bar,
  defList,
  fenced,
  indent,
  padEnd,
  padStart,
  paint,
  SHADE,
  show,
  stackedBar,
  table,
  visibleLength,
  wrapText,
} from '../src/present.ts';
import { readShowBlocks } from '../src/setup-show.ts';

describe('visibleLength', () => {
  it('counts plain text as its length', () => {
    expect(visibleLength('abcdef')).toBe(6);
  });

  it('ignores ANSI escapes, which is what keeps padding math honest', () => {
    const painted = paint.brand('AKA');
    // The string really is longer than what the terminal shows — otherwise this
    // case would hold whether or not the escapes were stripped.
    expect(painted.length).toBeGreaterThan(3);
    expect(visibleLength(painted)).toBe(3);
  });

  it('counts the shade glyphs as one column each', () => {
    // They are the whole UI grammar and are multi-byte; a length taken in bytes
    // rather than code points would silently widen every severity cell.
    expect(visibleLength(Object.values(SHADE).join(''))).toBe(4);
  });
});

describe('padEnd / padStart', () => {
  it('pads to the requested width', () => {
    expect(padEnd('ab', 5)).toBe('ab   ');
    expect(padStart('ab', 5)).toBe('   ab');
  });

  it('leaves text that already exceeds the width untouched', () => {
    // Truncating would corrupt the value; the column simply runs wide.
    expect(padEnd('abcdef', 3)).toBe('abcdef');
    expect(padStart('abcdef', 3)).toBe('abcdef');
  });

  it('pads a painted cell by its VISIBLE width', () => {
    // The consequence of visibleLength, stated where it bites: a coloured cell
    // padded by raw length would come out visibly short and drag every column
    // after it leftward.
    const cell = padEnd(paint.critical('hi'), 6);
    expect(visibleLength(cell)).toBe(6);
  });
});

describe('paint', () => {
  it('emits a 24-bit truecolor sequence around the text', () => {
    // #33e6c6 → 51, 230, 198. Asserted as the parsed channel values rather than
    // by echoing the constant, so a mis-sliced hex (a classic off-by-one in
    // slice(1,3)/slice(3,5)/slice(5,7)) fails here.
    expect(paint.brand('x')).toBe('[38;2;51;230;198mx[0m');
  });

  it('bolds without a colour channel', () => {
    expect(paint.bold('x')).toBe('[1mx[0m');
  });
});

describe('bar', () => {
  it('fills proportionally and pads the rest with the light track', () => {
    expect(bar(5, 10, 10)).toBe(`${SHADE.full.repeat(5)}${SHADE.light.repeat(5)}`);
  });

  it('renders an empty track when max is 0, rather than dividing by it', () => {
    // `value / 0` is Infinity, which Math.round leaves as Infinity — the guard
    // is what stops `repeat()` throwing RangeError on a store with no data yet.
    expect(bar(3, 0, 6)).toBe(SHADE.light.repeat(6));
  });

  it('clamps a value above max to a full bar', () => {
    expect(bar(99, 10, 8)).toBe(SHADE.full.repeat(8));
  });

  it('clamps a negative value to an empty bar', () => {
    expect(bar(-5, 10, 8)).toBe(SHADE.light.repeat(8));
  });

  it('always returns exactly `width` columns', () => {
    for (const value of [0, 1, 3, 7, 10, 50]) {
      expect(visibleLength(bar(value, 10, 12)), `value=${String(value)}`).toBe(12);
    }
  });
});

describe('stackedBar', () => {
  const seg = (value: number, glyph: string): { value: number; glyph: string } => ({
    value,
    glyph,
  });

  it('sizes the whole run by total against max', () => {
    // Half the max → half the width, so a quiet day draws a shorter bar.
    const out = stackedBar([seg(10, SHADE.full)], 10, 20, 10);
    expect(out.trimEnd()).toBe(SHADE.full.repeat(5));
  });

  it('leaves NO hole when the shares do not divide evenly', () => {
    // The largest-remainder property, and the reason the allocation is not three
    // independent Math.round calls.
    //
    // The fixture is chosen to DISCRIMINATE, which is harder here than it looks:
    // for three equal thirds each share is 3.33, and round() and floor() both
    // give 3, so that case holds either way and proves nothing. These shares are
    // 35/35/30 of ten columns — exactly 3.5, 3.5 and 3.0. Largest-remainder
    // floors to 3/3/3 and hands the leftover column to one of the .5s, giving
    // 4+3+3 = 10. Independent rounding gives 4+4+3 = 11 and overflows the row.
    // Verified by mutation: swapping Math.floor for Math.round reds this case
    // and nothing else in the file.
    const out = stackedBar(
      [seg(35, SHADE.full), seg(35, SHADE.dark), seg(30, SHADE.medium)],
      100,
      100,
      10,
    );
    const filled = out.trimEnd();
    expect(filled).toHaveLength(10);
    expect(filled).not.toContain(' ');
  });

  it('keeps the run contiguous when the shares are equal thirds', () => {
    // The case the one above used to be. It does not separate floor from round,
    // so it is kept as what it actually is — a check that an evenly-divided bar
    // has no gap — rather than as the largest-remainder proof.
    const out = stackedBar(
      [seg(1, SHADE.full), seg(1, SHADE.dark), seg(1, SHADE.medium)],
      3,
      3,
      10,
    );
    expect(out.trimEnd()).toHaveLength(10);
    expect(out.trimEnd()).not.toContain(' ');
  });

  it('pads to width with blanks, not a track, so trailing counts still align', () => {
    const out = stackedBar([seg(1, SHADE.full)], 1, 4, 12);
    expect(visibleLength(out)).toBe(12);
    expect(out).toMatch(/ $/u);
    // Deliberately blank rather than SHADE.light: a track here would read as a
    // fourth segment.
    expect(out).not.toContain(SHADE.light);
  });

  it('renders nothing when max is 0', () => {
    expect(stackedBar([seg(5, SHADE.full)], 5, 0, 6)).toBe(' '.repeat(6));
  });

  it('renders nothing when total is 0, rather than dividing by it', () => {
    expect(stackedBar([seg(0, SHADE.full)], 0, 10, 6)).toBe(' '.repeat(6));
  });

  it('OVERFLOWS the row when the segments outrun total — a known limit, not a goal', () => {
    // Pinned as the behaviour that exists, not the one that should. `filled` is
    // clamped to `width`, but each segment's length is a SHARE of `total`, and
    // nothing clamps the shares — so values summing past `total` each claim more
    // than the whole bar and the joined run overflows. Here: two segments of 50
    // against a total of 10 over 8 columns give 40 characters each, 80 in all.
    //
    // NOT fixed here, for two reasons. It is unreachable from every shipped
    // caller: the three sibling plugins' `render.ts` derive the last segment as
    // `Math.max(0, d.total - d.redacted - d.warned - d.blocked)`, so the values
    // sum to at most `total` by construction, and this package wires no caller
    // at all yet. And `stackedBar` is byte-identical across all four plugins'
    // `present.ts`; clamping copilot's copy alone would split that parity for a
    // path nobody can reach. If it is ever fixed, fix all four and this case is
    // the anchor that will go red.
    const out = stackedBar([seg(50, SHADE.full), seg(50, SHADE.dark)], 10, 10, 8);
    expect(visibleLength(out)).toBe(80);
  });

  it('holds the width invariant whenever the segments respect total', () => {
    // The contract that IS guaranteed, and the precondition every shipped caller
    // satisfies. Driven across a range so a single lucky arithmetic case cannot
    // carry it.
    for (const [a, b] of [
      [0, 10],
      [1, 9],
      [3, 7],
      [5, 5],
      [10, 0],
      [4, 3],
    ]) {
      const out = stackedBar([seg(a ?? 0, SHADE.full), seg(b ?? 0, SHADE.dark)], 10, 10, 12);
      expect(visibleLength(out), `${String(a)}/${String(b)}`).toBe(12);
    }
  });

  it('ignores a negative segment rather than eating its neighbours', () => {
    const out = stackedBar([seg(-5, SHADE.dark), seg(10, SHADE.full)], 10, 10, 10);
    expect(out.trimEnd()).toBe(SHADE.full.repeat(10));
  });
});

describe('wrapText', () => {
  it('wraps greedily at the width', () => {
    expect(wrapText('aaa bbb ccc', 7)).toEqual(['aaa bbb', 'ccc']);
  });

  it('keeps a word longer than the width on its own line rather than splitting it', () => {
    // Splitting would corrupt a rule id or a path; running wide is recoverable.
    expect(wrapText('short enormouslylongtoken', 6)).toEqual(['short', 'enormouslylongtoken']);
  });

  it('returns one empty line for empty input, so callers can index [0]', () => {
    // The documented contract, and the reason the trailing `lines.length > 0`
    // branch exists at all.
    expect(wrapText('', 10)).toEqual(['']);
    expect(wrapText('', 10)[0]).toBe('');
  });

  it('returns a single line when everything fits', () => {
    expect(wrapText('fits fine', 40)).toEqual(['fits fine']);
  });
});

describe('defList', () => {
  it('aligns values against the widest label', () => {
    const out = defList(
      [
        ['Repository', 'ai-tc'],
        ['Version', '0.9.13'],
      ],
      2,
    );
    const [first, second] = out.split('\n');
    // The property is the COLUMN, not the byte count: both values start at the
    // same offset because the short label was padded to the long one.
    expect(first?.indexOf('ai-tc')).toBe(second?.indexOf('0.9.13'));
  });

  it('survives an empty row list without a -Infinity width', () => {
    // `Math.max(...[])` is -Infinity, which would make `repeat()` throw; the
    // seeded 0 is what prevents it.
    expect(defList([])).toBe('');
  });
});

describe('indent', () => {
  it('indents every line of a multi-line block', () => {
    expect(indent('a\nb', 2)).toBe('  a\n  b');
  });

  it('indents a blank line too, so a block keeps its shape', () => {
    expect(indent('a\n\nb', 1)).toBe(' a\n \n b');
  });
});

describe('table', () => {
  it('uppercases headers and sizes columns to the widest cell', () => {
    const out = table(['name', 'count'], [['a-very-long-value', '1']]);
    const [header, rule, row] = out.split('\n');
    expect(header).toContain('NAME');
    expect(header).toContain('COUNT');
    // The rule and the row agree with the header on column width — the thing a
    // reader actually sees when a width is computed wrong.
    expect(visibleLength(rule ?? '')).toBe(visibleLength(header ?? ''));
    expect(row).toContain('a-very-long-value');
  });

  it('tolerates a row with fewer cells than there are headers', () => {
    // `r[i] ?? ''` — a ragged row must not make the width computation NaN, which
    // would propagate into repeat() and throw.
    const out = table(['a', 'b', 'c'], [['1']]);
    expect(out.split('\n')).toHaveLength(3);
    expect(out).not.toContain('undefined');
  });

  it('draws a rule between every row under rowSep, and none without it', () => {
    const rows = [['1'], ['2']];
    const banded = table(['n'], rows, { rowSep: true });
    const flush = table(['n'], rows);
    // Two data rows → header rule plus one separator between them.
    expect(banded.split('\n').filter((l) => l.startsWith('─'))).toHaveLength(2);
    expect(flush.split('\n').filter((l) => l.startsWith('─'))).toHaveLength(1);
  });

  it('renders a header-only table with no rows', () => {
    expect(table(['only'], []).split('\n')).toHaveLength(2);
  });
});

describe('fenced', () => {
  it('wraps a plain body in a three-backtick fence', () => {
    expect(fenced('hello')).toBe('```\nhello\n```');
  });

  it('WIDENS the fence past the longest backtick run in the body', () => {
    // The property this function exists for. CommonMark closes a fenced block on
    // the first line carrying at least as many backticks as the opener, so a
    // body containing ``` under a ``` fence ends the block early and renders
    // everything after it as Markdown — including whatever the surface was
    // trying to show verbatim.
    const body = 'a ``` b';
    const out = fenced(body);
    const [open] = out.split('\n');
    expect(open).toBe('````');
    expect(out.endsWith('\n````')).toBe(true);
  });

  it('widens for a run anywhere in the body, not just at a line start', () => {
    expect(fenced('x`````y').split('\n')[0]).toBe('``````');
  });

  it('never drops below three backticks for a body with one', () => {
    // `longestRun + 1` is 2 here; the Math.max(3, …) floor is what keeps it a
    // legal fence.
    expect(fenced('a ` b').split('\n')[0]).toBe('```');
  });

  it('keeps the body byte-for-byte between the fences', () => {
    const body = 'line one\n  indented\n\nlast';
    const out = fenced(body);
    const lines = out.split('\n');
    expect(lines.slice(1, -1).join('\n')).toBe(body);
  });
});

describe('show', () => {
  it('produces a region readShowBlocks can recover', () => {
    // `show` delegates to showBlock, so the property worth asserting is the
    // round trip through the reader the wizard actually uses — not that one
    // function calls another.
    expect(readShowBlocks(show('a confirmation line'))).toEqual(['a confirmation line']);
  });

  it('round-trips a fenced card unchanged', () => {
    const card = fenced(table(['rule'], [['secrets/twilio-key']]));
    expect(readShowBlocks(show(card))).toEqual([card]);
  });
});
