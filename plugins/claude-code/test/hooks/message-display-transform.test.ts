import { describe, expect, it, vi } from 'vitest';

import type { DisplayCarry, DisplayDeps } from '../../src/hooks/message-display-transform.ts';
import { EMPTY_CARRY, transformDelta } from '../../src/hooks/message-display-transform.ts';

const POINTER = `[[aka:secret:AA.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
const BADGE = '[scrubbed:secret/aws AKIA…MPLE]';

function makeDeps(overrides?: Partial<DisplayDeps>): DisplayDeps {
  return {
    mode: 'masked',
    maxRevealsPerMessage: 2,
    describe: () =>
      Promise.resolve({ category: 'secret', provider: 'aws', maskedMatch: 'AKIA…MPLE' }),
    reveal: () => Promise.resolve(null),
    ...overrides,
  };
}

describe('transformDelta — masked mode', () => {
  it('replaces a complete pointer with the descriptor badge', async () => {
    const result = await transformDelta(`key is ${POINTER} ok`, EMPTY_CARRY, false, makeDeps());
    expect(result.display).toBe(`key is ${BADGE} ok`);
    expect(result.carry.tail).toBe('');
  });

  it('falls back to the token category when describe returns null', async () => {
    const deps = makeDeps({ describe: () => Promise.resolve(null) });
    const result = await transformDelta(`x ${POINTER}`, EMPTY_CARRY, false, deps);
    expect(result.display).toBe('x [scrubbed:secret]');
  });

  it('falls back to the token category when describe throws', async () => {
    const deps = makeDeps({ describe: () => Promise.reject(new Error('boom')) });
    const result = await transformDelta(POINTER, EMPTY_CARRY, false, deps);
    expect(result.display).toBe('[scrubbed:secret]');
  });

  it('returns null display for a clean delta (fast path)', async () => {
    const result = await transformDelta('nothing to see here', EMPTY_CARRY, false, makeDeps());
    expect(result.display).toBeNull();
    expect(result.carry).toEqual(EMPTY_CARRY);
  });
});

describe('transformDelta — split pointers', () => {
  it('holds an open pointer tail and completes it on the next delta', async () => {
    const cut = 20;
    const deltaA = `see ${POINTER.slice(0, cut)}`;
    const deltaB = `${POINTER.slice(cut)} done`;
    const deps = makeDeps();

    const first = await transformDelta(deltaA, EMPTY_CARRY, false, deps);
    expect(first.display).toBe('see ');
    expect(first.carry.tail).toBe(POINTER.slice(0, cut));

    const second = await transformDelta(deltaB, first.carry, false, deps);
    expect(second.display).toBe(`${BADGE} done`);
    expect(second.carry.tail).toBe('');

    expect([first.display, second.display].join('')).toBe(`see ${BADGE} done`);
  });

  it('emits an empty display when the whole delta is held', async () => {
    const result = await transformDelta('[[aka:se', EMPTY_CARRY, false, makeDeps());
    expect(result.display).toBe('');
    expect(result.carry.tail).toBe('[[aka:se');
  });

  it('re-emits a held tail that turns out not to be a pointer', async () => {
    const deps = makeDeps();
    const first = await transformDelta('score [', EMPTY_CARRY, false, deps);
    expect(first.display).toBe('score ');
    expect(first.carry.tail).toBe('[');

    const second = await transformDelta('5] apples', first.carry, false, deps);
    expect(second.display).toBe('[5] apples');
    expect(second.carry.tail).toBe('');
  });
});

describe('transformDelta — full mode', () => {
  it('reveals the raw value with a trailing badge and counts it', async () => {
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.resolve('RAW-VALUE') });
    const result = await transformDelta(`use ${POINTER}`, EMPTY_CARRY, false, deps);
    expect(result.display).toBe('use RAW-VALUE [scrubbed:secret]');
    expect(result.carry.revealedCount).toBe(1);
  });

  it('masks beyond the per-message cap, with the count threaded via carry', async () => {
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.resolve('RAW') });

    const first = await transformDelta(`${POINTER} and ${POINTER}`, EMPTY_CARRY, false, deps);
    expect(first.display).toBe('RAW [scrubbed:secret] and RAW [scrubbed:secret]');
    expect(first.carry.revealedCount).toBe(2);

    const second = await transformDelta(`third ${POINTER}`, first.carry, false, deps);
    expect(second.display).toBe(`third ${BADGE}`);
    expect(second.carry.revealedCount).toBe(2);
  });

  it('falls back to the masked badge when reveal returns null', async () => {
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.resolve(null) });
    const result = await transformDelta(POINTER, EMPTY_CARRY, false, deps);
    expect(result.display).toBe(BADGE);
    expect(result.carry.revealedCount).toBe(0);
  });

  it('falls back to the masked badge when reveal throws', async () => {
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.reject(new Error('boom')) });
    const result = await transformDelta(POINTER, EMPTY_CARRY, false, deps);
    expect(result.display).toBe(BADGE);
  });
});

describe('transformDelta — protected regions', () => {
  it('masks inside a code fence even in full mode', async () => {
    const reveal = vi.fn(() => Promise.resolve('RAW'));
    const deps = makeDeps({ mode: 'full', reveal });
    const result = await transformDelta(
      `\`\`\`\nexport KEY=${POINTER}\n\`\`\``,
      EMPTY_CARRY,
      false,
      deps,
    );
    expect(result.display).toBe(`\`\`\`\nexport KEY=${BADGE}\n\`\`\``);
    expect(reveal).not.toHaveBeenCalled();
  });

  it('masks inside a fence opened in an earlier delta (state via carry)', async () => {
    const reveal = vi.fn(() => Promise.resolve('RAW'));
    const deps = makeDeps({ mode: 'full', reveal });

    const first = await transformDelta('```js\n', EMPTY_CARRY, false, deps);
    expect(first.display).toBeNull();
    expect(first.carry.fenceOpen).toBe(true);

    const second = await transformDelta(`const k = ${POINTER};\n`, first.carry, false, deps);
    expect(second.display).toBe(`const k = ${BADGE};\n`);
    expect(reveal).not.toHaveBeenCalled();
  });

  it('masks inside an inline backtick span', async () => {
    const reveal = vi.fn(() => Promise.resolve('RAW'));
    const deps = makeDeps({ mode: 'full', reveal });
    const result = await transformDelta(`run \`echo ${POINTER}\` now`, EMPTY_CARRY, false, deps);
    expect(result.display).toBe(`run \`echo ${BADGE}\` now`);
    expect(reveal).not.toHaveBeenCalled();
  });

  it('masks on a quoted line', async () => {
    const reveal = vi.fn(() => Promise.resolve('RAW'));
    const deps = makeDeps({ mode: 'full', reveal });
    const result = await transformDelta(`> the key was ${POINTER}`, EMPTY_CARRY, false, deps);
    expect(result.display).toBe(`> the key was ${BADGE}`);
    expect(reveal).not.toHaveBeenCalled();
  });

  it('reveals again on the line after a quoted line', async () => {
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.resolve('RAW') });
    const result = await transformDelta(`> quoted\nplain ${POINTER}`, EMPTY_CARRY, false, deps);
    expect(result.display).toBe('> quoted\nplain RAW [scrubbed:secret]');
  });
});

describe('transformDelta — final flush', () => {
  it('flushes an unterminated pointer prefix verbatim on final', async () => {
    const deps = makeDeps();
    const first = await transformDelta('tail: [[aka:secr', EMPTY_CARRY, false, deps);
    expect(first.display).toBe('tail: ');
    expect(first.carry.tail).toBe('[[aka:secr');

    const last = await transformDelta('', first.carry, true, deps);
    expect(last.display).toBe('[[aka:secr');
    expect(last.carry.tail).toBe('');
  });

  it('holds nothing back when final is set on a single delta', async () => {
    const result = await transformDelta('end [[aka:se', EMPTY_CARRY, true, makeDeps());
    expect(result.display).toBeNull();
    expect(result.carry.tail).toBe('');
  });
});

describe('transformDelta — lookalikes', () => {
  it('passes an invalid-category lookalike through untouched', async () => {
    const result = await transformDelta(
      'see [[aka:bogus:AA.BB.CC]] here',
      EMPTY_CARRY,
      false,
      makeDeps(),
    );
    expect(result.display).toBeNull();
    expect(result.carry.tail).toBe('');
  });

  it('flushes a held prefix once it diverges from the pointer grammar', async () => {
    const deps = makeDeps();
    const first = await transformDelta('[[aka:secret:AB.', EMPTY_CARRY, false, deps);
    expect(first.display).toBe('');
    expect(first.carry.tail).toBe('[[aka:secret:AB.');

    const overflow = 'A'.repeat(30);
    const second = await transformDelta(overflow, first.carry, false, deps);
    expect(second.display).toBe(`[[aka:secret:AB.${overflow}`);
    expect(second.carry.tail).toBe('');
  });
});

describe('transformDelta — off mode', () => {
  it('always returns null display and an empty carry', async () => {
    const dirty: DisplayCarry = {
      tail: '[[aka:se',
      fenceOpen: true,
      tickOpen: true,
      lineQuoted: true,
      revealedCount: 2,
    };
    const result = await transformDelta(POINTER, dirty, false, makeDeps({ mode: 'off' }));
    expect(result.display).toBeNull();
    expect(result.carry).toEqual(EMPTY_CARRY);
  });
});

describe('transformDelta — region state on clean deltas', () => {
  it('tracks fence toggles even when nothing is emitted', async () => {
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.resolve('RAW') });
    const opened = await transformDelta('```\ninside', EMPTY_CARRY, false, deps);
    expect(opened.display).toBeNull();
    expect(opened.carry.fenceOpen).toBe(true);

    const closed = await transformDelta('\n```\nafter', opened.carry, false, deps);
    expect(closed.display).toBeNull();
    expect(closed.carry.fenceOpen).toBe(false);
  });
});
