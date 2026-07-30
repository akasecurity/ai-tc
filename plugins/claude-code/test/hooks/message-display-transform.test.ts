import { existsSync, mkdtempSync, readFileSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { DetectionCategory, POINTER_TOKEN_ANCHORED } from '@akasecurity/schema';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { DisplayCarry, DisplayDeps } from '../../src/hooks/message-display-transform.ts';
import {
  carryFilePath,
  EMPTY_CARRY,
  finalizeCarry,
  loadCarry,
  MAX_POINTER_LEN,
  saveCarry,
  transformDelta,
} from '../../src/hooks/message-display-transform.ts';

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

// Full mode with a spied reveal and no descriptor, so a masked fallback
// renders as the bare category badge.
function fullDeps(revealValue = 'RAW-VALUE'): {
  deps: DisplayDeps;
  reveal: ReturnType<typeof vi.fn>;
} {
  const reveal = vi.fn(() => Promise.resolve<string | null>(revealValue));
  return {
    deps: { mode: 'full', maxRevealsPerMessage: 99, describe: () => Promise.resolve(null), reveal },
    reveal,
  };
}

const tmpDirs: string[] = [];
function makeDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aka-display-carry-'));
  tmpDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of tmpDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

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
    expect(result.carry).toEqual({ ...EMPTY_CARRY, lineSeen: true });
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
      true,
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
    expect(first.carry.fence).toEqual({ char: '`', len: 3 });

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

  it('masks when the quoted line continues from an earlier delta', async () => {
    const { deps, reveal } = fullDeps();
    const first = await transformDelta('> the secret was ', EMPTY_CARRY, false, deps);
    expect(first.display).toBeNull();
    expect(first.carry.lineQuoted).toBe(true);

    const second = await transformDelta(`${POINTER}\n`, first.carry, true, deps);
    expect(second.display).toBe('[scrubbed:secret]\n');
    expect(reveal).not.toHaveBeenCalled();
  });

  it('reveals again on the line after a quoted line', async () => {
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.resolve('RAW') });
    const result = await transformDelta(`> quoted\nplain ${POINTER}`, EMPTY_CARRY, false, deps);
    expect(result.display).toBe('> quoted\nplain RAW [scrubbed:secret]');
  });
});

describe('transformDelta — CommonMark fence shape', () => {
  it('treats ``` inside a ````-opened fence as content, closing only on ````', async () => {
    const { deps, reveal } = fullDeps();
    const text = `\`\`\`\`markdown\nExample:\n\`\`\`\n${POINTER}\n\`\`\`\n\`\`\`\`\nplain ${POINTER}\n`;
    const result = await transformDelta(text, EMPTY_CARRY, true, deps);
    expect(result.display).toBe(
      '````markdown\nExample:\n```\n[scrubbed:secret]\n```\n````\n' +
        'plain RAW-VALUE [scrubbed:secret]\n',
    );
    expect(reveal).toHaveBeenCalledTimes(1);
  });

  it('masks inside a tilde fence', async () => {
    const { deps, reveal } = fullDeps();
    const text = `~~~\nexport KEY=${POINTER}\n~~~\nplain ${POINTER}`;
    const result = await transformDelta(text, EMPTY_CARRY, true, deps);
    expect(result.display).toBe(
      '~~~\nexport KEY=[scrubbed:secret]\n~~~\nplain RAW-VALUE [scrubbed:secret]',
    );
    expect(reveal).toHaveBeenCalledTimes(1);
  });

  it('never closes a tilde fence with backticks', async () => {
    const { deps, reveal } = fullDeps();
    const text = `~~~\n\`\`\`\n${POINTER}\n~~~\nplain ${POINTER}`;
    const result = await transformDelta(text, EMPTY_CARRY, true, deps);
    expect(result.display).toBe(
      '~~~\n```\n[scrubbed:secret]\n~~~\nplain RAW-VALUE [scrubbed:secret]',
    );
    expect(reveal).toHaveBeenCalledTimes(1);
  });

  it('registers a fence opener split across deltas and masks inside it', async () => {
    const { deps, reveal } = fullDeps();

    const first = await transformDelta('``', EMPTY_CARRY, false, deps);
    expect(first.display).toBe('');
    expect(first.carry.tail).toBe('``');

    const second = await transformDelta('`\ncode with ` inside\n', first.carry, false, deps);
    expect(second.display).toBe('```\ncode with ` inside\n');
    expect(second.carry.fence).toEqual({ char: '`', len: 3 });

    const third = await transformDelta(`${POINTER}\n\`\`\`\nplain\n`, second.carry, true, deps);
    expect(third.display).toBe('[scrubbed:secret]\n```\nplain\n');
    expect(third.carry.fence).toBeNull();
    expect(reveal).not.toHaveBeenCalled();
  });

  it('never toggles a fence on a mid-line marker run', async () => {
    const { deps, reveal } = fullDeps();
    const result = await transformDelta(`x \`\`\` y \`\`\` ${POINTER}`, EMPTY_CARRY, true, deps);
    expect(result.display).toBe('x ``` y ``` RAW-VALUE [scrubbed:secret]');
    expect(reveal).toHaveBeenCalledTimes(1);
  });

  it('holds a short trailing marker run for the next delta', async () => {
    const result = await transformDelta('text ```', EMPTY_CARRY, false, makeDeps());
    expect(result.display).toBe('text ');
    expect(result.carry.tail).toBe('```');
  });

  it('flushes an oversized trailing marker run instead of holding it', async () => {
    const result = await transformDelta('`'.repeat(9), EMPTY_CARRY, false, makeDeps());
    expect(result.display).toBeNull();
    expect(result.carry.tail).toBe('');
    expect(result.carry.fence).toEqual({ char: '`', len: 9 });
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

  it('keeps the longest valid pointer well under the hold bound', () => {
    const longestCategory = DetectionCategory.options.reduce((a, b) =>
      b.length > a.length ? b : a,
    );
    const longest = `[[aka:${longestCategory}:${'A'.repeat(7)}.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
    expect(POINTER_TOKEN_ANCHORED.test(longest)).toBe(true);
    expect(longest.length).toBeLessThanOrEqual(MAX_POINTER_LEN - 8);
  });
});

describe('transformDelta — off mode', () => {
  it('always returns null display and an empty carry', async () => {
    const dirty: DisplayCarry = {
      tail: '[[aka:se',
      fence: { char: '`', len: 3 },
      tickOpen: true,
      lineQuoted: true,
      lineSeen: true,
      lineIndent: 2,
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
    expect(opened.carry.fence).toEqual({ char: '`', len: 3 });

    const closed = await transformDelta('\n```\nafter', opened.carry, false, deps);
    expect(closed.display).toBeNull();
    expect(closed.carry.fence).toBeNull();
  });
});

describe('carry store', () => {
  it('keys carry files per session, so another session cannot clobber a held tail', async () => {
    const dir = makeDir();
    const deps = makeDeps();
    const keysA = { blockKey: 'sess-a/m1/0', messageKey: 'sess-a/m1' };
    const keysB = { blockKey: 'sess-b/m9/0', messageKey: 'sess-b/m9' };
    const fileA = carryFilePath(dir, 'sess-a');
    const fileB = carryFilePath(dir, 'sess-b');
    expect(fileA).not.toBe(fileB);

    const cut = 18;
    const first = await transformDelta(
      `The key is ${POINTER.slice(0, cut)}`,
      EMPTY_CARRY,
      false,
      deps,
    );
    expect(first.display).toBe('The key is ');
    expect(first.carry.tail).toBe(POINTER.slice(0, cut));
    saveCarry(fileA, keysA, first.carry);

    // A concurrent session saves and finalizes without touching A's file.
    const other = await transformDelta('other text', EMPTY_CARRY, false, deps);
    saveCarry(fileB, keysB, other.carry);
    finalizeCarry(fileB, keysB, EMPTY_CARRY);
    expect(existsSync(fileB)).toBe(false);

    // Session A's held tail survives and completes: no screen text is lost.
    const restored = loadCarry(fileA, keysA);
    expect(restored.tail).toBe(POINTER.slice(0, cut));
    const second = await transformDelta(`${POINTER.slice(cut)} done`, restored, false, deps);
    expect(second.display).toBe(`${BADGE} done`);
  });

  it('finalize is key-checked: a stale final never deletes a newer block state', () => {
    const dir = makeDir();
    const file = carryFilePath(dir, 's');
    const newer = { blockKey: 's/m2/0', messageKey: 's/m2' };
    saveCarry(file, newer, { ...EMPTY_CARRY, tail: '[[aka:se' });

    finalizeCarry(file, { blockKey: 's/m1/0', messageKey: 's/m1' }, EMPTY_CARRY);
    expect(loadCarry(file, newer).tail).toBe('[[aka:se');

    finalizeCarry(file, newer, EMPTY_CARRY);
    expect(existsSync(file)).toBe(false);
    expect(loadCarry(file, newer)).toEqual(EMPTY_CARRY);
  });

  it('caps reveals per message: the count survives block finals within one message', async () => {
    const dir = makeDir();
    const file = carryFilePath(dir, 's');
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.resolve('RAW') });
    const keys0 = { blockKey: 's/m/0', messageKey: 's/m' };
    const keys1 = { blockKey: 's/m/1', messageKey: 's/m' };

    const block0 = await transformDelta(
      `${POINTER} and ${POINTER}`,
      loadCarry(file, keys0),
      true,
      deps,
    );
    expect(block0.carry.revealedCount).toBe(2);
    finalizeCarry(file, keys0, block0.carry);

    const carry1 = loadCarry(file, keys1);
    expect(carry1.revealedCount).toBe(2);
    expect(carry1.tail).toBe('');
    const block1 = await transformDelta(`third ${POINTER}`, carry1, false, deps);
    expect(block1.display).toBe(`third ${BADGE}`);
    expect(block1.carry.revealedCount).toBe(2);

    // A new message starts a fresh count.
    const nextMessage = loadCarry(file, { blockKey: 's/m2/0', messageKey: 's/m2' });
    expect(nextMessage.revealedCount).toBe(0);
  });

  it('never persists a revealed value in the carry', async () => {
    const dir = makeDir();
    const file = carryFilePath(dir, 's');
    const keys = { blockKey: 's/m/0', messageKey: 's/m' };
    const deps = makeDeps({ mode: 'full', reveal: () => Promise.resolve('RAW-SENTINEL') });

    const result = await transformDelta(`key ${POINTER} more [[aka:se`, EMPTY_CARRY, false, deps);
    expect(result.display).toContain('RAW-SENTINEL');
    expect(JSON.stringify(result.carry)).not.toContain('RAW-SENTINEL');

    saveCarry(file, keys, result.carry);
    expect(readFileSync(file, 'utf8')).not.toContain('RAW-SENTINEL');
    finalizeCarry(file, keys, result.carry);
    expect(readFileSync(file, 'utf8')).not.toContain('RAW-SENTINEL');
  });

  it('sanitizes hostile session ids into a safe basename', () => {
    const dir = makeDir();
    const file = carryFilePath(dir, '../evil/../../id');
    expect(dirname(file)).toBe(dir);
    expect(file).not.toContain('..');
  });

  it('reaps stale carry files on save', () => {
    const dir = makeDir();
    const staleFile = carryFilePath(dir, 'old-session');
    saveCarry(
      staleFile,
      { blockKey: 'o/m/0', messageKey: 'o/m' },
      { ...EMPTY_CARRY, tail: '[[aka:se' },
    );
    const past = new Date(Date.now() - 20 * 60 * 1000);
    utimesSync(staleFile, past, past);

    const file = carryFilePath(dir, 'fresh');
    saveCarry(file, { blockKey: 'f/m/0', messageKey: 'f/m' }, EMPTY_CARRY);
    expect(existsSync(staleFile)).toBe(false);
    expect(existsSync(file)).toBe(true);
  });
});
