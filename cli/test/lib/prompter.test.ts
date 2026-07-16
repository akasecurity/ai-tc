import { describe, expect, it } from 'vitest';

import type { HiddenInputState } from '../../src/lib/prompter.ts';
import { processHiddenChar } from '../../src/lib/prompter.ts';

function feed(chars: string): HiddenInputState {
  let state: HiddenInputState = { value: '', esc: 'none' };
  for (const ch of chars) state = processHiddenChar(state, ch);
  return state;
}

describe('processHiddenChar', () => {
  it('accumulates printable characters', () => {
    expect(feed('s3cret!').value).toBe('s3cret!');
  });

  it('submits on Enter (both CR and LF)', () => {
    expect(feed('abc\r')).toMatchObject({ value: 'abc', done: 'submit' });
    expect(feed('abc\n')).toMatchObject({ value: 'abc', done: 'submit' });
  });

  it('cancels on Ctrl+C', () => {
    expect(feed('ab\u0003').done).toBe('cancel');
  });

  it('backspace removes the last character (DEL and BS)', () => {
    expect(feed('abcd\u007f\u007f').value).toBe('ab');
    expect(feed('ab\b').value).toBe('a');
    expect(feed('\u007f').value).toBe(''); // backspace on empty is a no-op
  });

  it('drops other C0 control bytes — they never join the secret', () => {
    expect(feed('a\tb\u0000c\u000bd').value).toBe('abcd');
  });

  it('swallows a whole arrow-key escape sequence, not just the ESC byte', () => {
    // Up arrow is ESC [ A — the '[' and 'A' are printable and would silently
    // corrupt the hidden value if only the ESC were dropped.
    expect(feed('ab\u001b[Acd').value).toBe('abcd');
    // Longer CSI with parameters (e.g. ESC [ 1 ; 5 C — ctrl+right).
    expect(feed('x\u001b[1;5Cy').value).toBe('xy');
  });

  it('ignores input after done', () => {
    const submitted = feed('a\rZZZ');
    expect(submitted).toMatchObject({ value: 'a', done: 'submit' });
  });
});
