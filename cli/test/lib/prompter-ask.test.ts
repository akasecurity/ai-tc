import { once } from 'node:events';
import type { PassThrough } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { terminalPrompter } from '../../src/lib/prompter.ts';
import { closableTerminal } from '../helpers/closable-terminal.ts';

const UNSETTLED = Symbol('unsettled');

/** The promise's value, or UNSETTLED if it has not settled within `ms`. */
async function settledWithin<T>(promise: Promise<T>, ms = 500): Promise<T | typeof UNSETTLED> {
  let timer: NodeJS.Timeout | undefined;
  const expired = new Promise<typeof UNSETTLED>((resolve) => {
    timer = setTimeout(() => {
      resolve(UNSETTLED);
    }, ms);
  });
  try {
    return await Promise.race([promise, expired]);
  } finally {
    clearTimeout(timer);
  }
}

describe('terminalPrompter ask', () => {
  it('resolves to the typed line', async () => {
    const t = closableTerminal();
    const pending = terminalPrompter(t.io).ask('Proceed? [y/N] ');
    t.input.write('yes\n');
    expect(await settledWithin(pending)).toBe('yes');
    expect(t.written()).toContain('Proceed? [y/N] ');
  });

  it('resolves to an empty answer when the input ends before an answer', async () => {
    const t = closableTerminal();
    const pending = terminalPrompter(t.io).ask('Proceed? [y/N] ');
    t.input.end();
    expect(await settledWithin(pending)).toBe('');
  });

  it('resolves to an empty answer on Ctrl-D at an empty prompt', async () => {
    const t = closableTerminal();
    const pending = terminalPrompter(t.io).ask('Proceed? [y/N] ');
    t.input.write('\u0004');
    expect(await settledWithin(pending)).toBe('');
  });

  it.each([
    [
      'end of stream',
      (input: PassThrough) => {
        input.end();
      },
    ],
    [
      'Ctrl-D',
      (input: PassThrough) => {
        input.write('\u0004');
      },
    ],
  ])('ends the question line on %s, so the next line starts fresh', async (_name, close) => {
    const t = closableTerminal();
    const pending = terminalPrompter(t.io).ask('Proceed? [y/N] ');
    close(t.input);
    await settledWithin(pending);
    expect(t.written().endsWith('\n')).toBe(true);
  });

  it('keeps a typed answer when the input ends right after it', async () => {
    const t = closableTerminal();
    const pending = terminalPrompter(t.io).ask('Proceed? [y/N] ');
    t.input.write('yes\n');
    t.input.end();
    expect(await settledWithin(pending)).toBe('yes');
  });

  it('answers a second question empty after the input ended during the first', async () => {
    const t = closableTerminal();
    const prompter = terminalPrompter(t.io);
    const first = prompter.ask('First? [y/N] ');
    t.input.end();
    expect(await settledWithin(first)).toBe('');

    expect(await settledWithin(prompter.ask('Second? [y/N] '))).toBe('');
    expect(t.written().endsWith('Second? [y/N] \n')).toBe(true);
  });

  it('answers empty at once when the input had already ended', async () => {
    const t = closableTerminal();
    t.input.resume();
    t.input.end();
    await once(t.input, 'end');

    expect(await settledWithin(terminalPrompter(t.io).ask('Proceed? [y/N] '))).toBe('');
    expect(t.written()).toBe('Proceed? [y/N] \n');
  });

  it('answers empty at once when the input was destroyed', async () => {
    const t = closableTerminal();
    t.input.destroy();

    expect(await settledWithin(terminalPrompter(t.io).ask('Proceed? [y/N] '))).toBe('');
    expect(t.written()).toBe('Proceed? [y/N] \n');
  });

  it('asks again on the same input after an answer', async () => {
    const t = closableTerminal();
    const prompter = terminalPrompter(t.io);
    const first = prompter.ask('First: ');
    t.input.write('one\n');
    expect(await settledWithin(first)).toBe('one');

    const second = prompter.ask('Second: ');
    t.input.write('two\n');
    expect(await settledWithin(second)).toBe('two');
  });
});
