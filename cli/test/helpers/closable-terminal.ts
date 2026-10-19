import { PassThrough, Writable } from 'node:stream';

import type { TerminalIo } from '../../src/lib/prompter.ts';

export interface ClosableTerminal {
  io: TerminalIo;
  /** Type into the prompt, or `end()` it to close the input the way EOF does. */
  input: PassThrough;
  /** Everything the prompter wrote to stdout so far. */
  written: () => string;
}

/**
 * A terminal whose input a test can type into and then close. Both streams
 * report as TTYs, so the prompter is interactive and readline runs in terminal
 * mode, where Ctrl-D arrives as the byte 0x04 rather than as end-of-stream.
 */
export function closableTerminal(): ClosableTerminal {
  const input = Object.assign(new PassThrough(), { isTTY: true });
  let written = '';
  const output = Object.assign(
    new Writable({
      write(chunk: Buffer, _encoding, done) {
        written += chunk.toString('utf8');
        done();
      },
    }),
    { isTTY: true },
  );
  return {
    io: {
      input: input as unknown as NodeJS.ReadStream,
      output: output as unknown as NodeJS.WriteStream,
      errorOutput: new PassThrough() as unknown as NodeJS.WriteStream,
      signals: {
        once: () => undefined,
        off: () => undefined,
        raise: () => undefined,
      },
    },
    input,
    written: () => written,
  };
}
