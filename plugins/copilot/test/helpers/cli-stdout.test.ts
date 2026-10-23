/**
 * The model of the CLI's stdout parsing that the e2e suite reads hook runs
 * through. Its cases follow the bullet points of the hooks reference's "How
 * stdout is parsed when progress messages are mixed in" one by one, because a
 * model that drifted from them would let the suite approve a stdout the host
 * reads differently.
 */
import { describe, expect, it } from 'vitest';

import { progressLine } from '../../src/hooks/shared.ts';
import { readCliStdout } from './cli-stdout.ts';

describe('readCliStdout', () => {
  it('removes progress lines and parses what is left as the output', () => {
    const stdout = `${progressLine('first')}${progressLine('second')}{"permissionDecision":"deny","permissionDecisionReason":"r"}`;
    expect(readCliStdout(stdout)).toEqual({
      progress: ['first', 'second'],
      rest: '{"permissionDecision":"deny","permissionDecisionReason":"r"}',
      output: { permissionDecision: 'deny', permissionDecisionReason: 'r' },
    });
  });

  it('reads progress lines alone as NO output, the default behavior', () => {
    expect(readCliStdout(progressLine('only a notice'))).toEqual({
      progress: ['only a notice'],
      rest: '',
      output: undefined,
    });
  });

  it('reads an empty stdout as no output and no progress', () => {
    expect(readCliStdout('')).toEqual({ progress: [], rest: '', output: undefined });
  });

  it('keeps a JSON object that is not a progress message in the output', () => {
    const { progress, output } = readCliStdout('{"type":"other","message":"x"}');
    expect(progress).toEqual([]);
    expect(output).toEqual({ type: 'other', message: 'x' });
  });

  it('does not recognise a progress object spread over several lines', () => {
    // "Multi-line / pretty-printed progress objects are not recognized as
    // progress and will be left in the output stream". Left in, it reaches
    // the parse beside the decision and breaks it, which this model reports
    // as a throw rather than as the no-output the host would quietly fall to.
    const pretty = `${JSON.stringify({ type: 'progress', message: 'm' }, null, 2)}\n{"permissionDecision":"deny"}`;
    expect(() => readCliStdout(pretty)).toThrow();
  });

  it('refuses two decision objects, which the host reads as no output', () => {
    expect(() => readCliStdout('{"a":1}\n{"b":2}')).toThrow();
  });

  it('escapes a newline inside the message, so a progress line stays one line', () => {
    // The property `progressLine` owes: a message with a line break in it is
    // still recognised, and arrives whole.
    const line = progressLine('line one\nline two');
    expect(line.endsWith('\n')).toBe(true);
    expect(line.slice(0, -1)).not.toContain('\n');
    expect(readCliStdout(line).progress).toEqual(['line one\nline two']);
  });
});
