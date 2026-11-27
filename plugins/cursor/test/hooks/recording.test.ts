// The SDK owns when a recording is written and how (see plugin-sdk's
// hook-recordings suite); these cases pin what this plugin puts in one.
import { mkdirSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { HARNESS } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import type { HookRecording } from '../../src/hooks/recording.ts';
import { answerAndRecord, recordHookRun } from '../../src/hooks/recording.ts';
import { denyOutput } from '../../src/hooks/shared.ts';

let root: string;
let dir: string;
const AT = new Date('2026-11-26T10:00:00.000Z');

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-cursor-recording-'));
  dir = join(root, 'hook-recordings');
});

afterEach(() => {
  removeTrees([root]);
});

function only(): HookRecording {
  const files = readdirSync(dir);
  expect(files).toHaveLength(1);
  return JSON.parse(readFileSync(join(dir, files[0] ?? ''), 'utf8')) as HookRecording;
}

describe('recordHookRun', () => {
  it('records nothing while the directory is absent', () => {
    expect(recordHookRun('preToolUse', '{}', undefined, dir, AT)).toBeUndefined();
    expect(readdirSync(root)).toEqual([]);
  });

  it('records the event, the parsed payload and the output', () => {
    mkdirSync(dir);
    const output = denyOutput('blocked');
    const file = recordHookRun('preToolUse', '{"tool_name":"Shell"}', output, dir, AT);
    expect(file).toContain('preToolUse');
    expect(only()).toEqual({
      recordedAt: AT.toISOString(),
      harness: HARNESS.Cursor,
      event: 'preToolUse',
      stdin: { tool_name: 'Shell' },
      output,
    });
  });

  it('records a prompt stop as written', () => {
    mkdirSync(dir);
    const output = { continue: false as const, user_message: 'stopped' };
    recordHookRun('beforeSubmitPrompt', '{}', output, dir, AT);
    expect(only().output).toEqual(output);
  });
});

describe('answerAndRecord', () => {
  it('returns the handler answer and records it with the event and stdin', async () => {
    mkdirSync(dir);
    const output = denyOutput('blocked');
    const answer = await answerAndRecord(
      () => Promise.resolve(output),
      'preToolUse',
      '{"tool_name":"Shell"}',
      dir,
    );
    expect(answer).toBe(output);
    const recording = only();
    expect([recording.event, recording.stdin, recording.output]).toEqual([
      'preToolUse',
      { tool_name: 'Shell' },
      output,
    ]);
  });

  it('returns silence unchanged and records it as null', async () => {
    mkdirSync(dir);
    expect(
      await answerAndRecord(() => Promise.resolve(undefined), 'sessionStart', '{}', dir),
    ).toBeUndefined();
    expect(only().output).toBeNull();
  });
});
