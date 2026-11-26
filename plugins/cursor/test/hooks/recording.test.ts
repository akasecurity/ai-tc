import { mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as PluginSdkModule from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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
  it('records nothing, and creates nothing, while the directory is absent', () => {
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

  it('keeps a payload that is not JSON as text, and a silent hook as a null output', () => {
    mkdirSync(dir);
    recordHookRun(undefined, 'not json', undefined, dir, AT);
    const recording = only();
    expect(recording.stdin).toBe('not json');
    expect(recording.output).toBeNull();
    expect(recording.event).toBeNull();
  });

  it.skipIf(process.platform === 'win32')('writes each recording owner-only', () => {
    mkdirSync(dir);
    const file = recordHookRun('preToolUse', '{}', undefined, dir, AT) ?? '';
    expect(statSync(file).mode & 0o077).toBe(0);
  });

  it('swallows a failed write rather than failing the hook', () => {
    mkdirSync(dir);
    expect(recordHookRun('preToolUse', '{}', undefined, dir, AT)).toBeDefined();
    // The same name again: the exclusive create fails, and nothing is thrown.
    expect(recordHookRun('preToolUse', '{}', undefined, dir, AT)).toBeUndefined();
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

// The hook calls this after it has decided, inside the body its watchdog races,
// so a throw here would replace the decision with silence.
describe('recordHookRun with a home it cannot resolve', () => {
  it('swallows the failure and records nothing', async () => {
    vi.resetModules();
    vi.doMock('@akasecurity/plugin-sdk', async (importOriginal) => ({
      ...(await importOriginal<typeof PluginSdkModule>()),
      dataDir: () => {
        throw new Error('no home');
      },
    }));
    try {
      const fresh = await import('../../src/hooks/recording.ts');
      expect(fresh.recordHookRun('preToolUse', '{}', denyOutput('blocked'))).toBeUndefined();
    } finally {
      vi.doUnmock('@akasecurity/plugin-sdk');
      vi.resetModules();
    }
  });
});
