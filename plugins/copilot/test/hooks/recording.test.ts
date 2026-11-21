import { mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import type { HookRecording } from '../../src/hooks/recording.ts';
import { exitCodeFor, recordHookRun } from '../../src/hooks/recording.ts';
import { PROMPT_BLOCK_EXIT_CODE } from '../../src/hooks/shared.ts';

let root: string;
let dir: string;
const AT = new Date('2026-11-21T10:00:00.000Z');

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-recording-'));
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

  it('records the event, the parsed payload, the verdict and its exit code', () => {
    mkdirSync(dir);
    const verdict = { systemMessage: 'flagged' };
    const file = recordHookRun('PreToolUse', '{"tool_name":"run_in_terminal"}', verdict, dir, AT);
    expect(file).toContain('PreToolUse');
    expect(only()).toEqual({
      recordedAt: AT.toISOString(),
      event: 'PreToolUse',
      stdin: { tool_name: 'run_in_terminal' },
      verdict,
      exitCode: 0,
    });
  });

  it('records a prompt block with the exit code it ends in', () => {
    mkdirSync(dir);
    recordHookRun('userPromptSubmitted', '{}', { promptBlock: 'stopped' }, dir, AT);
    expect(only().exitCode).toBe(PROMPT_BLOCK_EXIT_CODE);
  });

  it('keeps a payload that is not JSON as text, and a silent hook as a null verdict', () => {
    mkdirSync(dir);
    recordHookRun(undefined, 'not json', undefined, dir, AT);
    const recording = only();
    expect(recording.stdin).toBe('not json');
    expect(recording.verdict).toBeNull();
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

describe('exitCodeFor', () => {
  it('maps a prompt block to exit 2 and everything else to 0', () => {
    expect(exitCodeFor({ promptBlock: 'x' })).toBe(2);
    expect(exitCodeFor({ systemMessage: 'x' })).toBe(0);
    expect(exitCodeFor(undefined)).toBe(0);
  });
});
