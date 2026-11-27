import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { HARNESS } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import type * as DataDirModule from '../src/data-dir.ts';
import type { HookRecordingBase } from '../src/hook-recordings.ts';
import { recordHookRun } from '../src/hook-recordings.ts';

let root: string;
let dir: string;
const AT = new Date('2026-11-26T10:00:00.000Z');

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-sdk-recording-'));
  dir = join(root, 'hook-recordings');
});

afterEach(() => {
  removeTrees([root]);
});

function all(): (HookRecordingBase & Record<string, unknown>)[] {
  return readdirSync(dir)
    .sort()
    .map(
      (name) =>
        JSON.parse(readFileSync(join(dir, name), 'utf8')) as HookRecordingBase &
          Record<string, unknown>,
    );
}

describe('recordHookRun', () => {
  it('records nothing, and creates nothing, while the directory is absent', () => {
    expect(recordHookRun(HARNESS.Cursor, 'preToolUse', '{}', {}, { dir, now: AT })).toBeUndefined();
    expect(readdirSync(root)).toEqual([]);
  });

  it('records the time, event and parsed payload with the answer fields beside them', () => {
    mkdirSync(dir);
    const file = recordHookRun(
      HARNESS.Cursor,
      'preToolUse',
      '{"tool_name":"Shell"}',
      { output: null },
      {
        dir,
        now: AT,
      },
    );
    expect(file).toContain('preToolUse');
    expect(all()).toEqual([
      {
        recordedAt: AT.toISOString(),
        harness: HARNESS.Cursor,
        event: 'preToolUse',
        stdin: { tool_name: 'Shell' },
        output: null,
      },
    ]);
  });

  it('keeps a payload that is not JSON as text, and a missing event as null', () => {
    mkdirSync(dir);
    recordHookRun(HARNESS.Cursor, undefined, 'not json', {}, { dir, now: AT });
    const [recording] = all();
    expect(recording?.stdin).toBe('not json');
    expect(recording?.event).toBeNull();
  });

  it('never lets an answer field overwrite a base field', () => {
    mkdirSync(dir);
    recordHookRun(
      HARNESS.Cursor,
      'preToolUse',
      '{"n":1}',
      { harness: 'other', event: 'other', stdin: 'other', recordedAt: 'other', output: null },
      { dir, now: AT },
    );
    expect(all()).toEqual([
      {
        recordedAt: AT.toISOString(),
        harness: HARNESS.Cursor,
        event: 'preToolUse',
        stdin: { n: 1 },
        output: null,
      },
    ]);
  });

  it('keeps every run of the same event in the same millisecond', () => {
    mkdirSync(dir);
    const first = recordHookRun(HARNESS.Cursor, 'preToolUse', '{"n":1}', {}, { dir, now: AT });
    const second = recordHookRun(HARNESS.Cursor, 'preToolUse', '{"n":2}', {}, { dir, now: AT });
    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first).not.toBe(second);
    expect(all().map((r) => r.stdin)).toHaveLength(2);
  });

  it.skipIf(process.platform === 'win32')('writes each recording owner-only', () => {
    mkdirSync(dir);
    const file = recordHookRun(HARNESS.Cursor, 'preToolUse', '{}', {}, { dir, now: AT }) ?? '';
    expect(statSync(file).mode & 0o077).toBe(0);
  });

  it('swallows a failed write rather than failing the hook', () => {
    // A file where the directory should be: it exists, and nothing can be written under it.
    writeFileSync(dir, '');
    expect(recordHookRun(HARNESS.Cursor, 'preToolUse', '{}', {}, { dir, now: AT })).toBeUndefined();
  });
});

// A plugin calls this after its hook has decided, inside the body its watchdog
// races, so a throw here would replace the decision with the fail-open default.
describe('recordHookRun with a home it cannot resolve', () => {
  it('swallows the failure and records nothing', async () => {
    vi.resetModules();
    vi.doMock('../src/data-dir.ts', async (importOriginal) => ({
      ...(await importOriginal<typeof DataDirModule>()),
      dataDir: () => {
        throw new Error('no home');
      },
    }));
    try {
      const fresh = await import('../src/hook-recordings.ts');
      expect(fresh.recordHookRun(HARNESS.Cursor, 'preToolUse', '{}', {})).toBeUndefined();
    } finally {
      vi.doUnmock('../src/data-dir.ts');
      vi.resetModules();
    }
  });
});
