/**
 * The tool-result handler, driven in-process against a real temp home. It
 * records and reports; it never writes to stdout.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { runPostToolUse } from '../../src/hooks/post-tool-use-run.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import type { StderrCapture } from '../helpers/stderr-capture.ts';
import { captureStderr } from '../helpers/stderr-capture.ts';
import type { TempStore } from '../helpers/store.ts';
import { FIXTURE, payload, RULE_ID, tempStore } from '../helpers/store.ts';

let store: TempStore;
let stderr: StderrCapture;

beforeEach(() => {
  store = tempStore();
  stderr = captureStderr();
});

afterEach(() => {
  vi.restoreAllMocks();
  store.cleanup();
});

function result(output: unknown, overrides: Record<string, unknown> = {}): string {
  return JSON.stringify(
    payload('postToolUse', { tool_output: output, cwd: store.cwd, ...overrides }),
  );
}

async function run(stdin: string): Promise<unknown> {
  return runPostToolUse('postToolUse', stdin, { akaHome: store.akaHome });
}

describe('runPostToolUse', () => {
  it('records a flagged result, writes nothing, and says so on stderr', async () => {
    store.seedPolicy('block');
    expect(await run(result(`TWILIO=${FIXTURE.example}`))).toBeUndefined();
    expect(store.findingRules()).toContain(RULE_ID);
    expect(store.eventTypes()).toContain('response');
    const notice = stderr.filtered();
    expect(notice).toContain(RULE_ID);
    expect(notice).toContain('reached the model unchanged');
    expectNoEchoOf(notice, FIXTURE.example);
  });

  it('scans a structured result by its string leaves', async () => {
    store.seedPolicy('warn');
    expect(await run(result({ rows: [{ value: FIXTURE.example }] }))).toBeUndefined();
    expect(store.findingRules()).toContain(RULE_ID);
  });

  it('records nothing for a clean result', async () => {
    store.seedPolicy('block');
    expect(await run(result('total 0'))).toBeUndefined();
    expect(store.findingRules()).toEqual([]);
    expect(stderr.filtered()).toBe('');
  });

  it('returns before the store opens for an empty result or another event', async () => {
    expect(await run(result(''))).toBeUndefined();
    expect(
      await runPostToolUse('preToolUse', result(FIXTURE.example), { akaHome: store.akaHome }),
    ).toBeUndefined();
    expect(stderr.filtered()).toBe('');
  });
});
