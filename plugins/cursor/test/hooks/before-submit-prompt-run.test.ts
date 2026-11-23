/**
 * The prompt handler, driven in-process against a real temp home.
 */
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { LARGE_INPUT_THRESHOLD_CHARS } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { tooLargeToScanMessage } from '../../src/exception-guidance.ts';
import { runBeforeSubmitPrompt } from '../../src/hooks/before-submit-prompt-run.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import type { StderrCapture } from '../helpers/stderr-capture.ts';
import { captureStderr } from '../helpers/stderr-capture.ts';
import type { TempStore } from '../helpers/store.ts';
import { FIXTURE, payload, RULE_ID, tempStore } from '../helpers/store.ts';

const LARGE = `${'lorem ipsum dolor sit amet '.repeat(Math.ceil(LARGE_INPUT_THRESHOLD_CHARS / 27))}end`;

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

function prompt(text: unknown, overrides: Record<string, unknown> = {}): string {
  return JSON.stringify(
    payload('beforeSubmitPrompt', { prompt: text, workspace_roots: [store.cwd], ...overrides }),
  );
}

async function run(stdin: string, options: { scanWorkerUrl?: URL } = {}): Promise<unknown> {
  return runBeforeSubmitPrompt('beforeSubmitPrompt', stdin, {
    akaHome: store.akaHome,
    ...options,
  });
}

function messageOf(output: unknown): string {
  return String((output as { user_message?: unknown } | undefined)?.user_message);
}

describe('runBeforeSubmitPrompt', () => {
  it('records a clean prompt and writes nothing', async () => {
    store.seedPolicy('block');
    expect(await run(prompt('List the files in this project.'))).toBeUndefined();
    expect(store.eventTypes()).toContain('prompt');
    expect(stderr.filtered()).toBe('');
  });

  it('stops a prompt carrying a secret under block, echoing none of it', async () => {
    store.seedPolicy('block');
    const output = await run(prompt(`use ${FIXTURE.example} for the call`));
    const message = messageOf(output);
    expect(output).toEqual({ continue: false, user_message: message });
    expect(message).toContain(RULE_ID);
    expect(store.findingRules()).toContain(RULE_ID);
    expectNoEchoOf(message, FIXTURE.example);
  });

  it('lets a flagged prompt through under warn and says so on stderr', async () => {
    store.seedPolicy('warn');
    expect(await run(prompt(`use ${FIXTURE.example}`))).toBeUndefined();
    const notice = stderr.filtered();
    expect(notice).toContain(RULE_ID);
    expectNoEchoOf(notice, FIXTURE.example);
  });

  it('stops a prompt too large to scan in time', async () => {
    store.seedPolicy('block');
    const absent = pathToFileURL(join(store.root, 'no-worker-here', 'scan-worker.js'));
    const output = await run(prompt(LARGE), { scanWorkerUrl: absent });
    expect(output).toEqual({ continue: false, user_message: tooLargeToScanMessage('prompt') });
  });

  it('declines an empty or missing prompt, and another event', async () => {
    expect(await run(prompt(''))).toBeUndefined();
    expect(await run(prompt(42))).toBeUndefined();
    expect(
      await runBeforeSubmitPrompt('preToolUse', prompt(`use ${FIXTURE.example}`), {
        akaHome: store.akaHome,
      }),
    ).toBeUndefined();
  });

  it('fails open with a stderr warning when the store cannot be opened', async () => {
    store.corrupt();
    expect(await run(prompt(`use ${FIXTURE.example}`))).toBeUndefined();
    expect(stderr.filtered()).toContain('could not open its local store');
  });
});
