/**
 * The tool-call handler, driven in-process against a real temp home.
 *
 * Nothing is mocked but stderr, which is captured: the store is a real
 * `node:sqlite` file under a throwaway `akaHome`, and every payload is the
 * constructed `preToolUse.json` with its tool input and `cwd` re-pointed.
 *
 * Every raw-value absence check runs AFTER a positive control on the same
 * bytes, because an empty message satisfies every absence check.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { LARGE_INPUT_THRESHOLD_CHARS } from '@akasecurity/plugin-sdk';
import { POINTER_TOKEN_ANCHORED } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { tooLargeToScanMessage } from '../../src/exception-guidance.ts';
import { denyPointerMessage } from '../../src/hooks/pre-tool-use-decision.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import { denyOutput } from '../../src/hooks/shared.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import type { StderrCapture } from '../helpers/stderr-capture.ts';
import { captureStderr } from '../helpers/stderr-capture.ts';
import type { TempStore } from '../helpers/store.ts';
import { FIXTURE, payload, RULE_ID, tempStore } from '../helpers/store.ts';

// A real pointer token, assembled from parts so neither this repository's own
// scanning nor a reader mistakes the source for one.
const POINTER = `${'['.repeat(2)}aka:secret:AA.${'A'.repeat(26)}.${'B'.repeat(16)}${']'.repeat(2)}`;

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

function call(
  toolName: string,
  toolInput: unknown,
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify(
    payload('preToolUse', {
      tool_name: toolName,
      tool_input: toolInput,
      cwd: store.cwd,
      workspace_roots: [store.cwd],
      ...overrides,
    }),
  );
}

async function run(stdin: string, options: { scanWorkerUrl?: URL } = {}): Promise<unknown> {
  return runPreToolUse('preToolUse', stdin, { akaHome: store.akaHome, ...options });
}

function reasonOf(output: unknown): string {
  return String((output as { agent_message?: unknown } | undefined)?.agent_message);
}

it('builds a pointer the schema recognises (the control for the pointer case)', () => {
  expect(POINTER).toMatch(POINTER_TOKEN_ANCHORED);
});

describe('runPreToolUse', () => {
  it('writes nothing for a clean Shell call', async () => {
    store.seedPolicy('block');
    expect(await run(call('Shell', { command: 'ls -la' }))).toBeUndefined();
    expect(stderr.filtered()).toBe('');
    // The control: the store was opened, so the silence is a decision.
    expect(existsSync(join(store.akaHome, 'data', 'aka.db'))).toBe(true);
  });

  it('denies a secret in a Shell command under block, echoing none of it', async () => {
    store.seedPolicy('block');
    const output = await run(call('Shell', { command: `curl -u "${FIXTURE.example}" x` }));
    const reason = reasonOf(output);
    expect(output).toEqual(denyOutput(reason));
    expect(reason).toContain(RULE_ID);
    expect(store.findingRules()).toContain(RULE_ID);
    expectNoEchoOf(reason, FIXTURE.example);
    expectNoEchoOf(stderr.raw(), FIXTURE.example);
  });

  it('denies a secret written to a file under block', async () => {
    store.seedPolicy('block');
    const output = await run(
      call('Write', { file_path: join(store.cwd, 'creds.txt'), contents: FIXTURE.example }),
    );
    expect(reasonOf(output)).toContain(RULE_ID);
    expect(store.findingRules()).toContain(RULE_ID);
  });

  it('denies a secret in an MCP tool’s nested arguments under block', async () => {
    store.seedPolicy('block');
    const output = await run(
      call('MCP:send_message', { channel: 'ops', body: { text: `key ${FIXTURE.example}` } }),
    );
    expect(reasonOf(output)).toContain(RULE_ID);
  });

  it('accepts tool_input as a JSON string', async () => {
    store.seedPolicy('block');
    const output = await run(call('Shell', JSON.stringify({ command: `echo ${FIXTURE.example}` })));
    expect(reasonOf(output)).toContain(RULE_ID);
  });

  it('writes nothing under warn and says so on stderr', async () => {
    store.seedPolicy('warn');
    const output = await run(call('Shell', { command: `echo ${FIXTURE.example}` }));
    expect(output).toBeUndefined();
    const notice = stderr.filtered();
    expect(notice).toContain(RULE_ID);
    expectNoEchoOf(notice, FIXTURE.example);
  });

  it('carries a redact policy out as a block, since no rewrite is emitted', async () => {
    store.seedPolicy('redact');
    const output = await run(
      call('Write', { file_path: join(store.cwd, 'a.txt'), contents: FIXTURE.example }),
    );
    // Either the runtime degraded the redact to the shipped fallback (warn,
    // silence on stdout) or it reached the decision as a redact, which is a
    // deny. What must never happen is an output that is not a deny.
    if (output !== undefined) expect(output).toEqual(denyOutput(reasonOf(output)));
    expect(store.findingRules()).toContain(RULE_ID);
  });

  it('denies a vault pointer in a Shell command before opening the store', async () => {
    const output = await run(call('Shell', { command: `echo ${POINTER}` }));
    expect(output).toEqual(denyOutput(denyPointerMessage('Shell')));
    expect(existsSync(store.akaHome)).toBe(false);
  });

  it('denies a field too large to scan in time', async () => {
    store.seedPolicy('block');
    const absent = pathToFileURL(join(store.root, 'no-worker-here', 'scan-worker.js'));
    const output = await run(call('Shell', { command: `echo ${LARGE}` }), {
      scanWorkerUrl: absent,
    });
    expect(output).toEqual(denyOutput(tooLargeToScanMessage('Shell call')));
  });

  it('returns before the store opens for a tool with nothing to scan', async () => {
    expect(await run(call('Read', { path: '/etc/hosts' }))).toBeUndefined();
    expect(existsSync(store.akaHome)).toBe(false);
  });

  it('declines a payload for another event', async () => {
    store.seedPolicy('block');
    const stdin = call('Shell', { command: `echo ${FIXTURE.example}` });
    expect(await runPreToolUse('postToolUse', stdin, { akaHome: store.akaHome })).toBeUndefined();
    const relabelled = call(
      'Shell',
      { command: `echo ${FIXTURE.example}` },
      { hook_event_name: 'beforeShellExecution' },
    );
    expect(await run(relabelled)).toBeUndefined();
  });

  it('declines stdin that is not a JSON object', async () => {
    expect(await run('not json')).toBeUndefined();
    expect(await run('[]')).toBeUndefined();
  });

  it('fails open with a stderr warning when the store cannot be opened', async () => {
    store.corrupt();
    const output = await run(call('Shell', { command: `echo ${FIXTURE.example}` }));
    expect(output).toBeUndefined();
    expect(stderr.filtered()).toContain('could not open its local store');
  });
});
