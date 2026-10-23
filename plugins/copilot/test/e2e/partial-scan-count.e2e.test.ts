/**
 * A partial scan is counted in the hook fail-open tally through the BUILT hooks.
 *
 * The handler suites inject the counter, so they show the decision and nothing
 * about the count reaching disk: the default counter is a detached child
 * resolved as a sibling of the running script, which under vitest is a source
 * path with no such sibling. Here the built hook runs under a throwaway home and
 * the tally it leaves is read back — the same file `aka status` renders.
 *
 * Each case also pins what the host sees, exit code and stdout, since counting
 * must change neither: on the CLI the hook output stays empty, with the notice
 * carried as a progress line the host strips before parsing, and on VS Code
 * stdout carries only the notice it carried before.
 *
 * A count is written by a DETACHED child the hook does not wait on, so it is
 * awaited rather than read straight after the hook exits. "Counts nothing" is
 * shown by ordering: the scanned-in-full run goes first and a run that does
 * count goes second, so a stray count from the first would have landed long
 * before the second's settles at exactly one.
 */
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { LARGE_INPUT_THRESHOLD_CHARS, readHookFailOpens } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  unscannedPastWalkLimitsMessage,
  unscannedWorkerUnavailableMessage,
} from '../../src/exception-guidance.ts';
import { readCliStdout } from '../helpers/cli-stdout.ts';

// test/e2e -> plugins/copilot
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');
const MANIFEST = join(PLUGIN_ROOT, 'plugin.json');

const SESSION_ID = 'c1779e76-9889-419b-ab12-f7bb8a957e15';
const DELIVERED = 'the output already reached the model unchanged';
const FILLER = 'lorem ipsum dolor sit amet '.repeat(Math.ceil(LARGE_INPUT_THRESHOLD_CHARS / 27));

interface HookRun {
  stdout: string;
  stderr: string;
  status: number | null;
}

let root: string;
let home: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-partial-scan-'));
  home = join(root, 'home');
  mkdirSync(home);
});

afterEach(() => {
  removeTree(root);
});

function runScript(
  script: string,
  event: string,
  payload: unknown,
  scriptsDir: string = SCRIPTS_DIR,
): HookRun {
  const result = spawnSync(process.execPath, [join(scriptsDir, script), event, MANIFEST], {
    env: { HOME: home, USERPROFILE: home },
    input: JSON.stringify(payload),
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    timeout: 60_000,
  });
  return { stdout: result.stdout, stderr: result.stderr, status: result.status };
}

/** A copy of the build with the scan worker removed: an install that never shipped one. */
function scriptsWithoutWorker(): string {
  const scriptsDir = join(root, 'scripts');
  cpSync(SCRIPTS_DIR, scriptsDir, { recursive: true });
  rmSync(join(scriptsDir, 'scan-worker.js'));
  expect(existsSync(join(scriptsDir, 'scan-worker.js'))).toBe(false);
  return scriptsDir;
}

function tally(): number {
  return readHookFailOpens(join(home, '.aka', 'data'))?.failOpens ?? 0;
}

/** Wait for the detached count to land at `expected`, then hold there. */
async function expectTallySettlesAt(expected: number): Promise<void> {
  await vi.waitFor(
    () => {
      expect(tally()).toBe(expected);
    },
    { timeout: 15_000, interval: 50 },
  );
  await new Promise((resolve) => setTimeout(resolve, 500));
  expect(tally()).toBe(expected);
}

function nested(): unknown {
  let deep: unknown = 'nothing sensitive at the bottom';
  for (let i = 0; i < 10; i += 1) deep = { k: deep };
  return { shallow: 'nothing here', deep };
}

const DIALECTS = [
  {
    kind: 'cli',
    event: 'postToolUse',
    promptEvent: 'userPromptSubmitted',
    tool: 'bash',
    envelope: { sessionId: SESSION_ID, timestamp: 1788547866483, cwd: '/tmp' },
    result: (toolResult: unknown) => ({
      toolName: 'bash',
      toolArgs: { command: 'cat x' },
      toolResult,
    }),
    text: (text: string) => ({ resultType: 'success', textResultForLlm: text }),
  },
  {
    kind: 'vscode',
    event: 'PostToolUse',
    promptEvent: 'UserPromptSubmit',
    tool: 'run_in_terminal',
    envelope: { hook_event_name: 'PostToolUse', session_id: SESSION_ID, cwd: '/tmp' },
    result: (toolResponse: unknown) => ({
      tool_name: 'run_in_terminal',
      tool_input: { command: 'cat x' },
      tool_response: toolResponse,
    }),
    text: (text: string) => text,
  },
] as const;

describe.each(DIALECTS)(
  'the built hooks count a partial scan [$kind]',
  (d) => {
    const isCli = d.kind === 'cli';
    const toolPayload = (response: unknown): Record<string, unknown> => ({
      ...d.envelope,
      ...d.result(response),
    });

    /**
     * What the host reads on stdout: on the CLI no output, with the notice as a
     * progress line beside it; on VS Code one note.
     */
    function expectNotice(run: HookRun, message: string): void {
      expect(run.status, run.stderr).toBe(0);
      if (isCli) {
        const { output, progress } = readCliStdout(run.stdout);
        expect(output).toBeUndefined();
        expect(progress).toContain(message);
        expect(run.stderr).toContain(message);
      } else {
        expect(JSON.parse(run.stdout)).toEqual({ systemMessage: message });
      }
    }

    it('counts nothing for a result scanned in full, and one for a result the walk cut', async () => {
      const full = runScript('post-tool-use.js', d.event, toolPayload(d.text('nothing sensitive')));
      expect(full.status, full.stderr).toBe(0);
      // The store opened and the result was captured: the zero below is a scan
      // that found nothing to count, not a hook that never ran.
      expect(existsSync(join(home, '.aka', 'data', 'aka.db'))).toBe(true);

      const cut = runScript('post-tool-use.js', d.event, toolPayload(nested()));
      expectNotice(cut, unscannedPastWalkLimitsMessage(`${d.tool} result`, DELIVERED));

      await expectTallySettlesAt(1);
    });

    it('counts one for a result too large to scan, with no worker to scan it', async () => {
      const run = runScript(
        'post-tool-use.js',
        d.event,
        toolPayload(d.text(FILLER)),
        scriptsWithoutWorker(),
      );
      expectNotice(run, unscannedWorkerUnavailableMessage(`${d.tool} result`, DELIVERED));

      await expectTallySettlesAt(1);
    });

    it('counts one for a prompt too large to scan, and none for one scanned in full', async () => {
      const envelope = isCli ? d.envelope : { ...d.envelope, hook_event_name: d.promptEvent };
      const scriptsDir = scriptsWithoutWorker();

      const small = runScript(
        'user-prompt-submit.js',
        d.promptEvent,
        {
          ...envelope,
          prompt: 'nothing to see here',
        },
        scriptsDir,
      );
      expect(small.status, small.stderr).toBe(0);

      const large = runScript(
        'user-prompt-submit.js',
        d.promptEvent,
        {
          ...envelope,
          prompt: FILLER,
        },
        scriptsDir,
      );
      expectNotice(
        large,
        unscannedWorkerUnavailableMessage('prompt', 'it was sent to the model unchanged'),
      );

      await expectTallySettlesAt(1);
    });
  },
  120_000,
);
