/**
 * The BUILT hook scripts, run as Cursor runs them: a child process with the
 * payload on stdin, the event token in argv, and HOME pointed at a temp home.
 *
 * What the host requires of every run is asserted first and carries stderr as
 * its message: exit 0, and stdout either empty or exactly one JSON object.
 */
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { OWNER_MARKER } from '../../src/install.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { withTempHome } from '../helpers/run-hook.ts';
import { FIXTURE, payload, RULE_ID } from '../helpers/store.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = join(HERE, '..', '..', 'scripts');

interface HookRun {
  stdout: string;
  stderr: string;
  status: number;
}

function runHook(script: string, event: string, home: string, input: string): HookRun {
  const result = spawnSync(process.execPath, [join(SCRIPTS_DIR, script), event, OWNER_MARKER], {
    env: { HOME: home, USERPROFILE: home },
    input,
    encoding: 'utf8',
    cwd: home,
  });
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    status: result.status ?? 1,
  };
}

function silent(run: HookRun): void {
  expect(run.status, run.stderr).toBe(0);
  expect(run.stdout).toBe('');
}

function soleObject(run: HookRun): Record<string, unknown> {
  expect(run.status, run.stderr).toBe(0);
  expect(run.stdout).not.toBe('');
  return JSON.parse(run.stdout) as Record<string, unknown>;
}

function seedPolicy(home: string, policy: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(FIXTURE.namespace, FIXTURE.packId, policy);
  } finally {
    db.close();
  }
}

const HOOKS = [
  ['session-start.js', 'sessionStart'],
  ['before-submit-prompt.js', 'beforeSubmitPrompt'],
  ['pre-tool-use.js', 'preToolUse'],
  ['post-tool-use.js', 'postToolUse'],
] as const;

describe.each(HOOKS)('%s fails open', (script, event) => {
  it('on stdin that is not JSON', () => {
    withTempHome((home) => {
      silent(runHook(script, event, home, 'not json'));
    });
  });

  it('on an empty stdin', () => {
    withTempHome((home) => {
      silent(runHook(script, event, home, ''));
    });
  });

  it('on truncated JSON', () => {
    withTempHome((home) => {
      const whole = JSON.stringify(payload(event, { cwd: home, workspace_roots: [home] }));
      silent(runHook(script, event, home, whole.slice(0, Math.floor(whole.length / 2))));
    });
  });

  it('on an oversized stdin that is not JSON', () => {
    withTempHome((home) => {
      silent(runHook(script, event, home, `{"prompt":"${'x'.repeat(4 * 1024 * 1024)}`));
    });
  });

  it('on a stdin that never closes', async () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-cursor-stall-'));
    try {
      const run = await new Promise<HookRun>((resolve) => {
        const child = spawn(process.execPath, [join(SCRIPTS_DIR, script), event, OWNER_MARKER], {
          env: { HOME: home, USERPROFILE: home },
          cwd: home,
        });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
        child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
        // Half a payload and then nothing: stdin stays open until the hook exits.
        child.stdin.write('{"hook_event_name":');
        child.on('close', (status) => {
          resolve({ stdout, stderr, status: status ?? 1 });
        });
      });
      silent(run);
    } finally {
      removeTrees([home]);
    }
  });

  it('on a store that cannot be opened', () => {
    withTempHome((home) => {
      const dataDir = join(home, '.aka', 'data');
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(join(dataDir, 'aka.db'), 'not a database\n'.repeat(64));
      const input = payload(event, {
        cwd: home,
        workspace_roots: [home],
        prompt: `use ${FIXTURE.example}`,
        tool_input: { command: `echo ${FIXTURE.example}` },
        tool_output: FIXTURE.example,
      });
      silent(runHook(script, event, home, JSON.stringify(input)));
    });
  });
});

describe('the built hooks enforce', () => {
  it('preToolUse denies a secret in a Shell command under block', () => {
    withTempHome((home) => {
      seedPolicy(home, 'block');
      const input = payload('preToolUse', {
        cwd: home,
        tool_input: { command: `curl -u "${FIXTURE.example}" x` },
      });
      const output = soleObject(
        runHook('pre-tool-use.js', 'preToolUse', home, JSON.stringify(input)),
      );
      expect(output.permission).toBe('deny');
      expect(String(output.agent_message)).toContain(RULE_ID);
      expectNoEchoOf(String(output.agent_message), FIXTURE.example);
    });
  });

  it('beforeSubmitPrompt stops a prompt carrying a secret under block', () => {
    withTempHome((home) => {
      seedPolicy(home, 'block');
      const input = payload('beforeSubmitPrompt', {
        workspace_roots: [home],
        prompt: `use ${FIXTURE.example}`,
      });
      const output = soleObject(
        runHook('before-submit-prompt.js', 'beforeSubmitPrompt', home, JSON.stringify(input)),
      );
      expect(output.continue).toBe(false);
      expect(String(output.user_message)).toContain(RULE_ID);
    });
  });

  it('a clean call writes nothing', () => {
    withTempHome((home) => {
      seedPolicy(home, 'block');
      const input = payload('preToolUse', { cwd: home });
      silent(runHook('pre-tool-use.js', 'preToolUse', home, JSON.stringify(input)));
    });
  });
});
