// The capture-forward helpers and PreToolUse's hold check in-process, so their
// lines are measured; test/e2e/capture-forward.e2e.test.ts drives the same
// paths through the built hooks.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  ATTACHED_CAPTURE_SETTINGS_FILENAME,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { useLoopbackServer } from '../../../../packages/remote/test/helpers/loopback.ts';
import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  postToolUseForward,
  SESSION_HELD_REASON,
  sessionHoldDenial,
} from '../../src/hooks/capture-forward.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';

const server = useLoopbackServer();
let home: string;
let dataDir: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-claude-capture-unit-'));
  dataDir = join(home, '.aka', 'data');
  mkdirSync(dataDir, { recursive: true });
  vi.stubEnv('HOME', home);
  vi.stubEnv('USERPROFILE', home);
});
afterEach(() => {
  vi.unstubAllEnvs();
  removeTree(home);
});

function settings(body: Record<string, unknown>): void {
  writeFileSync(
    join(dataDir, ATTACHED_CAPTURE_SETTINGS_FILENAME),
    JSON.stringify({ v: 1, ...body }),
  );
}

function modRunning(sessionId: string): void {
  const dir = join(dataDir, 'mod-sessions');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, `${sessionId}.json`),
    JSON.stringify({ v: 1, sessionId, at: Date.now() }),
  );
}

function attach(body: unknown): void {
  server.reply((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  const endpoint = server.origin;
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint, attachedAt: '2026-10-28T10:00:00.000Z' } },
    join(home, '.aka'),
  );
  writeControlPlaneCredential(settingsDir(join(home, '.aka')), {
    specVersion: 1,
    endpoint,
    apiKey: 'not-a-real-key-claude-unit',
  });
}

describe('postToolUseForward', () => {
  it('marks nothing without settings', () => {
    expect(postToolUseForward(dataDir, 's1', undefined)).toBeUndefined();
  });

  it('marks tool output with the cap while the mod is not running', () => {
    settings({ toolOutput: { maxChars: 50 } });
    expect(postToolUseForward(dataDir, 's1', undefined)).toEqual({ maxChars: 50 });
  });

  it("leaves tool output to the session's running mod", () => {
    settings({ toolOutput: { maxChars: 50 } });
    modRunning('s1');
    expect(postToolUseForward(dataDir, 's1', undefined)).toBeUndefined();
  });

  it('marks a repository the settings name even while the mod runs, since only this hook knows the file', () => {
    settings({ toolOutput: { maxChars: 50, repos: ['github.com/acme/app'] } });
    modRunning('s1');
    expect(postToolUseForward(dataDir, 's1', 'github.com/acme/app')).toEqual({ maxChars: 50 });
  });

  it('marks only a repository the settings name', () => {
    settings({ toolOutput: { maxChars: 50, repos: ['github.com/acme/app'] } });
    expect(postToolUseForward(dataDir, 's1', 'github.com/acme/app')).toEqual({ maxChars: 50 });
    expect(postToolUseForward(dataDir, 's1', 'github.com/acme/other')).toBeUndefined();
  });
});

describe('the session hold', () => {
  it('refuses with the deployment reason, or the generic one', async () => {
    settings({ sessionHold: true });
    attach({ held: true, reason: 'Paused for review.' });
    expect(
      (await sessionHoldDenial(dataDir, 's1'))?.hookSpecificOutput.permissionDecisionReason,
    ).toBe('AKA: Paused for review.');
    attach({ held: true });
    expect(
      (await sessionHoldDenial(dataDir, 's1'))?.hookSpecificOutput.permissionDecisionReason,
    ).toBe(`AKA: ${SESSION_HELD_REASON}`);
  });

  it('lets the call go on when the session is not held', async () => {
    settings({ sessionHold: true });
    attach({ held: false });
    expect(await sessionHoldDenial(dataDir, 's1')).toBeNull();
  });

  it('refuses a held session in PreToolUse before anything else, in hook mode only', async () => {
    settings({ sessionHold: true });
    attach({ held: true });
    const input = {
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
      session_id: 's1',
      cwd: home,
      hook_event_name: 'PreToolUse',
    };
    const emitted: HookOutput[] = [];
    const emit = (output: HookOutput): Promise<void> => {
      emitted.push(output);
      return Promise.resolve();
    };

    expect(await runPreToolUse(input, emit, { mode: 'hook' })).toBe('finished');
    expect(emitted).toEqual([
      {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: `AKA: ${SESSION_HELD_REASON}`,
        },
      },
    ]);

    for (const toolInput of [undefined, 'ls', ['ls']]) {
      emitted.length = 0;
      expect(await runPreToolUse({ ...input, tool_input: toolInput }, emit, { mode: 'hook' })).toBe(
        'finished',
      );
      expect(JSON.stringify(emitted), String(toolInput)).toContain(SESSION_HELD_REASON);
    }

    emitted.length = 0;
    await runPreToolUse(input, emit, { mode: 'mod' });
    expect(JSON.stringify(emitted)).not.toContain(SESSION_HELD_REASON);
  });
});
