// The capture-forward helpers in-process, so their lines are measured;
// capture-forward.e2e.test.ts drives the same paths through the built hooks.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  ATTACHED_CAPTURE_SETTINGS_FILENAME,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { useLoopbackServer } from '../../../../packages/remote/test/helpers/loopback.ts';
import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  denyIfSessionHeld,
  SESSION_HELD_REASON,
  sessionHoldDenial,
  toolOutputForward,
} from '../../src/hooks/capture-forward.ts';

const server = useLoopbackServer();
let home: string;
let dataDir: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-codex-capture-unit-'));
  dataDir = join(home, '.aka', 'data');
  mkdirSync(dataDir, { recursive: true });
});
afterEach(() => {
  removeTree(home);
});

function settings(body: Record<string, unknown>): void {
  writeFileSync(
    join(dataDir, ATTACHED_CAPTURE_SETTINGS_FILENAME),
    JSON.stringify({ v: 1, ...body }),
  );
}

function attach(answer: { status: number; body: unknown }): void {
  server.reply((_req, res) => {
    res.writeHead(answer.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(answer.body));
  });
  const endpoint = server.origin;
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint, attachedAt: '2026-10-28T10:00:00.000Z' } },
    join(home, '.aka'),
  );
  writeControlPlaneCredential(settingsDir(join(home, '.aka')), {
    specVersion: 1,
    endpoint,
    apiKey: 'not-a-real-key-codex-unit',
  });
}

describe('toolOutputForward', () => {
  const input = { cwd: '/nowhere/at/all' };

  it('marks nothing without settings', () => {
    expect(toolOutputForward(dataDir, input, 'Bash', undefined)).toBeUndefined();
  });

  it('marks tool output with the cap the settings name', () => {
    settings({ toolOutput: { maxChars: 50 } });
    expect(toolOutputForward(dataDir, input, 'Bash', undefined)).toEqual({ maxChars: 50 });
  });

  it('marks no apply_patch result when the settings name repositories', () => {
    settings({ toolOutput: { maxChars: 50, repos: ['github.com/acme/app'] } });
    expect(toolOutputForward(dataDir, input, 'apply_patch', undefined)).toBeUndefined();
  });
});

describe('the session hold', () => {
  it('refuses with the deployment reason, or the generic one', async () => {
    settings({ sessionHold: true });
    attach({ status: 200, body: { held: true, reason: 'Paused for review.' } });
    expect(await sessionHoldDenial(dataDir, 's1')).toEqual({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: 'AKA: Paused for review.',
      },
    });
    attach({ status: 200, body: { held: true } });
    expect(
      (await sessionHoldDenial(dataDir, 's1'))?.hookSpecificOutput.permissionDecisionReason,
    ).toBe(`AKA: ${SESSION_HELD_REASON}`);
  });

  it('emits the refusal for a held session and answers true', async () => {
    settings({ sessionHold: true });
    attach({ status: 200, body: { held: true } });
    const emitted: unknown[] = [];
    const held = await denyIfSessionHeld(dataDir, { session_id: 's1' }, (output) => {
      emitted.push(output);
      return Promise.resolve();
    });
    expect(held).toBe(true);
    expect(emitted).toHaveLength(1);
  });

  it('emits nothing and answers false when the session is not held', async () => {
    settings({ sessionHold: true });
    attach({ status: 200, body: { held: false } });
    const emitted: unknown[] = [];
    const held = await denyIfSessionHeld(dataDir, { session_id: 's1' }, (output) => {
      emitted.push(output);
      return Promise.resolve();
    });
    expect(held).toBe(false);
    expect(emitted).toEqual([]);
  });
});
