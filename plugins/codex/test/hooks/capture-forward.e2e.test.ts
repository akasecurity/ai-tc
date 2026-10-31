import { execFile } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import {
  applyOnboarding,
  ATTACHED_CAPTURE_SETTINGS_FILENAME,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { useLoopbackServer } from '../../../../packages/remote/test/helpers/loopback.ts';
import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { SESSION_HELD_REASON } from '../../src/hooks/capture-forward.ts';

const SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts');

let home: string;
const server = useLoopbackServer();
let seen: string[];

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-codex-capture-'));
  mkdirSync(join(home, '.aka', 'data'), { recursive: true });
  seen = [];
});
afterEach(() => {
  removeTree(home);
});

function hook(name: string, payload: unknown): Promise<{ stdout: string; ms: number }> {
  const started = performance.now();
  return new Promise((resolve) => {
    const child = execFile(
      process.execPath,
      [join(SCRIPTS, `${name}.js`)],
      { env: { HOME: home, USERPROFILE: home }, encoding: 'utf8', timeout: 30_000 },
      (_err, stdout) => {
        resolve({ stdout, ms: performance.now() - started });
      },
    );
    child.stdin?.end(JSON.stringify(payload));
  });
}

function captureSettings(settings: Record<string, unknown>): void {
  writeFileSync(
    join(home, '.aka', 'data', ATTACHED_CAPTURE_SETTINGS_FILENAME),
    JSON.stringify({ v: 1, ...settings }),
  );
}

function attach(answer: (respond: (status: number, body: unknown) => void) => void) {
  server.reply((req, res) => {
    seen.push(`${req.method ?? ''} ${req.url ?? ''}`);
    answer((status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    });
  });
  const endpoint = server.origin;
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint, attachedAt: '2026-10-28T10:00:00.000Z' } },
    join(home, '.aka'),
  );
  writeControlPlaneCredential(settingsDir(join(home, '.aka')), {
    specVersion: 1,
    endpoint,
    apiKey: 'not-a-real-key-codex',
  });
}

const bash = (command: string) => ({
  tool_name: 'Bash',
  tool_input: { command },
  session_id: 'sess-hold',
  cwd: home,
  hook_event_name: 'PreToolUse',
});

describe('the session hold, through the built PreToolUse hook', () => {
  it('refuses the call with the deployment reason when the session is held', async () => {
    captureSettings({ sessionHold: true });
    attach((respond) => {
      respond(200, { held: true, reason: 'Paused for review.' });
    });
    const run = await hook('pre-tool-use', bash('ls'));
    const out = JSON.parse(run.stdout) as {
      hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
    };
    expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput.permissionDecisionReason).toBe('AKA: Paused for review.');
    expect(seen).toEqual(['GET /v1/plugin/sessions/sess-hold/hold']);
  });

  it('names a generic reason when the deployment gives none', async () => {
    captureSettings({ sessionHold: true });
    attach((respond) => {
      respond(200, { held: true });
    });
    const run = await hook('pre-tool-use', bash('ls'));
    expect(run.stdout).toContain(SESSION_HELD_REASON);
  });

  it('lets the call go on when the deployment does not answer in time', async () => {
    captureSettings({ sessionHold: true });
    attach(() => {
      // Never answers.
    });
    const run = await hook('pre-tool-use', bash('ls'));
    expect(run.stdout).toBe('');
    expect(seen).toHaveLength(1);
  });

  it('asks nothing when the settings leave the check off', async () => {
    attach((respond) => {
      respond(200, { held: true });
    });
    const run = await hook('pre-tool-use', bash('ls'));
    expect(run.stdout).toBe('');
    expect(seen).toEqual([]);
  });
});

function storedResponses(): { content: string; attributes: string }[] {
  const db = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'));
  try {
    return db
      .prepare("SELECT content, attributes FROM audit_events WHERE event_type = 'response'")
      .all() as { content: string; attributes: string }[];
  } finally {
    db.close();
  }
}

const bashResult = (output: string) => ({
  tool_name: 'Bash',
  tool_input: { command: 'cat notes.txt' },
  tool_response: output,
  session_id: 'sess-forward',
  cwd: home,
  hook_event_name: 'PostToolUse',
});

describe('tool output forwarding, through the built PostToolUse hook', () => {
  it('records nothing for clean output by default', async () => {
    await hook('post-tool-use', bashResult('nothing sensitive in here'));
    expect(storedResponses()).toEqual([]);
  });

  it('records nothing for a repository the settings do not name', async () => {
    captureSettings({ toolOutput: { maxChars: 10, repos: ['github.com/acme/app'] } });
    await hook('post-tool-use', bashResult('nothing sensitive in here'));
    expect(storedResponses()).toEqual([]);
  });

  it('records clean output, cut to the cap, when the settings forward tool output', async () => {
    captureSettings({ toolOutput: { maxChars: 10 } });
    await hook('post-tool-use', bashResult('nothing sensitive in here'));
    const rows = storedResponses();
    expect(rows.map((row) => row.content)).toEqual(['nothing se']);
  });
});
