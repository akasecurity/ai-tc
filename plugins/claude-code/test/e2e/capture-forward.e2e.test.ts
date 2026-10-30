/**
 * Tool output forwarding and the session hold, through the built hooks and the
 * mod's helper, against a throwaway home and a loopback deployment.
 */
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  applyOnboarding,
  ATTACHED_CAPTURE_SETTINGS_FILENAME,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { useLoopbackServer } from '../../../../packages/remote/test/helpers/loopback.ts';
import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { SESSION_HELD_REASON } from '../../src/hooks/capture-forward.ts';
import { runHook, runHookAsync, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SECRET = bundledDetections()
  .flatMap((pack) => pack.rules)
  .find((rule) => rule.id === 'secrets/twilio-key')?.examples?.[0];

const server = useLoopbackServer();

async function withTempHomeAsync(fn: (home: string) => Promise<void>): Promise<void> {
  const home = mkdtempSync(join(tmpdir(), 'aka-capture-forward-'));
  try {
    await fn(home);
  } finally {
    removeTree(home);
  }
}

const env = (home: string) => ({ ...tempHomeEnv(home), NODE_OPTIONS: '' });

function dataDir(home: string): string {
  const dir = join(home, '.aka', 'data');
  mkdirSync(dir, { recursive: true });
  return dir;
}

function captureSettings(home: string, settings: Record<string, unknown>): void {
  writeFileSync(
    join(dataDir(home), ATTACHED_CAPTURE_SETTINGS_FILENAME),
    JSON.stringify({ v: 1, ...settings }),
  );
}

function modRunning(home: string, sessionId: string): void {
  const dir = join(dataDir(home), 'mod-sessions');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, `${sessionId}.json`),
    JSON.stringify({ v: 1, sessionId, at: Date.now() }),
  );
}

function attach(
  home: string,
  answer: (respond: (status: number, body: unknown) => void) => void,
): string[] {
  const seen: string[] = [];
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
    apiKey: 'not-a-real-key-claude',
  });
  return seen;
}

const preToolUse = (home: string) =>
  JSON.stringify({
    tool_name: 'Bash',
    tool_input: { command: 'ls' },
    session_id: 'sess-hold',
    cwd: home,
    hook_event_name: 'PreToolUse',
  });

describe('the session hold, through the built PreToolUse hook', () => {
  it('refuses the call when the deployment holds the session', async () => {
    await withTempHomeAsync(async (home) => {
      captureSettings(home, { sessionHold: true });
      const seen = attach(home, (respond) => {
        respond(200, { held: true });
      });
      const run = await runHookAsync('pre-tool-use', preToolUse(home), { env: env(home) });
      const out = JSON.parse(run.stdout) as {
        hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
      };
      expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
      expect(out.hookSpecificOutput.permissionDecisionReason).toBe(`AKA: ${SESSION_HELD_REASON}`);
      expect(seen).toEqual(['GET /v1/plugin/sessions/sess-hold/hold']);
    });
  });

  it('lets the call go on when the deployment does not answer in time', async () => {
    await withTempHomeAsync(async (home) => {
      captureSettings(home, { sessionHold: true });
      const seen = attach(home, () => {
        // Never answers.
      });
      const run = await runHookAsync('pre-tool-use', preToolUse(home), { env: env(home) });
      expect(run.status).toBe(0);
      expect(run.stdout).not.toContain('deny');
      expect(seen).toHaveLength(1);
    });
  });

  it('asks nothing when the settings leave the check off', async () => {
    await withTempHomeAsync(async (home) => {
      const seen = attach(home, (respond) => {
        respond(200, { held: true });
      });
      const run = await runHookAsync('pre-tool-use', preToolUse(home), { env: env(home) });
      expect(run.stdout).not.toContain('deny');
      expect(seen).toEqual([]);
    });
  });
});

function responses(home: string): { content: string }[] {
  const file = join(home, '.aka', 'data', 'aka.db');
  if (!existsSync(file)) return [];
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    return db
      .prepare("SELECT content FROM audit_events WHERE event_type = 'response' ORDER BY rowid")
      .all() as { content: string }[];
  } finally {
    db.close();
  }
}

const postToolUse = (home: string, output: string) =>
  JSON.stringify({
    tool_name: 'Bash',
    tool_input: { command: 'cat notes.txt' },
    tool_response: { stdout: output, stderr: '' },
    session_id: 'sess-forward',
    cwd: home,
    hook_event_name: 'PostToolUse',
  });

describe('tool output forwarding, through the built PostToolUse hook', () => {
  it('records nothing for clean output by default', () => {
    withTempHome((home) => {
      runHook('post-tool-use', postToolUse(home, 'nothing sensitive in here'), { env: env(home) });
      expect(responses(home)).toEqual([]);
    });
  });

  it('records clean output cut to the cap when the settings forward tool output', () => {
    withTempHome((home) => {
      captureSettings(home, { toolOutput: { maxChars: 10 } });
      runHook('post-tool-use', postToolUse(home, 'nothing sensitive in here'), { env: env(home) });
      expect(responses(home)).toEqual([{ content: 'nothing se' }]);
    });
  });

  it('records nothing for a repository the settings do not name', () => {
    withTempHome((home) => {
      captureSettings(home, { toolOutput: { maxChars: 10, repos: ['github.com/acme/app'] } });
      runHook('post-tool-use', postToolUse(home, 'nothing sensitive in here'), { env: env(home) });
      expect(responses(home)).toEqual([]);
    });
  });

  it("leaves tool output to the session's mod while the mod is running", () => {
    withTempHome((home) => {
      captureSettings(home, { toolOutput: { maxChars: 10 } });
      modRunning(home, 'sess-forward');
      runHook('post-tool-use', postToolUse(home, 'nothing sensitive in here'), { env: env(home) });
      expect(responses(home)).toEqual([]);
    });
  });
});

describe("tool output forwarding, through the mod's helper", () => {
  const forwardRow = (home: string, text: string, length?: number) => {
    const cwd = join(home, 'project');
    mkdirSync(cwd, { recursive: true });
    return runHook(
      'mod-tokenize',
      JSON.stringify({
        v: 1,
        text,
        sessionId: 'sess-mod',
        cwd,
        row: {
          door: 'tool-result',
          tool: 'Read',
          forward: { maxChars: 100, ...(length === undefined ? {} : { length }) },
        },
      }),
      { env: env(home) },
    );
  };

  it('records a clean tool result and answers no rewrite', () => {
    withTempHome((home) => {
      captureSettings(home, { toolOutput: { maxChars: 100 } });
      const run = forwardRow(home, 'a clean tool result', 5_000);
      expect(run.status).toBe(1);
      expect(run.stdout).toBe('');
      expect(responses(home)).toEqual([{ content: 'a clean tool result' }]);
    });
  });

  it('records nothing when the settings no longer forward tool output', () => {
    withTempHome((home) => {
      dataDir(home);
      const run = forwardRow(home, 'a clean tool result');
      expect(run.status).toBe(1);
      expect(responses(home)).toEqual([]);
    });
  });

  it('records nothing for a repository the settings do not name', () => {
    withTempHome((home) => {
      captureSettings(home, { toolOutput: { maxChars: 100, repos: ['github.com/acme/app'] } });
      const run = forwardRow(home, 'a clean tool result');
      expect(run.status).toBe(1);
      expect(responses(home)).toEqual([]);
    });
  });

  it('records nothing for a tool result with a finding, which is recorded elsewhere', () => {
    withTempHome((home) => {
      captureSettings(home, { toolOutput: { maxChars: 100 } });
      expect(SECRET).toBeDefined();
      const run = forwardRow(home, `key=${SECRET ?? ''}`);
      expect(run.status).toBe(1);
      expect(run.stdout).toBe('');
      expect(responses(home)).toEqual([]);
    });
  });
});
