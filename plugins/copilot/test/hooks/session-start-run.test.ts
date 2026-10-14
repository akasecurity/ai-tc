/**
 * The sessionStart handler, driven in-process against a real temp home.
 *
 * Nothing is mocked: the store is a real `node:sqlite` file under a throwaway
 * `akaHome`, the config is the one the handler resolves itself, and every
 * payload is a RECORDED fixture re-pointed at a temp `cwd` (the recorded path
 * does not exist on this machine).
 *
 * The handler emits nothing on every path, so `toBeUndefined()` alone cannot
 * tell a hook that opened the root from one that declined, crashed into a
 * swallowed throw, or never ran. Every silence case therefore sits beside the
 * row it should — or should not — leave in the store.
 */
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { loadConfig, resolveCopilotProvider } from '@akasecurity/plugin-sdk';
import { HARNESS, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { runSessionStart } from '../../src/hooks/session-start-run.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

const DIALECTS = [
  {
    kind: 'cli',
    event: 'sessionStart',
    payload: () => fixture('cli', 'sessionStart.json'),
    sessionId: (p: Record<string, unknown>) => p.sessionId,
  },
  {
    kind: 'vscode',
    event: 'SessionStart',
    payload: () => fixture('vscode-provisional', 'SessionStart.json'),
    sessionId: (p: Record<string, unknown>) => p.session_id,
  },
] as const;

let root: string;
let akaHome: string;
let cwd: string;
let home: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-session-run-'));
  // Not created here: the handler's own config load creates it, so a case
  // that must not open the store can assert the directory never appeared.
  akaHome = join(root, 'aka-home');
  cwd = mkdtempSync(join(tmpdir(), 'aka-copilot-session-run-cwd-'));
  home = mkdtempSync(join(tmpdir(), 'aka-copilot-session-run-home-'));
});

afterEach(() => {
  removeTrees([root, cwd, home]);
});

function rows(sql: string): Record<string, unknown>[] {
  const db = new DatabaseSync(join(akaHome, 'data', 'aka.db'));
  try {
    return db.prepare(sql).all();
  } finally {
    db.close();
  }
}

describe('runSessionStart', () => {
  // The precondition that keeps this suite from starting real background
  // processes: a fresh home is standalone with body expiry off, so none of the
  // three detached children `handleSessionStart` can spawn is reachable here.
  it('runs against a home that spawns no detached child', () => {
    const { settings } = loadConfig(akaHome, resolveCopilotProvider);
    expect(settings.runMode).toBe('standalone');
    expect(settings.bodyRetention.enabled).toBe(false);
  });

  describe.each(DIALECTS)('on the $kind dialect', ({ kind, event, payload, sessionId }) => {
    it('opens the session root and its inventory, and emits nothing', async () => {
      const input = { ...payload(), cwd };
      const output = await runSessionStart(event, JSON.stringify(input), {
        akaHome,
        homeDir: home,
      });
      expect(output).toBeUndefined();

      const sessions = rows(
        "SELECT id, attributes, host_id, harness_id FROM audit_events WHERE event_type = 'session'",
      );
      expect(sessions.map((r) => r.id)).toEqual([sessionId(input)]);
      const attrs = JSON.parse(String(sessions[0]?.attributes)) as Record<string, unknown>;
      expect(attrs.harness).toBe(HARNESS.Copilot);
      // From the payload dialect, not from anything the process could see.
      expect(attrs.harness_interface).toBe(kind);
      expect(attrs.provider).toBe('unknown');

      // The inventory the root hangs off: this machine's host and the Copilot
      // harness, each a row the root names.
      const [session] = sessions;
      const host = rows(
        `SELECT object_type FROM inventory WHERE id = '${String(session?.host_id)}'`,
      );
      expect(host).toEqual([{ object_type: 'host' }]);
      const harness = rows(
        `SELECT object_type, title, attributes FROM inventory WHERE id = '${String(session?.harness_id)}'`,
      );
      expect(harness.map((r) => [r.object_type, r.title])).toEqual([
        ['harness', SOURCE_TOOL.Copilot],
      ]);
      const harnessAttrs = JSON.parse(String(harness[0]?.attributes)) as Record<string, unknown>;
      expect(harnessAttrs.interface).toBe(kind);
    });

    it('declines a payload with no cwd without opening the store', async () => {
      const input: Record<string, unknown> = { ...payload() };
      delete input.cwd;
      const output = await runSessionStart(event, JSON.stringify(input), {
        akaHome,
        homeDir: home,
      });
      expect(output).toBeUndefined();
      // Not merely no session row: the config load creates the home, so its
      // absence shows the handler stopped before touching the store at all.
      expect(existsSync(akaHome)).toBe(false);
    });
  });

  it('ignores an event token for some other hook', async () => {
    const input = { ...fixture('cli', 'sessionStart.json'), cwd };
    // `sessionEnd` carries the same envelope on this host, so only the token
    // can tell the two apart.
    const output = await runSessionStart('sessionEnd', JSON.stringify(input), {
      akaHome,
      homeDir: home,
    });
    expect(output).toBeUndefined();
    expect(existsSync(akaHome)).toBe(false);
  });

  it('runs with no event token at all', async () => {
    const input = { ...fixture('cli', 'sessionStart.json'), cwd };
    await runSessionStart(undefined, JSON.stringify(input), { akaHome, homeDir: home });
    expect(rows("SELECT id FROM audit_events WHERE event_type = 'session'")).toHaveLength(1);
  });

  it.each(['', 'not json', '[]', 'null'])(
    'declines stdin that is not a payload object (%j)',
    async (stdin) => {
      const output = await runSessionStart('sessionStart', stdin, { akaHome, homeDir: home });
      expect(output).toBeUndefined();
      expect(existsSync(akaHome)).toBe(false);
    },
  );
});
