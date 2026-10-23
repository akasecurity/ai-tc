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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { setDefaultGatewayFactory, standaloneGatewayFactory } from '@akasecurity/plugin-runtime';
import { loadConfig, resolveCopilotProvider } from '@akasecurity/plugin-sdk';
import { HARNESS, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { runSessionStart } from '../../src/hooks/session-start-run.ts';
import { progressLine, takeQueuedProgress } from '../../src/hooks/shared.ts';
import { readCliStdout } from '../helpers/cli-stdout.ts';

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

// The session start's notices have no message field on either dialect, and
// stdout is read only as a decision. So each goes to stderr, and on the CLI
// dialect it is also queued as a progress line, which the host strips before
// reading the output. Each one is driven here from the state that produces it,
// and the CLI cases read both copies.
describe('runSessionStart notices', () => {
  let stderr: string[];
  let restoreGateway: (() => void) | undefined;

  beforeEach(() => {
    stderr = [];
    takeQueuedProgress();
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
  });

  afterEach(() => {
    restoreGateway?.();
    restoreGateway = undefined;
    vi.restoreAllMocks();
  });

  async function start(sessionId: string): Promise<unknown> {
    const input = { ...fixture('cli', 'sessionStart.json'), cwd, sessionId };
    return runSessionStart('sessionStart', JSON.stringify(input), { akaHome, homeDir: home });
  }

  /**
   * What the CLI host would show for the queued notices: the stdout
   * `runHookFailOpen` writes for a hook that returned no output, read the way
   * the reference says the host reads it. Its output must stay empty.
   */
  function shownOnCli(): string[] {
    const read = readCliStdout(takeQueuedProgress().map(progressLine).join(''));
    expect(read.output).toBeUndefined();
    return read.progress;
  }

  function seedWarnEraStore(): void {
    const settingsDir = join(akaHome, 'settings');
    mkdirSync(settingsDir, { recursive: true });
    writeFileSync(join(settingsDir, 'settings.json'), JSON.stringify({ policy: 'warn' }));
    const db = openLocalDatabase(join(akaHome, 'data'));
    try {
      db.policies.upsertCategoryAction('secret', 'block');
    } finally {
      db.close();
    }
  }

  it('writes nothing on a fresh standalone home', async () => {
    expect(await start('s-fresh')).toBeUndefined();
    expect(stderr.join('')).toBe('');
    expect(takeQueuedProgress()).toEqual([]);
    // The control: the session root landed, so the silence is a decision.
    expect(rows("SELECT id FROM audit_events WHERE event_type = 'session'")).toHaveLength(1);
  });

  it('writes the warn-era notice once, when the cap actually lands', async () => {
    seedWarnEraStore();
    expect(await start('s-warn-1')).toBeUndefined();
    const first = stderr.join('');
    expect(first).toContain('the global "warn only" handling was retired');
    expect(first.endsWith('\n')).toBe(true);
    const shown = shownOnCli();
    expect(shown).toHaveLength(1);
    expect(shown[0]).toContain('the global "warn only" handling was retired');

    stderr = [];
    await start('s-warn-2');
    // Nothing left to cap, so the second session says nothing about it.
    expect(stderr.join('')).not.toContain('warn only');
    expect(takeQueuedProgress().join('')).not.toContain('warn only');
  });

  it('writes the forwarding line on a machine whose gateway forwards', async () => {
    restoreGateway = setDefaultGatewayFactory((cfg, meta) => {
      const gateway = standaloneGatewayFactory(cfg, meta);
      return Object.assign(gateway, {
        forwardingScope: () => ({ deploymentName: 'Acme', mode: 'machine' as const }),
      });
    });
    expect(await start('s-attached')).toBeUndefined();
    expect(stderr.join('')).toBe('AKA: forwarding everything to Acme (machine-wide)\n');
    expect(shownOnCli()).toEqual(['AKA: forwarding everything to Acme (machine-wide)']);
  });

  it('queues no progress line for the same notice under VS Code', async () => {
    // The control on the dialect split: VS Code documents no progress line,
    // so the notice reaches stderr only there.
    restoreGateway = setDefaultGatewayFactory((cfg, meta) => {
      const gateway = standaloneGatewayFactory(cfg, meta);
      return Object.assign(gateway, {
        forwardingScope: () => ({ deploymentName: 'Acme', mode: 'machine' as const }),
      });
    });
    const input = { ...fixture('vscode-provisional', 'SessionStart.json'), cwd };
    await runSessionStart('SessionStart', JSON.stringify(input), { akaHome, homeDir: home });
    expect(stderr.join('')).toBe('AKA: forwarding everything to Acme (machine-wide)\n');
    expect(takeQueuedProgress()).toEqual([]);
  });
});
