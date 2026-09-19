/**
 * THE RECORDED ORDER, not the intuitive one.
 *
 * The live CLI session in `test/fixtures/cli/` stamps `userPromptSubmitted` at
 * 1788547858031 and `sessionStart` at 1788547858051: the prompt hook fires
 * TWENTY MILLISECONDS BEFORE the session hook it is nominally inside. So on
 * this host the once-per-session inventory pass routinely runs AFTER the
 * session's first capture has already been written, and the property that has
 * to hold is that opening the root second loses nothing — not that it is
 * opened first.
 *
 * Driving the intuitive order instead would pass whether or not that held,
 * which is why this file drives the fixtures' own timestamps and asserts the
 * ordering it observes rather than restating it.
 */
import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { handleSessionStart, resolveDataGateway } from '@akasecurity/plugin-runtime';
import { createPluginRuntime, type PluginConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { readSessionStartFacts } from '../../src/hooks/session-start-payload.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures', 'cli');

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as Record<string, unknown>;
}

let dataDir: string;
let cwd: string;
let home: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), 'aka-copilot-order-'));
  cwd = mkdtempSync(join(tmpdir(), 'aka-copilot-order-cwd-'));
  home = mkdtempSync(join(tmpdir(), 'aka-copilot-order-home-'));
  mkdirSync(join(dataDir, 'settings'), { recursive: true });
});

afterEach(() => {
  removeTrees([dataDir, cwd, home]);
});

function config(): PluginConfig {
  return {
    settings: {
      specVersion: 1,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: join(dataDir, 'settings'),
    onboarded: true,
    // What this host resolves: nothing. See plugin-sdk's provider-copilot.ts.
    provider: { provider: 'unknown' },
  };
}

/** Write one prompt capture the way the userPromptSubmitted hook will. */
async function capturePrompt(sessionId: string, text: string): Promise<void> {
  const cfg = config();
  const runtime = createPluginRuntime(resolveDataGateway(cfg), cfg.settings, { dataDir });
  try {
    await runtime.capture({
      kind: 'prompt',
      sourceTool: SOURCE_TOOL.Copilot,
      text,
      metadata: { sessionId },
    });
  } finally {
    await runtime.close();
  }
}

async function openSession(sessionId: string, harnessInterface: string | undefined): Promise<void> {
  await handleSessionStart(
    {
      sessionId,
      cwd,
      tool: SOURCE_TOOL.Copilot,
      harnessVersion: '1.0.83',
      harnessInterface,
      homeDir: home,
    },
    config(),
  );
}

function rows(sql: string): Record<string, unknown>[] {
  const db = new DatabaseSync(join(dataDir, 'aka.db'));
  try {
    return db.prepare(sql).all();
  } finally {
    db.close();
  }
}

/**
 * The single row a query is expected to return.
 *
 * The length is asserted HERE rather than at each call site, which is what
 * keeps the narrowing honest: a bang or a cast would satisfy the compiler on an
 * EMPTY result and then read every field as undefined, so a query that matched
 * nothing would fail on a confusing property assertion rather than on the row
 * count that actually went wrong.
 */
function only(sql: string): Record<string, unknown> {
  const found = rows(sql);
  expect(found).toHaveLength(1);
  const [row] = found;
  if (row === undefined) throw new Error(`no row for: ${sql}`);
  return row;
}

/** A defined string, narrowed by assertion rather than by a bang. */
function defined(value: string | undefined): string {
  expect(value).toBeDefined();
  if (value === undefined) throw new Error('expected a defined value');
  return value;
}

describe('sessionStart arriving after the session’s first prompt', () => {
  // The premise. If the recordings ever stop showing this, the case below is
  // still correct but is no longer describing the host — so the premise is
  // asserted rather than quoted from the README.
  it('is what the recordings show', () => {
    const prompt = fixture('userPromptSubmitted.json').timestamp as number;
    const start = fixture('sessionStart.json').timestamp as number;
    expect(prompt).toBeLessThan(start);
    expect(start - prompt).toBe(20);
  });

  it('opens the root and keeps the capture that preceded it', async () => {
    const facts = readSessionStartFacts(fixture('sessionStart.json'));
    const sessionId = defined(facts.sessionId);

    // The recorded order: the prompt first, the session root twenty
    // milliseconds later.
    await capturePrompt(sessionId, 'run the shell command: false');
    await openSession(sessionId, facts.harnessInterface);

    const session = only("SELECT * FROM audit_events WHERE event_type = 'session'");
    expect(session.id).toBe(sessionId);

    // The capture written BEFORE the root still hangs off it: the root is keyed
    // on the session id, not on having been written first.
    const prompt = only("SELECT * FROM audit_events WHERE event_type = 'prompt'");
    expect(prompt.root_session_id).toBe(sessionId);

    const attrs = JSON.parse(session.attributes as string) as Record<string, unknown>;
    expect(attrs.harness).toBe('copilot');
    expect(attrs.harness_interface).toBe('cli');
    // Unresolved, and recorded as unresolved rather than as a guessed backend.
    expect(attrs.provider).toBe('unknown');
  });

  // The once-per-session claim has to survive a host that fires sessionStart
  // more than once (resume, clear, compact) — and, on this host, one that
  // fires it late.
  it('is claimed once however many times the hook runs', async () => {
    const sessionId = 'repeat-session';
    await capturePrompt(sessionId, 'first prompt');
    await openSession(sessionId, 'cli');
    await openSession(sessionId, 'cli');
    await openSession(sessionId, 'cli');

    expect(rows("SELECT * FROM audit_events WHERE event_type = 'session'")).toHaveLength(1);
  });
});
