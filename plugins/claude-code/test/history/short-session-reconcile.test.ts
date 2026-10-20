// A session that ends inside the reconcile throttle window still records the
// llm_call and tool_call rows of its turns. The hooks' real trigger and the real
// worker run against a real local store; only the process boundary is stood in
// for: a spawn is held, and its argv is later handed to the worker the way the
// detached child would run it.
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { spawned } = vi.hoisted(() => ({ spawned: [] as string[][] }));
vi.mock('node:child_process', () => ({
  spawn: (_command: string, args: readonly string[]) => {
    spawned.push(args.slice(1));
    return { on: () => undefined, unref: () => undefined };
  },
}));

import { triggerReconcile } from '../../src/history/reconcile-trigger.ts';
import { runReconcileWorker } from '../../src/history/reconcile-worker.ts';

const SESSION = 'sess-short';
const WINDOW_MS = 30_000;

function config(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 2,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'full',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

const usage = { input_tokens: 100, output_tokens: 50 };

// One turn of the session: a prompt, a reply that calls a tool, the tool's
// result, and the closing reply. Two model calls and one tool call.
function turn(number: number): string {
  const n = String(number);
  const base = { sessionId: SESSION, cwd: '/Users/me/proj', version: '1.2.3', entrypoint: 'cli' };
  const lines = [
    {
      type: 'user',
      uuid: `u-${n}`,
      promptId: `p-${n}`,
      timestamp: `2026-10-20T10:00:0${n}.000Z`,
      message: { role: 'user', content: 'do a thing' },
    },
    {
      type: 'assistant',
      uuid: `a-${n}-1`,
      parentUuid: `u-${n}`,
      timestamp: `2026-10-20T10:00:0${n}.100Z`,
      message: {
        id: `msg_${n}_1`,
        model: 'claude-sonnet-4-5-20250929',
        usage,
        content: [
          { type: 'tool_use', id: `toolu_${n}`, name: 'Bash', input: { command: 'echo hi' } },
        ],
      },
    },
    {
      type: 'user',
      uuid: `r-${n}`,
      parentUuid: `a-${n}-1`,
      timestamp: `2026-10-20T10:00:0${n}.200Z`,
      message: {
        role: 'user',
        content: [{ type: 'tool_result', tool_use_id: `toolu_${n}`, content: 'hi\n' }],
      },
    },
    {
      type: 'assistant',
      uuid: `a-${n}-2`,
      parentUuid: `r-${n}`,
      timestamp: `2026-10-20T10:00:0${n}.300Z`,
      message: { id: `msg_${n}_2`, model: 'claude-sonnet-4-5-20250929', usage },
    },
  ];
  return lines.map((line) => JSON.stringify({ ...base, ...line })).join('\n') + '\n';
}

function count(dataDir: string, eventType: string): number {
  // The store is created by the first pass that writes; before it there is none.
  const dbPath = join(dataDir, 'aka.db');
  if (!existsSync(dbPath)) return 0;
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const row = db
      .prepare('SELECT COUNT(*) AS n FROM audit_events WHERE event_type = ?')
      .get(eventType) as { n: number };
    return row.n;
  } finally {
    db.close();
  }
}

describe('a session that ends inside the reconcile throttle window', () => {
  let dataDir: string;
  let transcriptPath: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-short-data-'));
    transcriptPath = join(dataDir, `${SESSION}.jsonl`);
    writeFileSync(transcriptPath, '');
    spawned.length = 0;
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  // What the detached children do. One spawned with no due time runs when it is
  // spawned; one spawned with a due time sleeps until it and runs then, which
  // for a session that has ended is after the session.
  async function runChildren(due: boolean): Promise<void> {
    const mine = spawned.filter((args) => args.length > 2 === due);
    for (const args of mine) spawned.splice(spawned.indexOf(args), 1);
    for (const args of mine) {
      await runReconcileWorker(args, {
        sleep: () => Promise.resolve(),
        config: () => config(dataDir),
      });
    }
  }
  // SessionStart and Stop call the same trigger with the same session and path.
  const trigger = () => {
    triggerReconcile(dataDir, SESSION, transcriptPath);
  };
  const finishTurn = (n: number) => {
    appendFileSync(transcriptPath, turn(n));
    trigger();
  };

  it('records every turn of a session whose Stops come seconds after SessionStart', async () => {
    trigger();
    await runChildren(false);
    finishTurn(1);
    await runChildren(false);
    finishTurn(2);
    await runChildren(false);
    // The session has ended. Whatever the hooks scheduled for later now runs.
    await runChildren(true);

    expect(count(dataDir, 'llm_call')).toBe(4);
    expect(count(dataDir, 'tool_call')).toBe(2);
  });

  it('records the turn of a one-shot session that Stops within seconds of SessionStart', async () => {
    trigger();
    await runChildren(false);
    finishTurn(1);
    await runChildren(false);
    await runChildren(true);

    expect(count(dataDir, 'llm_call')).toBe(2);
    expect(count(dataDir, 'tool_call')).toBe(1);
  });

  it('records the last turn of a longer session when its Stop follows an earlier pass within the window', async () => {
    trigger();
    await runChildren(false);
    // The first turn takes a while: its Stop is well past the SessionStart window.
    const longAgo = new Date(Date.now() - 2 * WINDOW_MS);
    utimesSync(join(dataDir, `reconcile-last-attempt-${SESSION}`), longAgo, longAgo);
    finishTurn(1);
    await runChildren(false);
    // The second turn is short: its Stop is seconds after the first Stop's pass.
    finishTurn(2);
    await runChildren(false);
    await runChildren(true);

    expect(count(dataDir, 'llm_call')).toBe(4);
    expect(count(dataDir, 'tool_call')).toBe(2);
  });
});
