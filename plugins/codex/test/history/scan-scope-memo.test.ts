// The backfill sweep's scope-key memo, as the sweep wires it: ONE memo per pass,
// handed every message, so a directory that messages share is walked once and
// keyed identically wherever it recurs, even past the resolver's own memo bound.
// How the memo behaves once built is pinned where it lives, in plugin-sdk's
// scope-key tests; this file pins that the sweep builds exactly one per pass.
//
// It has its own file because it wraps the SDK's memo factory in a spy, and a
// module mock applies to every test in the file that declares it. The wrapper
// delegates, so the keys are the real ones and only the builds are counted.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { scanHistory } from '../../src/history/scan.ts';

const { memoFactory } = vi.hoisted(() => ({
  memoFactory: vi.fn<() => (cwd: string | undefined) => string | undefined>(),
}));

vi.mock('@akasecurity/plugin-sdk', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  memoFactory.mockImplementation(
    actual.scopeKeyMemo as () => (cwd: string | undefined) => string | undefined,
  );
  return { ...actual, scopeKeyMemo: memoFactory };
});

// The userinfo in an scp-form remote reads as an email address to a scanner,
// so the fixture builds it from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;
// Composed at runtime so the repo's own secret scanning does not flag this file.
const BACKFILL_SECRET = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const NOW = Date.parse('2026-06-24T00:00:00.000Z');

function config(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 3,
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
    provider: { provider: 'openai' },
  };
}

describe('scanHistory — one scope-key memo per pass', () => {
  let dataDir: string;
  let root: string;
  let workRepo: string;
  let scratch: string;
  beforeEach(() => {
    memoFactory.mockClear();
    dataDir = mkdtempSync(join(tmpdir(), 'aka-scan-memo-data-'));
    root = mkdtempSync(join(tmpdir(), 'aka-scan-memo-tx-'));
    workRepo = mkdtempSync(join(tmpdir(), 'aka-scan-memo-repo-'));
    mkdirSync(join(workRepo, '.git'), { recursive: true });
    writeFileSync(
      join(workRepo, '.git', 'config'),
      `[remote "origin"]\n\turl = ${gitUser}github.com:acme/work.git\n`,
    );
    scratch = mkdtempSync(join(tmpdir(), 'aka-scan-memo-scratch-'));
  });
  afterEach(() => {
    for (const d of [dataDir, root, workRepo, scratch]) rmSync(d, { recursive: true, force: true });
  });

  it('builds one memo for a pass over four messages in two directories, and keys them by it', async () => {
    const dir = join(root, '2026', '06', '20');
    mkdirSync(dir, { recursive: true });
    const userMessage = (timestamp: string, text: string): string =>
      JSON.stringify({
        timestamp,
        type: 'response_item',
        payload: { type: 'message', role: 'user', content: [{ type: 'input_text', text }] },
      });
    const turn = (cwd: string, second: string): string =>
      JSON.stringify({
        timestamp: `2026-06-20T12:00:${second}.000Z`,
        type: 'turn_context',
        payload: { turn_id: `turn-${second}`, cwd },
      });
    // Rollout A opens in the work checkout, moves to a scratch directory, and
    // comes back. Rollout B names no directory at all.
    writeFileSync(
      join(dir, 'rollout-a.jsonl'),
      [
        JSON.stringify({
          timestamp: '2026-06-20T11:59:00.000Z',
          type: 'session_meta',
          payload: { session_id: 'sess-a', cwd: workRepo },
        }),
        userMessage('2026-06-20T12:00:00.000Z', `note 00 ${BACKFILL_SECRET}`),
        turn(scratch, '01'),
        userMessage('2026-06-20T12:00:02.000Z', `note 02 ${BACKFILL_SECRET}`),
        turn(workRepo, '03'),
        userMessage('2026-06-20T12:00:04.000Z', `note 04 ${BACKFILL_SECRET}`),
      ].join('\n'),
    );
    writeFileSync(
      join(dir, 'rollout-b.jsonl'),
      userMessage('2026-06-20T12:00:06.000Z', `note 06 ${BACKFILL_SECRET}`),
    );
    const cfg = config(dataDir);

    await scanHistory(cfg, { dir: root, now: NOW });

    // The control: the spy is in the path, so a count of one is a count and not a
    // seam that is never reached.
    expect(memoFactory).toHaveBeenCalledTimes(1);
    const db = new DatabaseSync(cfg.dbPath);
    try {
      const rows = db
        .prepare(
          "SELECT scope_key AS key FROM audit_events WHERE event_type = 'prompt' ORDER BY started_at",
        )
        .all() as { key: string | null }[];
      expect(rows.map((r) => r.key)).toEqual([
        'github.com/acme/work',
        null,
        'github.com/acme/work',
        null,
      ]);
    } finally {
      db.close();
    }
  });
});
