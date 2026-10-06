// The reconcile pass's scope-key memo, as the reconciler wires it: ONE memo per
// pass, handed to every session and every leaf, so a directory that sessions
// share is walked once and keyed identically everywhere. How the memo behaves
// once built (one resolution per directory, kept past the resolver's own bound)
// is pinned where it lives, in plugin-sdk's scope-key-memo test; this file pins
// that the reconciler builds exactly one per pass instead of one per call.
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

import { reconcileHistory, reconcileSessionTail } from '../../src/history/usage.ts';

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
const WORK_KEY = 'github.com/acme/work';

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

const NOW = Date.parse('2026-06-20T12:00:00.000Z');

// One session: a prompt, then one usage-bearing assistant record run in `cwd`
// that issues one Bash tool_use.
function session(sessionId: string, cwd: string): string {
  return [
    JSON.stringify({
      type: 'user',
      uuid: `u-${sessionId}`,
      promptId: `p-${sessionId}`,
      sessionId,
      timestamp: '2026-06-20T10:00:00.000Z',
      message: { role: 'user', content: 'go' },
    }),
    JSON.stringify({
      type: 'assistant',
      uuid: `a-${sessionId}`,
      parentUuid: `u-${sessionId}`,
      sessionId,
      cwd,
      version: '1.2.3',
      timestamp: '2026-06-20T10:00:05.000Z',
      message: {
        id: `msg-${sessionId}`,
        model: 'claude-sonnet-4-5-20250929',
        usage: { input_tokens: 10, output_tokens: 5 },
        content: [
          { type: 'tool_use', id: `toolu-${sessionId}`, name: 'Bash', input: { command: 'ls' } },
        ],
      },
    }),
  ].join('\n');
}

describe('reconcile passes — one scope-key memo per pass', () => {
  let dataDir: string;
  let transcripts: string;
  let workRepo: string;
  beforeEach(() => {
    memoFactory.mockClear();
    dataDir = mkdtempSync(join(tmpdir(), 'aka-memo-data-'));
    transcripts = mkdtempSync(join(tmpdir(), 'aka-memo-tx-'));
    workRepo = mkdtempSync(join(tmpdir(), 'aka-memo-repo-'));
    mkdirSync(join(workRepo, '.git'), { recursive: true });
    writeFileSync(
      join(workRepo, '.git', 'config'),
      `[remote "origin"]\n\turl = ${gitUser}github.com:acme/work.git\n`,
    );
  });
  afterEach(() => {
    for (const d of [dataDir, transcripts, workRepo]) rmSync(d, { recursive: true, force: true });
  });

  function keyedRows(): number {
    const db = new DatabaseSync(join(dataDir, 'aka.db'));
    try {
      const { n } = db
        .prepare('SELECT COUNT(*) AS n FROM audit_events WHERE scope_key = :key')
        .get({ key: WORK_KEY }) as { n: number };
      return n;
    } finally {
      db.close();
    }
  }

  it('the backfill sweep builds one memo for two sessions and four leaves', async () => {
    const project = join(transcripts, '-proj');
    mkdirSync(project, { recursive: true });
    writeFileSync(join(project, 'sess-1.jsonl'), session('sess-1', workRepo));
    writeFileSync(join(project, 'sess-2.jsonl'), session('sess-2', workRepo));

    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    // The control: the spy is in the path, so a count of one is a count and not
    // a seam that is never reached.
    expect(memoFactory).toHaveBeenCalledTimes(1);
    // …and that one memo's answer reached every leaf of both sessions, and both roots.
    expect(keyedRows()).toBe(6); // 2 roots + 2 llm_call + 2 tool_call
  });

  it('the live tail pass builds one memo for both leaf kinds', async () => {
    const transcriptPath = join(transcripts, 'sess-1.jsonl');
    writeFileSync(transcriptPath, `${session('sess-1', workRepo)}\n`);

    await reconcileSessionTail(config(dataDir), 'sess-1', transcriptPath);

    expect(memoFactory).toHaveBeenCalledTimes(1);
    expect(keyedRows()).toBe(3); // the root + 1 llm_call + 1 tool_call
  });
});
