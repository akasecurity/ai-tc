// A reconcile pass records the commits a session's `git commit` made, read from the checkout's
// reflog, as `git_commit` rows under the session root in the real local store.
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { reconcileSessionTail } from '../../src/history/usage.ts';

const SESSION = 'sess-commits';
const COMMIT = 'c0ffee'.repeat(6) + 'c0ff';
const ISSUED = '2026-10-20T10:00:01.100Z';

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

function transcript(
  cwd: string,
  command: string,
  turn = 1,
  opts: { issued?: string; done?: string; isError?: boolean } = {},
): string {
  const n = String(turn);
  const usage = { input_tokens: 100, output_tokens: 50 };
  const base = { sessionId: SESSION, cwd, version: '1.2.3', entrypoint: 'cli' };
  return [
    {
      type: 'user',
      uuid: `u-${n}`,
      promptId: `p-${n}`,
      timestamp: opts.issued ?? ISSUED,
      message: { role: 'user', content: 'commit it' },
    },
    {
      type: 'assistant',
      uuid: `a-${n}`,
      parentUuid: `u-${n}`,
      timestamp: opts.issued ?? ISSUED,
      message: {
        id: `msg_${n}`,
        model: 'claude-sonnet-4-5-20250929',
        usage,
        content: [{ type: 'tool_use', id: `toolu_${n}`, name: 'Bash', input: { command } }],
      },
    },
    {
      type: 'user',
      uuid: `r-${n}`,
      parentUuid: `a-${n}`,
      timestamp: opts.done ?? '2026-10-20T10:00:03.000Z',
      message: {
        role: 'user',
        content: [
          {
            type: 'tool_result',
            tool_use_id: `toolu_${n}`,
            content: '1 file changed',
            ...(opts.isError ? { is_error: true } : {}),
          },
        ],
      },
    },
  ]
    .map((line) => JSON.stringify({ ...base, ...line }))
    .join('\n')
    .concat('\n');
}

function commitRows(dataDir: string): { parent_id: string; attributes: string }[] {
  const db = new DatabaseSync(join(dataDir, 'aka.db'), { readOnly: true });
  try {
    return db
      .prepare(
        "SELECT parent_id, attributes FROM audit_events WHERE event_type = 'git_commit' ORDER BY id",
      )
      .all() as { parent_id: string; attributes: string }[];
  } finally {
    db.close();
  }
}

describe('reconcileSessionTail — the commits a session made', () => {
  let dataDir: string;
  let workDir: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-commits-data-'));
    workDir = mkdtempSync(join(tmpdir(), 'aka-commits-work-'));
    mkdirSync(join(workDir, '.git', 'logs'), { recursive: true });
    writeFileSync(join(workDir, '.git', 'HEAD'), 'ref: refs/heads/feat/retries\n');
    const seconds = String(Math.floor(Date.parse('2026-10-20T10:00:02.000Z') / 1000));
    writeFileSync(
      join(workDir, '.git', 'logs', 'HEAD'),
      `${'a'.repeat(40)} ${COMMIT} Dev <dev@example.com> ${seconds} +0000\tcommit: add retries\n`,
    );
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(workDir, { recursive: true, force: true });
  });

  it('records the commit under the session as a command_window row', async () => {
    const path = join(workDir, 'transcript.jsonl');
    writeFileSync(path, transcript(workDir, 'git add -A && git commit -m "add retries"'));
    await reconcileSessionTail(config(dataDir), SESSION, path);
    const rows = commitRows(dataDir);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.parent_id).toBe(SESSION);
    expect(JSON.parse(rows[0]?.attributes ?? '{}')).toMatchObject({
      commit: COMMIT,
      kind: 'commit',
      attribution: 'command_window',
    });
  });

  it('keeps one row when a later pass reads the same commit again through another command', async () => {
    const path = join(workDir, 'transcript.jsonl');
    writeFileSync(path, transcript(workDir, 'git commit -m "add retries"'));
    await reconcileSessionTail(config(dataDir), SESSION, path);
    appendFileSync(
      path,
      transcript(workDir, 'git commit --amend --no-edit', 2, {
        issued: '2026-10-20T10:00:03.500Z',
        done: '2026-10-20T10:00:04.000Z',
      }),
    );
    await reconcileSessionTail(config(dataDir), SESSION, path);
    expect(commitRows(dataDir)).toHaveLength(1);
  });

  it('records nothing for a git commit whose result was an error', async () => {
    const path = join(workDir, 'transcript.jsonl');
    writeFileSync(path, transcript(workDir, 'git commit -m x', 1, { isError: true }));
    await reconcileSessionTail(config(dataDir), SESSION, path);
    expect(commitRows(dataDir)).toEqual([]);
  });

  it('records nothing for a git command that makes no commit', async () => {
    const path = join(workDir, 'transcript.jsonl');
    writeFileSync(path, transcript(workDir, 'git status'));
    await reconcileSessionTail(config(dataDir), SESSION, path);
    expect(commitRows(dataDir)).toEqual([]);
  });
});
