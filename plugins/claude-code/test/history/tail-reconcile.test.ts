// Integration tests for the LIVE per-turn capture path: the incremental
// tail reconcile + the UPSERT-take-MAX(output_tokens) leaf write. These run against
// a real local SQLite store (the same enforced-FK persistence path the backfill
// uses), driving `reconcileSessionTail` end-to-end — offset tracking, single-pass
// parse of only the new tail, and the cross-pass partial/final convergence.
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { readOffset } from '../../src/history/tail.ts';
import { reconcileSessionTail } from '../../src/history/usage.ts';

function config(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 2,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'full',
      dataSharesInPlace: true,
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

const SESSION = 'sess-tail';

// One assistant record line with the given message id + output tokens (+ optional
// parentUuid for run_key). Carries the inventory fields the root ensure needs.
function assistant(
  msgId: string,
  outputTokens: number,
  opts: { uuid?: string; parentUuid?: string; ts?: string } = {},
): string {
  return JSON.stringify({
    type: 'assistant',
    uuid: opts.uuid ?? `a-${msgId}`,
    parentUuid: opts.parentUuid,
    sessionId: SESSION,
    cwd: '/Users/me/proj',
    version: '1.2.3',
    gitBranch: 'main',
    entrypoint: 'cli',
    timestamp: opts.ts ?? '2026-06-20T10:00:05.000Z',
    message: {
      id: msgId,
      model: 'claude-sonnet-4-5-20250929',
      usage: { input_tokens: 100, output_tokens: outputTokens },
    },
  });
}

function userPrompt(uuid: string, promptId: string): string {
  return JSON.stringify({
    type: 'user',
    uuid,
    promptId,
    sessionId: SESSION,
    timestamp: '2026-06-20T10:00:00.000Z',
    message: { role: 'user', content: 'do a thing' },
  });
}

// Read the GENERATED output_tokens column (recomputed from attributes) per message.
function readRows(dataDir: string): Map<string, { output_tokens: number; run_key: unknown }> {
  const db = new DatabaseSync(join(dataDir, 'aka.db'));
  try {
    const calls = db
      .prepare("SELECT output_tokens, attributes FROM audit_events WHERE event_type = 'llm_call'")
      .all() as { output_tokens: number; attributes: string }[];
    const out = new Map<string, { output_tokens: number; run_key: unknown }>();
    for (const c of calls) {
      const attrs = JSON.parse(c.attributes) as Record<string, unknown>;
      out.set(String(attrs.message_id), { output_tokens: c.output_tokens, run_key: attrs.run_key });
    }
    return out;
  } finally {
    db.close();
  }
}

function countLlmCalls(dataDir: string): number {
  const db = new DatabaseSync(join(dataDir, 'aka.db'));
  try {
    const row = db
      .prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = 'llm_call'")
      .get() as { n: number };
    return row.n;
  } finally {
    db.close();
  }
}

describe('reconcileSessionTail — incremental tail capture', () => {
  let dataDir: string;
  let txDir: string;
  let transcriptPath: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-tail-data-'));
    txDir = mkdtempSync(join(tmpdir(), 'aka-tail-tx-'));
    mkdirSync(txDir, { recursive: true });
    transcriptPath = join(txDir, `${SESSION}.jsonl`);
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(txDir, { recursive: true, force: true });
  });

  it('first pass consumes the whole file; a second pass consumes ONLY the new tail', async () => {
    writeFileSync(
      transcriptPath,
      [userPrompt('u-1', 'p1'), assistant('msg_1', 50, { parentUuid: 'u-1' })].join('\n') + '\n',
    );

    const first = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(first.llmCalls).toBe(1);
    expect(countLlmCalls(dataDir)).toBe(1);
    const offAfterFirst = readOffset(dataDir, SESSION).offset;
    expect(offAfterFirst).toBeGreaterThan(0);

    // Append a second turn. The next pass must parse ONLY the new tail (1 new row),
    // not re-parse msg_1.
    appendFileSync(
      transcriptPath,
      [userPrompt('u-2', 'p2'), assistant('msg_2', 75, { parentUuid: 'u-2' })].join('\n') + '\n',
    );
    const second = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(second.llmCalls).toBe(1); // only the new tail's row
    expect(countLlmCalls(dataDir)).toBe(2); // total in the store
    expect(readOffset(dataDir, SESSION).offset).toBeGreaterThan(offAfterFirst);
  });

  it('does not consume a half-written trailing line until it is completed', async () => {
    // A complete first line + an in-flight second line (no newline yet).
    writeFileSync(
      transcriptPath,
      userPrompt('u-1', 'p1') + '\n' + assistant('msg_1', 50, { parentUuid: 'u-1' }).slice(0, 40),
    );
    const first = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    // The assistant line is incomplete → no llm_call yet (only the user line consumed).
    expect(first.llmCalls).toBe(0);
    expect(countLlmCalls(dataDir)).toBe(0);

    // Now write the FULL transcript (completing msg_1). The next pass picks it up.
    writeFileSync(
      transcriptPath,
      [userPrompt('u-1', 'p1'), assistant('msg_1', 50, { parentUuid: 'u-1' })].join('\n') + '\n',
    );
    const second = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(second.llmCalls).toBe(1);
    expect(countLlmCalls(dataDir)).toBe(1);
  });

  it('UPSERT-max converges a partial (1) then terminal (338) across two passes UP to 338', async () => {
    // Pass 1: a streaming PARTIAL — output_tokens = 1.
    writeFileSync(
      transcriptPath,
      userPrompt('u-1', 'p1') + '\n' + assistant('msg_x', 1, { parentUuid: 'u-1' }) + '\n',
    );
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(readRows(dataDir).get('msg_x')?.output_tokens).toBe(1);

    // Pass 2: the TERMINAL record for the SAME message.id — output_tokens = 338.
    // (Appended after the partial; the incremental tail reads only this new line.)
    appendFileSync(transcriptPath, assistant('msg_x', 338, { parentUuid: 'u-1' }) + '\n');
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);

    // Still ONE row for msg_x (collapsed by message.id), now at the full count.
    expect(countLlmCalls(dataDir)).toBe(1);
    expect(readRows(dataDir).get('msg_x')?.output_tokens).toBe(338);
  });

  it('UPSERT-max NEVER decreases: a stale partial after the terminal leaves it at 338', async () => {
    writeFileSync(
      transcriptPath,
      userPrompt('u-1', 'p1') + '\n' + assistant('msg_y', 338, { parentUuid: 'u-1' }) + '\n',
    );
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(readRows(dataDir).get('msg_y')?.output_tokens).toBe(338);

    // A later, smaller (stale) write for the same id must be ignored by the MAX guard.
    appendFileSync(transcriptPath, assistant('msg_y', 1, { parentUuid: 'u-1' }) + '\n');
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(readRows(dataDir).get('msg_y')?.output_tokens).toBe(338); // never decreased
  });

  it('is idempotent: re-running the same tail yields identical counts and values', async () => {
    writeFileSync(
      transcriptPath,
      [userPrompt('u-1', 'p1'), assistant('msg_1', 50, { parentUuid: 'u-1' })].join('\n') + '\n',
    );
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    const before = readRows(dataDir);

    // A no-op pass (no new bytes) must not change anything.
    const again = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(again.llmCalls).toBe(0); // nothing new consumed
    const after = readRows(dataDir);
    expect(after.size).toBe(before.size);
    expect(after.get('msg_1')?.output_tokens).toBe(before.get('msg_1')?.output_tokens);
  });

  it('attributes run_key across a tail boundary from the carry-forward seed', async () => {
    // Pass 1: the prompt + the first assistant call (establishes promptId p1 and the
    // lastPromptId carry-forward in the offset marker).
    writeFileSync(
      transcriptPath,
      [userPrompt('u-prompt', 'p1'), assistant('msg_1', 50, { parentUuid: 'u-prompt' })].join(
        '\n',
      ) + '\n',
    );
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(readOffset(dataDir, SESSION).lastPromptId).toBe('p1');

    // Pass 2: a tool-result-only continuation — a fresh assistant call whose
    // parentUuid points at a tool-result record that is NOT in this tail (its prompt
    // record was consumed last pass). The seeded promptId must still attribute it.
    appendFileSync(transcriptPath, assistant('msg_2', 60, { parentUuid: 'u-toolresult' }) + '\n');
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);

    const rows = readRows(dataDir);
    expect(rows.get('msg_1')?.run_key).toBe('p1');
    expect(rows.get('msg_2')?.run_key).toBe('p1'); // seeded carry-forward
  });
});
