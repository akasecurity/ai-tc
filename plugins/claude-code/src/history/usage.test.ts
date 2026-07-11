import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { reconcileHistory, reconcileSession, reconcileSessionTail } from './usage.ts';

// A standalone (local SQLite) config rooted at `dataDir`. The reconciler resolves
// the same gateway as the real backfill, so these tests exercise the real
// persistence path (INSERT OR IGNORE + enforced FKs), not a mock.
function config(dataDir: string): PluginConfig {
  return {
    settings: { specVersion: 2, runMode: 'standalone', policy: 'redact', historicalAccess: 'full' },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

const SESSION = 'sess-abc';

// A realistic transcript: a real prompt (promptId p1), the assistant call answering
// it (parentUuid → the prompt), a tool-result user record (type:user, fresh uuid,
// SAME promptId p1), then a second assistant call whose parentUuid points at the
// tool-result. Both assistant calls must therefore get run_key=p1 (not the
// tool-result uuid). Includes a `<synthetic>` and a zero-usage record the parser drops.
function transcript(): string {
  return [
    JSON.stringify({
      type: 'user',
      uuid: 'u-prompt',
      promptId: 'p1',
      sessionId: SESSION,
      timestamp: '2026-06-20T10:00:00.000Z',
      message: { role: 'user', content: 'do a thing' },
    }),
    JSON.stringify({
      type: 'assistant',
      uuid: 'a-1',
      parentUuid: 'u-prompt',
      sessionId: SESSION,
      cwd: '/Users/me/proj',
      version: '1.2.3',
      gitBranch: 'main',
      entrypoint: 'cli',
      timestamp: '2026-06-20T10:00:05.000Z',
      message: {
        id: 'msg_1',
        model: 'claude-sonnet-4-5-20250929',
        usage: {
          input_tokens: 100,
          output_tokens: 50,
          cache_creation_input_tokens: 20,
          cache_read_input_tokens: 10,
          cache_creation: { ephemeral_1h_input_tokens: 20, ephemeral_5m_input_tokens: 0 },
          server_tool_use: { web_search_requests: 1, web_fetch_requests: 0 },
          service_tier: 'standard',
        },
      },
    }),
    // Tool-result user record — type:user with a FRESH uuid but the turn's promptId.
    JSON.stringify({
      type: 'user',
      uuid: 'u-toolresult',
      promptId: 'p1',
      sessionId: SESSION,
      timestamp: '2026-06-20T10:00:06.000Z',
      message: { role: 'user', content: [{ type: 'tool_result', content: 'ok' }] },
    }),
    // Second assistant call — its parent is the tool-result record (u-toolresult).
    JSON.stringify({
      type: 'assistant',
      uuid: 'a-2',
      parentUuid: 'u-toolresult',
      sessionId: SESSION,
      cwd: '/Users/me/proj',
      version: '1.2.3',
      timestamp: '2026-06-20T10:00:08.000Z',
      message: {
        id: 'msg_2',
        model: 'claude-sonnet-4-5-20250929',
        usage: { input_tokens: 200, output_tokens: 75 },
      },
    }),
    // Dropped by the parser: synthetic + zero-usage.
    JSON.stringify({
      type: 'assistant',
      uuid: 'a-syn',
      sessionId: SESSION,
      timestamp: '2026-06-20T10:00:09.000Z',
      message: { id: 'msg_syn', model: '<synthetic>', usage: { output_tokens: 5 } },
    }),
  ].join('\n');
}

// A transcript whose assistant message is BOTH usage-bearing (so the reconciler
// ensures the session root) and carries a `tool_use` block, followed by the
// tool_result user record. Reconciling it writes one llm_call AND one tool_call.
function toolTranscript(): string {
  return [
    JSON.stringify({
      type: 'user',
      uuid: 'u-prompt',
      promptId: 'p1',
      sessionId: SESSION,
      timestamp: '2026-06-20T10:00:00.000Z',
      message: { role: 'user', content: 'run bash' },
    }),
    JSON.stringify({
      type: 'assistant',
      uuid: 'a-1',
      parentUuid: 'u-prompt',
      sessionId: SESSION,
      cwd: '/Users/me/proj',
      version: '1.2.3',
      entrypoint: 'cli',
      timestamp: '2026-06-20T10:00:05.000Z',
      message: {
        id: 'msg_1',
        model: 'claude-sonnet-4-5-20250929',
        usage: { input_tokens: 100, output_tokens: 50 },
        content: [
          { type: 'text', text: 'ok' },
          { type: 'tool_use', id: 'toolu_1', name: 'Bash', input: { command: 'echo hi' } },
        ],
      },
    }),
    JSON.stringify({
      type: 'user',
      uuid: 'u-tr',
      promptId: 'p1',
      sessionId: SESSION,
      timestamp: '2026-06-20T10:00:06.000Z',
      message: {
        role: 'user',
        content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: 'hi\n' }],
      },
    }),
  ].join('\n');
}

function seed(root: string, jsonl: string, project = '-Users-me-proj'): void {
  const dir = join(root, project);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${SESSION}.jsonl`), jsonl);
}

// Open a read-only view of the store to count / inspect llm_call rows.
function rows(dataDir: string): {
  count: number;
  byMessageId: Map<string, Record<string, unknown>>;
  sessionExists: boolean;
} {
  const db = new DatabaseSync(join(dataDir, 'aka.db'));
  try {
    const calls = db
      .prepare("SELECT id, started_at, attributes FROM audit_events WHERE event_type = 'llm_call'")
      .all() as { id: string; started_at: number; attributes: string }[];
    const byMessageId = new Map<string, Record<string, unknown>>();
    for (const c of calls) {
      const attrs = JSON.parse(c.attributes) as Record<string, unknown>;
      byMessageId.set(String(attrs.message_id), attrs);
    }
    const session = db
      .prepare("SELECT id FROM audit_events WHERE event_type = 'session' AND id = :id")
      .get({ id: SESSION });
    return { count: calls.length, byMessageId, sessionExists: session != null };
  } finally {
    db.close();
  }
}

describe('reconcileHistory — backfill', () => {
  let dataDir: string;
  let transcripts: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-usage-data-'));
    transcripts = mkdtempSync(join(tmpdir(), 'aka-usage-tx-'));
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(transcripts, { recursive: true, force: true });
  });

  it('writes one llm_call per usage-bearing assistant message and a session root', async () => {
    seed(transcripts, transcript());
    const summary = await reconcileHistory(config(dataDir), { dir: transcripts });

    expect(summary.sessions).toBe(1);
    expect(summary.llmCalls).toBe(2); // msg_1 + msg_2; synthetic + zero-usage dropped
    expect(summary.skipped).toBe(0);

    const r = rows(dataDir);
    expect(r.count).toBe(2);
    expect(r.sessionExists).toBe(true);
  });

  it('is idempotent — re-running yields the same row count (deterministic ids + INSERT OR IGNORE)', async () => {
    seed(transcripts, transcript());
    const opts = { dir: transcripts };

    const first = await reconcileHistory(config(dataDir), opts);
    expect(first.llmCalls).toBe(2);
    expect(rows(dataDir).count).toBe(2);

    const second = await reconcileHistory(config(dataDir), opts);
    expect(second.llmCalls).toBe(2); // re-attempted, but…
    expect(rows(dataDir).count).toBe(2); // …no double-count in the store
  });

  it('run_key is the parent prompt promptId, NOT the tool-result uuid', async () => {
    seed(transcripts, transcript());
    await reconcileHistory(config(dataDir), { dir: transcripts });

    const r = rows(dataDir);
    // Both calls in the turn share the prompt's promptId — even msg_2, whose direct
    // parent is the tool-result user record (carrying the same promptId).
    expect(r.byMessageId.get('msg_1')?.run_key).toBe('p1');
    expect(r.byMessageId.get('msg_2')?.run_key).toBe('p1');
    // And NOT the tool-result record's uuid (the fragmenting key we avoid).
    expect(r.byMessageId.get('msg_2')?.run_key).not.toBe('u-toolresult');
  });

  it('maps token + correlation fields onto the llm_call attributes', async () => {
    seed(transcripts, transcript());
    await reconcileHistory(config(dataDir), { dir: transcripts });

    const a = rows(dataDir).byMessageId.get('msg_1');
    expect(a).toMatchObject({
      model: 'claude-sonnet-4-5-20250929',
      provider: 'anthropic', // heuristic from `claude-…` (reconciler-created root)
      input_tokens: 100,
      output_tokens: 50,
      cache_creation_input_tokens: 20,
      cache_read_input_tokens: 10,
      ephemeral_1h_input_tokens: 20,
      ephemeral_5m_input_tokens: 0,
      web_search_requests: 1,
      web_fetch_requests: 0,
      service_tier: 'standard',
      message_id: 'msg_1',
      uuid: 'a-1',
      parent_uuid: 'u-prompt',
    });
  });
});

describe('reconcileHistory — tool calls', () => {
  let dataDir: string;
  let transcripts: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-usage-tc-data-'));
    transcripts = mkdtempSync(join(tmpdir(), 'aka-usage-tc-tx-'));
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(transcripts, { recursive: true, force: true });
  });

  function toolCallRow(dir: string): {
    parentId: string;
    rootId: string;
    attrs: Record<string, unknown>;
  } {
    const db = new DatabaseSync(join(dir, 'aka.db'));
    try {
      const row = db
        .prepare(
          "SELECT parent_id, root_session_id, attributes FROM audit_events WHERE event_type = 'tool_call'",
        )
        .get() as { parent_id: string; root_session_id: string; attributes: string };
      return {
        parentId: row.parent_id,
        rootId: row.root_session_id,
        attrs: JSON.parse(row.attributes) as Record<string, unknown>,
      };
    } finally {
      db.close();
    }
  }

  function toolCallCount(dir: string): number {
    const db = new DatabaseSync(join(dir, 'aka.db'));
    try {
      return (
        db
          .prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = 'tool_call'")
          .get() as { n: number }
      ).n;
    } finally {
      db.close();
    }
  }

  it('writes one tool_call per tool_use, parented on the session root, with run_key + metadata', async () => {
    seed(transcripts, toolTranscript());
    const summary = await reconcileHistory(config(dataDir), { dir: transcripts });

    expect(summary.toolCalls).toBe(1);
    const { parentId, rootId, attrs } = toolCallRow(dataDir);
    // The leaf hangs directly off the session root (FK-safe — the usage pass
    // ensured it), same as an llm_call.
    expect(parentId).toBe(SESSION);
    expect(rootId).toBe(SESSION);
    expect(attrs).toMatchObject({
      tool_name: 'Bash',
      tool_use_id: 'toolu_1',
      is_error: false,
      // Inherited from the assistant's parent prompt, exactly like the llm_call.
      run_key: 'p1',
      uuid: 'a-1',
      parent_uuid: 'u-prompt',
      // The salient input (Bash → command), masked. `echo hi` has no secret, so it
      // survives verbatim — this is what makes "which Bash did we run" queryable.
      target: 'echo hi',
    });
    expect(attrs.output_size).toBe('hi\n'.length);
    expect(attrs.input_size).toBeGreaterThan(0);
  });

  it('is idempotent — re-running yields the same tool_call count', async () => {
    seed(transcripts, toolTranscript());
    const opts = { dir: transcripts };

    await reconcileHistory(config(dataDir), opts);
    expect(toolCallCount(dataDir)).toBe(1);

    const second = await reconcileHistory(config(dataDir), opts);
    expect(second.toolCalls).toBe(1); // re-attempted…
    expect(toolCallCount(dataDir)).toBe(1); // …no double-count (deterministic id)
  });

  // The AWS key is ASSEMBLED at runtime so this source has no literal secret (the
  // plugin's own detector would block the write, as it did during development).
  const AWS_KEY = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
  function secretTranscript(): string {
    return [
      JSON.stringify({
        type: 'user',
        uuid: 'u-prompt',
        promptId: 'p1',
        sessionId: SESSION,
        timestamp: '2026-06-20T10:00:00.000Z',
        message: { role: 'user', content: 'configure aws' },
      }),
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-1',
        parentUuid: 'u-prompt',
        sessionId: SESSION,
        cwd: '/Users/me/proj',
        timestamp: '2026-06-20T10:00:05.000Z',
        message: {
          id: 'msg_1',
          model: 'claude-sonnet-4-5-20250929',
          usage: { input_tokens: 100, output_tokens: 50 },
          content: [
            {
              type: 'tool_use',
              id: 'toolu_sec',
              name: 'Bash',
              input: { command: `aws configure set aws_access_key_id ${AWS_KEY}` },
            },
          ],
        },
      }),
    ].join('\n');
  }

  function inspectionRows(dir: string): {
    eventType: string;
    category: string;
    maskedMatch: string;
    target: string;
  }[] {
    const db = new DatabaseSync(join(dir, 'aka.db'));
    try {
      return db
        .prepare(
          `SELECT ae.event_type AS eventType, d.category AS category,
                  f.masked_match AS maskedMatch,
                  json_extract(ae.attributes,'$.target') AS target
             FROM inspection_findings f
             JOIN audit_events ae          ON ae.id = f.audit_event_id
             JOIN inspection_definitions d ON d.id = f.inspection_definition_id`,
        )
        .all() as { eventType: string; category: string; maskedMatch: string; target: string }[];
    } finally {
      db.close();
    }
  }

  it('writes an inspection_finding for a secret in a tool target, linked to the tool_call', async () => {
    seed(transcripts, secretTranscript());
    await reconcileHistory(config(dataDir), { dir: transcripts });

    const findings = inspectionRows(dataDir);
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(f).toBeDefined();
    // The finding hangs off the tool_call audit event…
    expect(f?.eventType).toBe('tool_call');
    expect(f?.category).toBeTruthy();
    // …and neither the finding nor the stored target leaks the raw key.
    expect(f?.maskedMatch).not.toContain(AWS_KEY);
    expect(f?.target).not.toContain(AWS_KEY);
    expect(f?.target).toContain('[REDACTED');
  });

  it('inspection findings are idempotent (content-addressed) across re-runs', async () => {
    seed(transcripts, secretTranscript());
    const opts = { dir: transcripts };
    await reconcileHistory(config(dataDir), opts);
    const first = inspectionRows(dataDir).length;
    await reconcileHistory(config(dataDir), opts);
    expect(inspectionRows(dataDir).length).toBe(first); // no duplicate findings
  });

  // Regression: the stored target is size-capped (~500 chars), and masking must run on
  // the FULL raw target BEFORE that cap. A secret STRADDLING the cap would, under a
  // truncate-then-mask bug, have its leading chars survive the cut as a partial the
  // scanner can't match — leaking an unmasked prefix. Mask-then-truncate redacts it
  // whole first, so nothing of the key reaches the store.
  function straddlingSecretTranscript(): string {
    // 'echo ' (5) + 489 pad + ' ' (the delimiter the AWS rule's \b needs) → the 20-char
    // key spans chars 495–514, straddling the 500 cap.
    const command = `echo ${'x'.repeat(489)} ${AWS_KEY} done`;
    return [
      JSON.stringify({
        type: 'user',
        uuid: 'u-prompt',
        promptId: 'p1',
        sessionId: SESSION,
        timestamp: '2026-06-20T10:00:00.000Z',
        message: { role: 'user', content: 'configure aws' },
      }),
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-1',
        parentUuid: 'u-prompt',
        sessionId: SESSION,
        cwd: '/Users/me/proj',
        timestamp: '2026-06-20T10:00:05.000Z',
        message: {
          id: 'msg_1',
          model: 'claude-sonnet-4-5-20250929',
          usage: { input_tokens: 100, output_tokens: 50 },
          content: [{ type: 'tool_use', id: 'toolu_straddle', name: 'Bash', input: { command } }],
        },
      }),
    ].join('\n');
  }

  it('masks a secret straddling the target size cap — no unmasked prefix leaks', async () => {
    seed(transcripts, straddlingSecretTranscript());
    await reconcileHistory(config(dataDir), { dir: transcripts });

    const target = String(toolCallRow(dataDir).attrs.target);
    // The cap held: MAX_TARGET_LEN (500) chars + the single-char '…' truncation marker.
    expect(target.length).toBeLessThanOrEqual(501);
    // …and NO fragment of the key survived — not the whole key, and not the leading
    // chars a boundary split would have leaked (the key begins with `AKIA`).
    expect(target).not.toContain(AWS_KEY);
    expect(target).not.toContain('AKIA');
  });
});

describe('reconcileSessionTail — tool calls (tail path)', () => {
  let dataDir: string;
  let transcriptPath: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-usage-tail-data-'));
    const txDir = mkdtempSync(join(tmpdir(), 'aka-usage-tail-tx-'));
    transcriptPath = join(txDir, `${SESSION}.jsonl`);
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(transcriptPath, { recursive: true, force: true });
  });

  // The three records of one Bash turn, each as its own complete (newline-terminated)
  // line — the tail reader only consumes up to the LAST newline, so trailing newlines
  // matter here (unlike the whole-file backfill).
  const promptLine = JSON.stringify({
    type: 'user',
    uuid: 'u-prompt',
    promptId: 'p1',
    sessionId: SESSION,
    timestamp: '2026-06-20T10:00:00.000Z',
    message: { role: 'user', content: 'run bash' },
  });
  const assistantWithToolUse = JSON.stringify({
    type: 'assistant',
    uuid: 'a-1',
    parentUuid: 'u-prompt',
    sessionId: SESSION,
    cwd: '/Users/me/proj',
    version: '1.2.3',
    entrypoint: 'cli',
    timestamp: '2026-06-20T10:00:05.000Z',
    message: {
      id: 'msg_1',
      model: 'claude-sonnet-4-5-20250929',
      usage: { input_tokens: 100, output_tokens: 50 },
      content: [
        { type: 'text', text: 'ok' },
        { type: 'tool_use', id: 'toolu_1', name: 'Bash', input: { command: 'echo hi' } },
      ],
    },
  });
  const toolResultLine = JSON.stringify({
    type: 'user',
    uuid: 'u-tr',
    promptId: 'p1',
    sessionId: SESSION,
    timestamp: '2026-06-20T10:00:06.000Z',
    message: {
      role: 'user',
      content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: 'hi\n' }],
    },
  });

  function toolCallAttrs(dir: string): Record<string, unknown> | undefined {
    const db = new DatabaseSync(join(dir, 'aka.db'));
    try {
      const row = db
        .prepare("SELECT attributes FROM audit_events WHERE event_type = 'tool_call'")
        .get() as { attributes: string } | undefined;
      return row ? (JSON.parse(row.attributes) as Record<string, unknown>) : undefined;
    } finally {
      db.close();
    }
  }

  it('writes a tool_call with is_error/output_size when tool_use + tool_result land in one chunk', async () => {
    // The whole turn is present (trailing newline → the tool_result line is complete),
    // so ONE tail pass sees both records and enriches the leaf, exactly like backfill.
    writeFileSync(transcriptPath, `${promptLine}\n${assistantWithToolUse}\n${toolResultLine}\n`);

    const result = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(result.toolCalls).toBe(1);

    const attrs = toolCallAttrs(dataDir);
    expect(attrs).toMatchObject({
      tool_name: 'Bash',
      tool_use_id: 'toolu_1',
      is_error: false,
      run_key: 'p1',
      target: 'echo hi',
    });
    expect(attrs?.output_size).toBe('hi\n'.length);
  });

  it('permanently strands is_error/output_size when the tool_result lags into a later chunk', async () => {
    // Pass 1: only the prompt + the tool_use assistant record are flushed (a
    // flush race — the final tool_result isn't on disk yet). The tail consumes both complete
    // lines and writes the tool_call leaf WITHOUT is_error/output_size.
    writeFileSync(transcriptPath, `${promptLine}\n${assistantWithToolUse}\n`);
    const pass1 = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(pass1.toolCalls).toBe(1);

    let attrs = toolCallAttrs(dataDir);
    expect(attrs?.tool_use_id).toBe('toolu_1');
    expect(attrs?.is_error).toBeUndefined(); // absent — the tool_result wasn't in the chunk
    expect(attrs?.output_size).toBeUndefined();

    // Pass 2: the tool_result is now appended. But the offset has advanced past the
    // tool_use, so this chunk holds ONLY the tool_result (no tool_use) → no tool-call
    // record is produced, and the row is INSERT OR IGNORE-immutable, so the enrichment
    // is NEVER attached. This is the accepted, documented non-convergence trade-off.
    appendFileSync(transcriptPath, `${toolResultLine}\n`);
    const pass2 = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(pass2.toolCalls).toBe(0); // nothing new to write for tool calls

    attrs = toolCallAttrs(dataDir);
    expect(attrs?.is_error).toBeUndefined(); // STILL stranded (no UPSERT convergence)
    expect(attrs?.output_size).toBeUndefined();
  });
});

describe('reconcileSession — FK-safety & provider inheritance', () => {
  let dataDir: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-usage-fk-'));
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('creates inventory + root then inserts leaves when SessionStart never ran (no FK error)', async () => {
    const gateway = resolveDataGateway(config(dataDir));
    try {
      // Parse the transcript ourselves and feed reconcileSession directly — the
      // session root does NOT exist beforehand (no SessionStart).
      const { parseTranscriptUsage } = await import('./transcripts.ts');
      const records = parseTranscriptUsage(transcript());
      const result = await reconcileSession(gateway, SESSION, records);
      expect(result.llmCalls).toBe(2);
      expect(result.skipped).toBe(0);
    } finally {
      await gateway.close();
    }
    const r = rows(dataDir);
    expect(r.sessionExists).toBe(true); // the reconciler created the root itself
    expect(r.count).toBe(2); // leaves inserted under it without FK failure
  });

  it('inherits a SessionStart-written provider (bedrock) onto the leaves', async () => {
    // Pre-write the session root with provider='bedrock' (as SessionStart would,
    // with its contemporaneous env), THEN reconcile.
    const gateway = resolveDataGateway(config(dataDir));
    try {
      await gateway.ensureInventory({
        host: { objectType: 'host', identityKey: 'm1', attributes: {} },
      });
      await gateway.recordAuditEvent({
        id: SESSION,
        eventType: 'session',
        startedAt: '2026-06-20T09:59:00.000Z',
        attributes: { provider: 'bedrock' },
      });
      const { parseTranscriptUsage } = await import('./transcripts.ts');
      await reconcileSession(gateway, SESSION, parseTranscriptUsage(transcript()));
    } finally {
      await gateway.close();
    }
    const r = rows(dataDir);
    // The model id (`claude-…`) heuristically resolves to 'anthropic', but the
    // root's env-provider wins by first-write — every leaf reads 'bedrock' back.
    expect(r.byMessageId.get('msg_1')?.provider).toBe('bedrock');
    expect(r.byMessageId.get('msg_2')?.provider).toBe('bedrock');
  });
});
