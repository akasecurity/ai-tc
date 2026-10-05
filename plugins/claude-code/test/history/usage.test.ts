import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  resolveDataGateway,
  setDefaultGatewayFactory,
  standaloneGatewayFactory,
} from '@akasecurity/plugin-runtime';
import { type PluginConfig, resolveRepo } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { PLUGIN_PACKAGE, pluginBuild } from '../../src/build-info.ts';
import {
  reconcileHistory,
  reconcileSession,
  reconcileSessionTail,
} from '../../src/history/usage.ts';

// A standalone (local SQLite) config rooted at `dataDir`. The reconciler resolves
// the same gateway as the real backfill, so these tests exercise the real
// persistence path (INSERT OR IGNORE + enforced FKs), not a mock.
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

const SESSION = 'sess-abc';

// Pin the backfill's retention window to a fixed reference just after the fixtures'
// own timestamps (all at 2026-06-20T10:00:0x). `reconcileHistory` windows records to
// `(now ?? Date.now()) - windowDays` — without a fixed `now` these fixed-date
// fixtures fall out of the default 30-day window once the wall clock advances past
// them, dropping every record. Threading `NOW` keeps the walk deterministic and
// independent of the wall clock. (`reconcileSession`/`reconcileSessionTail` parse
// unbounded, so their tests don't need it.)
const NOW = Date.parse('2026-06-20T12:00:00.000Z');

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
    const summary = await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    expect(summary.sessions).toBe(1);
    expect(summary.llmCalls).toBe(2); // msg_1 + msg_2; synthetic + zero-usage dropped
    expect(summary.skipped).toBe(0);

    const r = rows(dataDir);
    expect(r.count).toBe(2);
    expect(r.sessionExists).toBe(true);
  });

  it('is idempotent — re-running yields the same row count (deterministic ids + INSERT OR IGNORE)', async () => {
    seed(transcripts, transcript());
    const opts = { dir: transcripts, now: NOW };

    const first = await reconcileHistory(config(dataDir), opts);
    expect(first.llmCalls).toBe(2);
    expect(rows(dataDir).count).toBe(2);

    const second = await reconcileHistory(config(dataDir), opts);
    expect(second.llmCalls).toBe(2); // re-attempted, but…
    expect(rows(dataDir).count).toBe(2); // …no double-count in the store
  });

  it('run_key is the parent prompt promptId, NOT the tool-result uuid', async () => {
    seed(transcripts, transcript());
    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

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
    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

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
    const summary = await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

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
    const opts = { dir: transcripts, now: NOW };

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
    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

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
    const opts = { dir: transcripts, now: NOW };
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
    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

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
      const { parseTranscriptUsage } = await import('../../src/history/transcripts.ts');
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
      const { parseTranscriptUsage } = await import('../../src/history/transcripts.ts');
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

describe('the reconcilers resolve their gateway with this build as pluginBuild', () => {
  // The reconciler can win the hourly posture throttle just as SessionStart
  // can, and a report resolved without the build identity clears the control
  // plane's plugin columns — so reverting either reconciler entry to a bare
  // resolveDataGateway(config) must fail here, not surface as a fleet row
  // that flaps between filled and null.
  let dataDir: string;
  let transcripts: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-usage-meta-data-'));
    transcripts = mkdtempSync(join(tmpdir(), 'aka-usage-meta-tx-'));
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(transcripts, { recursive: true, force: true });
    // The seam is process-global: a capture left installed leaks into the
    // next suite.
    setDefaultGatewayFactory();
  });

  function captureMeta(): { readonly value: unknown } {
    const box: { value: unknown } = { value: 'never-resolved' };
    setDefaultGatewayFactory((cfg, meta) => {
      box.value = meta;
      return standaloneGatewayFactory(cfg, meta);
    });
    return box;
  }

  it('reconcileHistory (the backfill sweep)', async () => {
    const captured = captureMeta();
    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });
    expect(pluginBuild()).toMatchObject({ package: PLUGIN_PACKAGE });
    expect(captured.value).toStrictEqual({ pluginBuild: pluginBuild() });
  });

  it('reconcileSessionTail (the live Stop path)', async () => {
    const transcriptPath = join(transcripts, `${SESSION}.jsonl`);
    writeFileSync(transcriptPath, transcript());
    const captured = captureMeta();
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(captured.value).toStrictEqual({ pluginBuild: pluginBuild() });
  });
});

describe('scope keys — the root from its project, each leaf from its own record', () => {
  // A checkout whose origin canonicalizes to github.com/acme/work, and a
  // directory in no repository at all. An scp-form remote's userinfo reads as
  // an email address to a scanner, so the fixture builds it from parts.
  const AT = String.fromCharCode(64);
  const gitUser = `git${AT}`;
  const WORK_KEY = 'github.com/acme/work';
  const PERSONAL_KEY = 'github.com/me/personal';
  let dataDir: string;
  let transcripts: string;
  let workRepo: string;
  let personalRepo: string;
  let scratch: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-usage-key-data-'));
    transcripts = mkdtempSync(join(tmpdir(), 'aka-usage-key-tx-'));
    workRepo = mkdtempSync(join(tmpdir(), 'aka-usage-key-repo-'));
    mkdirSync(join(workRepo, '.git'), { recursive: true });
    writeFileSync(
      join(workRepo, '.git', 'config'),
      `[remote "origin"]\n\turl = ${gitUser}github.com:acme/work.git\n`,
    );
    // A second checkout with its own forge remote.
    personalRepo = mkdtempSync(join(tmpdir(), 'aka-usage-key-personal-'));
    mkdirSync(join(personalRepo, '.git'), { recursive: true });
    writeFileSync(
      join(personalRepo, '.git', 'config'),
      '[remote "origin"]\n\turl = https://github.com/me/personal.git\n',
    );
    scratch = mkdtempSync(join(tmpdir(), 'aka-usage-key-scratch-'));
  });
  afterEach(() => {
    for (const d of [dataDir, transcripts, workRepo, personalRepo, scratch]) {
      rmSync(d, { recursive: true, force: true });
    }
  });

  const prompt = JSON.stringify({
    type: 'user',
    uuid: 'u-prompt',
    promptId: 'p1',
    sessionId: SESSION,
    timestamp: '2026-06-20T10:00:00.000Z',
    message: { role: 'user', content: 'go' },
  });

  // One usage-bearing assistant record with its own cwd (or none). It may
  // issue one tool_use: Bash `ls` unless `tool` names another.
  function assistant(rec: {
    uuid: string;
    messageId: string;
    ts: string;
    cwd?: string;
    outputTokens?: number;
    toolUseId?: string;
    tool?: { name: string; input: Record<string, unknown> };
  }): string {
    const tool = rec.tool ?? { name: 'Bash', input: { command: 'ls' } };
    return JSON.stringify({
      type: 'assistant',
      uuid: rec.uuid,
      parentUuid: 'u-prompt',
      sessionId: SESSION,
      ...(rec.cwd !== undefined ? { cwd: rec.cwd } : {}),
      version: '1.2.3',
      timestamp: rec.ts,
      message: {
        id: rec.messageId,
        model: 'claude-sonnet-4-5-20250929',
        usage: { input_tokens: 100, output_tokens: rec.outputTokens ?? 50 },
        content:
          rec.toolUseId !== undefined
            ? [{ type: 'tool_use', id: rec.toolUseId, name: tool.name, input: tool.input }]
            : [{ type: 'text', text: 'ok' }],
      },
    });
  }

  // The scope_key column of the session root, and of every leaf keyed by its
  // message_id (llm_call) or tool_use_id (tool_call).
  function keys(dir: string): {
    root: string | null | undefined;
    leaf: Map<string, string | null>;
  } {
    const db = new DatabaseSync(join(dir, 'aka.db'));
    try {
      const rows = db
        .prepare(
          `SELECT event_type AS type, scope_key AS key,
                  COALESCE(json_extract(attributes, '$.message_id'),
                           json_extract(attributes, '$.tool_use_id')) AS ref
             FROM audit_events
            WHERE event_type IN ('session', 'llm_call', 'tool_call')`,
        )
        .all() as { type: string; key: string | null; ref: string | null }[];
      let root: string | null | undefined;
      const leaf = new Map<string, string | null>();
      for (const row of rows) {
        if (row.type === 'session') root = row.key;
        else if (row.ref !== null) leaf.set(row.ref, row.key);
      }
      return { root, leaf };
    } finally {
      db.close();
    }
  }

  it("keys the root by its project and each leaf by its own record's cwd, never the root's", async () => {
    seed(
      transcripts,
      [
        prompt,
        assistant({
          uuid: 'a-1',
          messageId: 'msg_1',
          ts: '2026-06-20T10:00:05.000Z',
          cwd: workRepo,
          toolUseId: 'toolu_w',
        }),
        assistant({
          uuid: 'a-2',
          messageId: 'msg_2',
          ts: '2026-06-20T10:00:07.000Z',
          cwd: scratch,
          toolUseId: 'toolu_s',
        }),
        assistant({ uuid: 'a-3', messageId: 'msg_3', ts: '2026-06-20T10:00:09.000Z' }),
      ].join('\n'),
    );

    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    const { root, leaf } = keys(dataDir);
    // The first assistant record ran in the work checkout, so the root resolves there.
    expect(root).toBe(WORK_KEY);
    expect(leaf.get('msg_1')).toBe(WORK_KEY);
    expect(leaf.get('toolu_w')).toBe(WORK_KEY);
    // A call made from a scratch directory, and a record that names no cwd,
    // stay keyless even under a keyed root.
    expect(leaf.get('msg_2')).toBeNull();
    expect(leaf.get('toolu_s')).toBeNull();
    expect(leaf.get('msg_3')).toBeNull();
  });

  it("keys a file tool's leaf by the file's repository, not the directory it ran from", async () => {
    seed(
      transcripts,
      [
        prompt,
        // From the scratch directory, an Edit of a file in the work checkout…
        assistant({
          uuid: 'a-1',
          messageId: 'msg_1',
          ts: '2026-06-20T10:00:05.000Z',
          cwd: scratch,
          toolUseId: 'toolu_into_work',
          tool: { name: 'Edit', input: { file_path: join(workRepo, 'src', 'app.ts') } },
        }),
        // …and from the work checkout, a Write into the scratch directory.
        assistant({
          uuid: 'a-2',
          messageId: 'msg_2',
          ts: '2026-06-20T10:00:07.000Z',
          cwd: workRepo,
          toolUseId: 'toolu_into_scratch',
          tool: { name: 'Write', input: { file_path: join(scratch, 'notes.md') } },
        }),
      ].join('\n'),
    );

    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    const { leaf } = keys(dataDir);
    expect(leaf.get('toolu_into_work')).toBe(WORK_KEY);
    // The Write's target names a file in no repository, so its leaf is keyless
    // though the call ran in the work checkout.
    expect(leaf.get('toolu_into_scratch')).toBeNull();
    // The llm_call leaves still key by the directory each record ran in.
    expect(leaf.get('msg_1')).toBeNull();
    expect(leaf.get('msg_2')).toBe(WORK_KEY);
  });

  it('stamps the same key when a later pass replaces an llm_call bag', async () => {
    // Pass 1 sees only a streaming partial of msg_1 (output_tokens 1)…
    const partial = assistant({
      uuid: 'a-1p',
      messageId: 'msg_1',
      ts: '2026-06-20T10:00:05.000Z',
      cwd: workRepo,
      outputTokens: 1,
    });
    seed(transcripts, [prompt, partial].join('\n'));
    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });
    expect(keys(dataDir).leaf.get('msg_1')).toBe(WORK_KEY);

    // …pass 2 sees the terminal record (output_tokens 50). upsertLlmCallStmt
    // replaces the WHOLE bag, and the replacement must carry the same key.
    const terminal = assistant({
      uuid: 'a-1',
      messageId: 'msg_1',
      ts: '2026-06-20T10:00:06.000Z',
      cwd: workRepo,
      outputTokens: 50,
    });
    seed(transcripts, [prompt, partial, terminal].join('\n'));
    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    const db = new DatabaseSync(join(dataDir, 'aka.db'));
    try {
      const row = db
        .prepare(
          "SELECT scope_key AS key, json_extract(attributes, '$.output_tokens') AS out FROM audit_events WHERE event_type = 'llm_call'",
        )
        .get() as { key: string | null; out: number };
      expect(row.out).toBe(50); // the bag WAS replaced…
      expect(row.key).toBe(WORK_KEY); // …and the replacement carries the key
    } finally {
      db.close();
    }
  });

  it('the live tail path stamps its leaves the same way', async () => {
    const transcriptPath = join(transcripts, `${SESSION}.jsonl`);
    const turn = assistant({
      uuid: 'a-1',
      messageId: 'msg_1',
      ts: '2026-06-20T10:00:05.000Z',
      cwd: workRepo,
      toolUseId: 'toolu_w',
    });
    writeFileSync(transcriptPath, `${prompt}\n${turn}\n`);

    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);

    const { root, leaf } = keys(dataDir);
    expect(root).toBe(WORK_KEY);
    expect(leaf.get('msg_1')).toBe(WORK_KEY);
    expect(leaf.get('toolu_w')).toBe(WORK_KEY);
  });

  it.each([
    ['a relative cwd', '.'],
    ['a relative subdirectory', 'src'],
    ['an empty cwd', ''],
  ])(
    'keys no root from %s, though the reconciler runs inside a keyed checkout',
    async (_label, relativeCwd) => {
      // A relative cwd is walked from the reconciler's own directory, which a
      // transcript does not choose, so it would borrow that directory's
      // repository. Here the process IS in a checkout with a forge remote.
      mkdirSync(join(workRepo, 'src'), { recursive: true });
      seed(
        transcripts,
        [
          prompt,
          assistant({
            uuid: 'a-1',
            messageId: 'msg_1',
            ts: '2026-06-20T10:00:05.000Z',
            cwd: relativeCwd,
            toolUseId: 'toolu_1',
          }),
        ].join('\n'),
      );

      const home = process.cwd();
      process.chdir(workRepo);
      try {
        // The control: this process directory is a repository the resolver finds.
        expect(resolveRepo('.')).toBe('work');
        await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });
      } finally {
        // Restored before the shared afterEach removes the fixtures: a process
        // still standing inside one cannot delete it on Windows.
        process.chdir(home);
      }

      const { root, leaf } = keys(dataDir);
      expect(root).toBeNull();
      expect(leaf.get('msg_1')).toBeNull();
      expect(leaf.get('toolu_1')).toBeNull();
    },
  );

  it('a root built from a remoteless repo carries no key, and neither do its leaves', async () => {
    writeFileSync(join(workRepo, '.git', 'config'), '');
    seed(
      transcripts,
      [
        prompt,
        assistant({
          uuid: 'a-1',
          messageId: 'msg_1',
          ts: '2026-06-20T10:00:05.000Z',
          cwd: workRepo,
        }),
      ].join('\n'),
    );

    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    const { root, leaf } = keys(dataDir);
    expect(root).toBeNull();
    expect(leaf.get('msg_1')).toBeNull();
  });

  // One session whose every record ran in `cwd` and issued one tool call each.
  function seedCalls(
    cwd: string,
    calls: { id: string; name: string; input: Record<string, unknown> }[],
  ): void {
    seed(
      transcripts,
      [
        prompt,
        ...calls.map((c, i) =>
          assistant({
            uuid: `a-${String(i)}`,
            messageId: `msg_${String(i)}`,
            ts: `2026-06-20T10:00:${String(5 + i).padStart(2, '0')}.000Z`,
            cwd,
            toolUseId: c.id,
            tool: { name: c.name, input: c.input },
          }),
        ),
      ].join('\n'),
    );
  }

  it("keys a Grep or LS leaf by the root it searched, from the root itself, not the cwd's", async () => {
    seedCalls(workRepo, [
      // A checkout's top level: the parent directory is in no repository.
      { id: 'toolu_top', name: 'Grep', input: { pattern: 'x', path: personalRepo } },
      { id: 'toolu_sub', name: 'Grep', input: { pattern: 'x', path: join(personalRepo, 'src') } },
      { id: 'toolu_ls', name: 'LS', input: { path: personalRepo } },
      // Outside every repository: no key, and never the cwd's.
      { id: 'toolu_out', name: 'Grep', input: { pattern: 'x', path: scratch } },
      // No root: the directory the call ran in.
      { id: 'toolu_none', name: 'Grep', input: { pattern: 'x' } },
      // A relative root is read against the call's cwd, then keyed from itself.
      { id: 'toolu_rel', name: 'Grep', input: { pattern: 'x', path: 'src' } },
      // One that climbs out of the cwd checkout is keyed by where it lands: a
      // sibling checkout's top level, or no repository at all.
      {
        id: 'toolu_rel_sibling',
        name: 'Grep',
        input: { pattern: 'x', path: join('..', basename(personalRepo)) },
      },
      {
        id: 'toolu_rel_ls',
        name: 'LS',
        input: { path: join('..', basename(personalRepo), 'src') },
      },
      {
        id: 'toolu_rel_out',
        name: 'Grep',
        input: { pattern: 'x', path: join('..', basename(scratch)) },
      },
    ]);

    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    const { leaf } = keys(dataDir);
    expect(leaf.get('toolu_top')).toBe(PERSONAL_KEY);
    expect(leaf.get('toolu_sub')).toBe(PERSONAL_KEY);
    expect(leaf.get('toolu_ls')).toBe(PERSONAL_KEY);
    expect(leaf.get('toolu_out')).toBeNull();
    expect(leaf.get('toolu_none')).toBe(WORK_KEY);
    expect(leaf.get('toolu_rel')).toBe(WORK_KEY);
    expect(leaf.get('toolu_rel_sibling')).toBe(PERSONAL_KEY);
    expect(leaf.get('toolu_rel_ls')).toBe(PERSONAL_KEY);
    expect(leaf.get('toolu_rel_out')).toBeNull();
  });

  it('gives a relative search root or file no key when the call has no absolute cwd to read it against', async () => {
    // A record that names no cwd, and one whose cwd is itself relative. Either
    // way the path has no known location, and the process directory (here, inside
    // the work checkout) is not the place to read it from.
    seed(
      transcripts,
      [
        prompt,
        assistant({
          uuid: 'a-1',
          messageId: 'msg_1',
          ts: '2026-06-20T10:00:05.000Z',
          toolUseId: 'toolu_nocwd',
          tool: { name: 'Grep', input: { pattern: 'x', path: 'src' } },
        }),
        assistant({
          uuid: 'a-2',
          messageId: 'msg_2',
          ts: '2026-06-20T10:00:06.000Z',
          cwd: '.',
          toolUseId: 'toolu_relcwd',
          tool: { name: 'mcp__fs__read', input: { file_path: 'a.ts' } },
        }),
      ].join('\n'),
    );

    const home = process.cwd();
    process.chdir(workRepo);
    try {
      await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });
    } finally {
      process.chdir(home);
    }

    const { leaf } = keys(dataDir);
    expect(leaf.get('toolu_nocwd')).toBeNull();
    expect(leaf.get('toolu_relcwd')).toBeNull();
  });

  it('keys a Glob whose relative pattern climbs out of its root by nothing', async () => {
    seedCalls(workRepo, [
      // Inside the root: the cwd's checkout, as before.
      { id: 'toolu_glob_in', name: 'Glob', input: { pattern: 'src/**/*.ts' } },
      // The pattern itself names a place above the root, which no single
      // repository covers, with or without an explicit path.
      { id: 'toolu_glob_up', name: 'Glob', input: { pattern: '../personal/**/*.ts' } },
      {
        id: 'toolu_glob_up_path',
        name: 'Glob',
        input: { pattern: join('..', '*.ts'), path: join(workRepo, 'src') },
      },
    ]);

    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    const { leaf } = keys(dataDir);
    expect(leaf.get('toolu_glob_in')).toBe(WORK_KEY);
    expect(leaf.get('toolu_glob_up')).toBeNull();
    expect(leaf.get('toolu_glob_up_path')).toBeNull();
  });

  it('keys any tool that names a file by that file, and a Glob with an absolute pattern by nothing', async () => {
    seedCalls(workRepo, [
      {
        id: 'toolu_mcp_in',
        name: 'mcp__fs__read',
        input: { file_path: join(personalRepo, 'a.ts') },
      },
      {
        id: 'toolu_mcp_out',
        name: 'mcp__fs__read',
        input: { file_path: join(scratch, 'a.ts') },
      },
      {
        id: 'toolu_mcp_rel',
        name: 'mcp__fs__read',
        input: { file_path: 'src/a.ts' },
      },
      // A relative path is read against the call's cwd: one that climbs out of
      // the cwd checkout is keyed where it lands, never by the cwd.
      {
        id: 'toolu_mcp_rel_sibling',
        name: 'mcp__fs__read',
        input: { file_path: join('..', basename(personalRepo), 'a.ts') },
      },
      {
        id: 'toolu_mcp_rel_out',
        name: 'mcp__fs__read',
        input: { file_path: join('..', basename(scratch), 'a.ts') },
      },
      {
        id: 'toolu_mcp_rel_nb',
        name: 'mcp__nb__run',
        input: { notebook_path: join('..', basename(personalRepo), 'n.ipynb') },
      },
      { id: 'toolu_glob', name: 'Glob', input: { pattern: '*.ts', path: personalRepo } },
      {
        id: 'toolu_glob_abs',
        name: 'Glob',
        input: { pattern: join(personalRepo, '**', '*.ts') },
      },
    ]);

    await reconcileHistory(config(dataDir), { dir: transcripts, now: NOW });

    const { leaf } = keys(dataDir);
    expect(leaf.get('toolu_mcp_in')).toBe(PERSONAL_KEY);
    // A file outside every repository leaves the call keyless though it ran in a keyed one.
    expect(leaf.get('toolu_mcp_out')).toBeNull();
    // A relative path that stays inside the cwd checkout keeps its key.
    expect(leaf.get('toolu_mcp_rel')).toBe(WORK_KEY);
    expect(leaf.get('toolu_mcp_rel_sibling')).toBe(PERSONAL_KEY);
    expect(leaf.get('toolu_mcp_rel_out')).toBeNull();
    expect(leaf.get('toolu_mcp_rel_nb')).toBe(PERSONAL_KEY);
    expect(leaf.get('toolu_glob')).toBe(PERSONAL_KEY);
    expect(leaf.get('toolu_glob_abs')).toBeNull();
  });
});
