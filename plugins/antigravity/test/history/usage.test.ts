// Adapted from plugins/claude-code/src/history/usage.test.ts, restructured
// around Antigravity's simpler model: `turn_id` is stamped directly on each event
// (see transcripts.ts), so there is no Claude-Code-style uuid→promptId join
// to exercise here — the run_key assertions instead confirm each usage/tool
// record carries its OWN turn_id straight through.
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  resolveDataGateway,
  setDefaultGatewayFactory,
  standaloneGatewayFactory,
} from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { PLUGIN_PACKAGE, pluginBuild } from '../../src/build-info.ts';
import {
  reconcileHistory,
  reconcileSession,
  reconcileSessionTail,
} from '../../src/history/usage.ts';

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
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: { provider: 'google' },
  };
}

const SESSION = 'sess-abc';

// The fixtures below carry absolute timestamps, but reconcileHistory's window
// is relative to `now` — left unpinned, the fixtures age out of the window and
// every backfill test silently starts reconciling zero records.
const FIXTURE_NOW = Date.parse('2026-06-21T00:00:00.000Z');

function line(obj: unknown): string {
  return JSON.stringify(obj);
}

const sessionMeta = line({
  timestamp: '2026-06-20T10:00:00.000Z',
  type: 'session_meta',
  payload: {
    session_id: SESSION,
    id: 'thread-1',
    timestamp: '2026-06-20T10:00:00.000Z',
    cwd: '/Users/me/proj',
    originator: 'codex_cli_rs',
    cli_version: '0.140.0',
  },
});

const turnContext = line({
  timestamp: '2026-06-20T10:00:01.000Z',
  type: 'turn_context',
  payload: { turn_id: 'turn-1', cwd: '/Users/me/proj', model: 'gemini-3-pro' },
});

function tokenCount(
  timestamp: string,
  usage: { input: number; output: number; cached?: number },
): string {
  return line({
    timestamp,
    type: 'event_msg',
    payload: {
      type: 'token_count',
      info: {
        total_token_usage: {},
        last_token_usage: {
          input_tokens: usage.input,
          output_tokens: usage.output,
          cached_input_tokens: usage.cached ?? 0,
        },
        model_context_window: 200000,
      },
      rate_limits: null,
    },
  });
}

// One turn: session_meta + turn_context + a single token_count event.
function transcript(): string {
  return [
    sessionMeta,
    turnContext,
    tokenCount('2026-06-20T10:00:05.000Z', { input: 100, output: 50 }),
  ].join('\n');
}

function seed(root: string, jsonl: string): void {
  const dir = join(root, '2026', '06', '20');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `rollout-${SESSION}.jsonl`), jsonl);
}

function sessionAttrs(dataDir: string, sessionId: string): Record<string, unknown> | undefined {
  const db = new DatabaseSync(join(dataDir, 'aka.db'));
  try {
    const row = db
      .prepare("SELECT attributes FROM audit_events WHERE event_type = 'session' AND id = :id")
      .get({ id: sessionId }) as { attributes: string } | undefined;
    return row ? (JSON.parse(row.attributes) as Record<string, unknown>) : undefined;
  } finally {
    db.close();
  }
}

function rows(dataDir: string): {
  count: number;
  attrsByOrdinal: Record<string, unknown>[];
  sessionExists: boolean;
} {
  const db = new DatabaseSync(join(dataDir, 'aka.db'));
  try {
    const calls = db
      .prepare("SELECT id, started_at, attributes FROM audit_events WHERE event_type = 'llm_call'")
      .all() as { id: string; started_at: number; attributes: string }[];
    const attrsByOrdinal = calls.map((c) => JSON.parse(c.attributes) as Record<string, unknown>);
    const session = db
      .prepare("SELECT id FROM audit_events WHERE event_type = 'session' AND id = :id")
      .get({ id: SESSION });
    return { count: calls.length, attrsByOrdinal, sessionExists: session != null };
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

  it('writes one llm_call per token_count event and a session root', async () => {
    seed(transcripts, transcript());
    const summary = await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });

    expect(summary.sessions).toBe(1);
    expect(summary.llmCalls).toBe(1);
    expect(summary.skipped).toBe(0);

    const r = rows(dataDir);
    expect(r.count).toBe(1);
    expect(r.sessionExists).toBe(true);
  });

  it('is idempotent — re-running yields the same row count (deterministic ids + INSERT OR IGNORE)', async () => {
    seed(transcripts, transcript());
    const opts = { dir: transcripts, now: FIXTURE_NOW };

    const first = await reconcileHistory(config(dataDir), opts);
    expect(first.llmCalls).toBe(1);
    expect(rows(dataDir).count).toBe(1);

    const second = await reconcileHistory(config(dataDir), opts);
    expect(second.llmCalls).toBe(1);
    expect(rows(dataDir).count).toBe(1);
  });

  it('run_key is the turn_id stamped on the event, and the model comes from turn_context', async () => {
    seed(transcripts, transcript());
    await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });

    const attrs = rows(dataDir).attrsByOrdinal[0];
    expect(attrs).toMatchObject({
      model: 'gemini-3-pro',
      provider: 'google', // heuristic from `gemini-…` (reconciler-created root)
      input_tokens: 100,
      output_tokens: 50,
      run_key: 'turn-1',
    });
  });

  it('stamps harness_interface from session_meta.originator onto the session root (backfill)', async () => {
    seed(transcripts, transcript());
    await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });
    expect(sessionAttrs(dataDir, SESSION)?.harness_interface).toBe('codex_cli_rs');
  });

  it('distinguishes a ChatGPT-desktop-hosted session from a terminal one via harness_interface', async () => {
    const desktopSessionMeta = line({
      timestamp: '2026-06-20T10:00:00.000Z',
      type: 'session_meta',
      payload: {
        session_id: SESSION,
        id: 'thread-1',
        timestamp: '2026-06-20T10:00:00.000Z',
        cwd: '/Users/me/proj',
        originator: 'codex_desktop',
        cli_version: '0.140.0',
      },
    });
    seed(
      transcripts,
      [
        desktopSessionMeta,
        turnContext,
        tokenCount('2026-06-20T10:00:05.000Z', { input: 100, output: 50 }),
      ].join('\n'),
    );
    await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });
    expect(sessionAttrs(dataDir, SESSION)?.harness_interface).toBe('codex_desktop');
  });

  it('drops an all-zero token_count event (no billable turn)', async () => {
    seed(
      transcripts,
      [
        sessionMeta,
        turnContext,
        tokenCount('2026-06-20T10:00:05.000Z', { input: 0, output: 0 }),
      ].join('\n'),
    );
    const summary = await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });
    expect(summary.sessions).toBe(0);
    expect(summary.llmCalls).toBe(0);
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

  function shellTranscript(): string {
    return [
      sessionMeta,
      turnContext,
      tokenCount('2026-06-20T10:00:04.000Z', { input: 100, output: 50 }),
      line({
        timestamp: '2026-06-20T10:00:05.000Z',
        type: 'event_msg',
        payload: {
          type: 'exec_command_begin',
          call_id: 'call-1',
          turn_id: 'turn-1',
          command: ['echo', 'hi'],
          cwd: '/Users/me/proj',
          parsed_cmd: [],
        },
      }),
      line({
        timestamp: '2026-06-20T10:00:06.000Z',
        type: 'event_msg',
        payload: {
          type: 'exec_command_end',
          call_id: 'call-1',
          turn_id: 'turn-1',
          command: ['echo', 'hi'],
          cwd: '/Users/me/proj',
          parsed_cmd: [],
          stdout: 'hi\n',
          stderr: '',
          aggregated_output: 'hi\n',
          exit_code: 0,
          duration: '0.01s',
          formatted_output: 'hi\n',
          status: 'completed',
        },
      }),
    ].join('\n');
  }

  it('writes one tool_call per exec_command pair, parented on the session root, with run_key', async () => {
    seed(transcripts, shellTranscript());
    const summary = await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });

    expect(summary.toolCalls).toBe(1);
    const { parentId, rootId, attrs } = toolCallRow(dataDir);
    expect(parentId).toBe(SESSION);
    expect(rootId).toBe(SESSION);
    expect(attrs).toMatchObject({
      tool_name: 'shell',
      tool_use_id: 'call-1',
      is_error: false,
      run_key: 'turn-1',
      target: 'echo hi',
    });
    expect(attrs.output_size).toBe('hi\n'.length);
  });

  it('is idempotent — re-running yields the same tool_call count', async () => {
    seed(transcripts, shellTranscript());
    const opts = { dir: transcripts, now: FIXTURE_NOW };

    await reconcileHistory(config(dataDir), opts);
    expect(toolCallCount(dataDir)).toBe(1);

    const second = await reconcileHistory(config(dataDir), opts);
    expect(second.toolCalls).toBe(1);
    expect(toolCallCount(dataDir)).toBe(1);
  });

  // The AWS key is ASSEMBLED at runtime so this source has no literal secret.
  const AWS_KEY = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
  function secretTranscript(): string {
    return [
      sessionMeta,
      turnContext,
      tokenCount('2026-06-20T10:00:04.000Z', { input: 100, output: 50 }),
      line({
        timestamp: '2026-06-20T10:00:05.000Z',
        type: 'event_msg',
        payload: {
          type: 'exec_command_begin',
          call_id: 'call-sec',
          turn_id: 'turn-1',
          command: ['aws', 'configure', 'set', 'aws_access_key_id', AWS_KEY],
          cwd: '/Users/me/proj',
          parsed_cmd: [],
        },
      }),
      line({
        timestamp: '2026-06-20T10:00:06.000Z',
        type: 'event_msg',
        payload: {
          type: 'exec_command_end',
          call_id: 'call-sec',
          turn_id: 'turn-1',
          command: ['aws', 'configure', 'set', 'aws_access_key_id', AWS_KEY],
          cwd: '/Users/me/proj',
          parsed_cmd: [],
          stdout: '',
          stderr: '',
          aggregated_output: '',
          exit_code: 0,
          duration: '0.01s',
          formatted_output: '',
          status: 'completed',
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
    await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });

    const findings = inspectionRows(dataDir);
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(f).toBeDefined();
    expect(f?.eventType).toBe('tool_call');
    expect(f?.category).toBeTruthy();
    expect(f?.maskedMatch).not.toContain(AWS_KEY);
    expect(f?.target).not.toContain(AWS_KEY);
    expect(f?.target).toContain('[REDACTED');
  });

  it('inspection findings are idempotent (content-addressed) across re-runs', async () => {
    seed(transcripts, secretTranscript());
    const opts = { dir: transcripts, now: FIXTURE_NOW };
    await reconcileHistory(config(dataDir), opts);
    const first = inspectionRows(dataDir).length;
    await reconcileHistory(config(dataDir), opts);
    expect(inspectionRows(dataDir).length).toBe(first);
  });
});

describe('reconcileSessionTail — the live per-turn path', () => {
  let dataDir: string;
  let transcriptPath: string;
  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'aka-usage-tail-data-'));
    const txDir = mkdtempSync(join(tmpdir(), 'aka-usage-tail-tx-'));
    transcriptPath = join(txDir, `rollout-${SESSION}.jsonl`);
  });
  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(transcriptPath, { recursive: true, force: true });
  });

  const execBegin = line({
    timestamp: '2026-06-20T10:00:05.000Z',
    type: 'event_msg',
    payload: {
      type: 'exec_command_begin',
      call_id: 'call-1',
      turn_id: 'turn-1',
      command: ['echo', 'hi'],
      cwd: '/Users/me/proj',
      parsed_cmd: [],
    },
  });
  const execEnd = line({
    timestamp: '2026-06-20T10:00:06.000Z',
    type: 'event_msg',
    payload: {
      type: 'exec_command_end',
      call_id: 'call-1',
      turn_id: 'turn-1',
      command: ['echo', 'hi'],
      cwd: '/Users/me/proj',
      parsed_cmd: [],
      stdout: 'hi\n',
      stderr: '',
      aggregated_output: 'hi\n',
      exit_code: 0,
      duration: '0.01s',
      formatted_output: 'hi\n',
      status: 'completed',
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

  it('writes a tool_call when exec_command_begin/end land in one tail chunk', async () => {
    const usageLine = tokenCount('2026-06-20T10:00:04.000Z', { input: 100, output: 50 });
    writeFileSync(
      transcriptPath,
      `${sessionMeta}\n${turnContext}\n${usageLine}\n${execBegin}\n${execEnd}\n`,
    );

    const result = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(result.toolCalls).toBe(1);
    expect(result.llmCalls).toBe(1);

    const attrs = toolCallAttrs(dataDir);
    expect(attrs).toMatchObject({
      tool_name: 'shell',
      tool_use_id: 'call-1',
      is_error: false,
      run_key: 'turn-1',
      target: 'echo hi',
    });
    expect(attrs?.output_size).toBe('hi\n'.length);
  });

  it('a second tail pass consumes only the newly-appended turn', async () => {
    const usageLine = tokenCount('2026-06-20T10:00:04.000Z', { input: 100, output: 50 });
    writeFileSync(transcriptPath, `${sessionMeta}\n${turnContext}\n${usageLine}\n`);
    const first = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(first.llmCalls).toBe(1);

    appendFileSync(transcriptPath, `${execBegin}\n${execEnd}\n`);
    const second = await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    expect(second.llmCalls).toBe(0); // no new token_count event
    expect(second.toolCalls).toBe(1); // the new turn's tool call
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
      const { parseTranscriptUsage } = await import('../../src/history/transcripts.ts');
      const records = parseTranscriptUsage(transcript());
      const result = await reconcileSession(gateway, SESSION, records);
      expect(result.llmCalls).toBe(1);
      expect(result.skipped).toBe(0);
    } finally {
      await gateway.close();
    }
    const r = rows(dataDir);
    expect(r.sessionExists).toBe(true);
    expect(r.count).toBe(1);
  });

  it('inherits a SessionStart-written provider (gateway) onto the leaves', async () => {
    const gateway = resolveDataGateway(config(dataDir));
    try {
      await gateway.ensureInventory({
        host: { objectType: 'host', identityKey: 'm1', attributes: {} },
      });
      await gateway.recordAuditEvent({
        id: SESSION,
        eventType: 'session',
        startedAt: '2026-06-20T09:59:00.000Z',
        attributes: { provider: 'gateway' },
      });
      const { parseTranscriptUsage } = await import('../../src/history/transcripts.ts');
      await reconcileSession(gateway, SESSION, parseTranscriptUsage(transcript()));
    } finally {
      await gateway.close();
    }
    // The model id (`gemini-3-pro`) heuristically resolves to 'google', but the
    // root's env-provider wins by first-write — the leaf reads 'gateway' back.
    expect(rows(dataDir).attrsByOrdinal[0]?.provider).toBe('gateway');
  });
});

describe('the reconcilers resolve their gateway with this build as pluginBuild', () => {
  // The reconciler can win the hourly posture throttle just as the first
  // PreInvocation can, and a report resolved without the build identity clears
  // the control plane's plugin columns — so reverting the reconciler entry to
  // a bare resolveDataGateway(config) must fail here. Both reconciler entries
  // resolve through the one reconcileGateway helper this drives.
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

  it('reconcileHistory (the backfill sweep)', async () => {
    let captured: unknown = 'never-resolved';
    setDefaultGatewayFactory((cfg, meta) => {
      captured = meta;
      return standaloneGatewayFactory(cfg, meta);
    });
    await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });
    expect(pluginBuild()).toMatchObject({ package: PLUGIN_PACKAGE });
    expect(captured).toStrictEqual({ pluginBuild: pluginBuild() });
  });
});
