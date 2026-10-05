// Adapted from plugins/claude-code/src/history/usage.test.ts, restructured
// around Codex's simpler model: `turn_id` is stamped directly on each event
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
import { type PluginConfig, resolveRepo } from '@akasecurity/plugin-sdk';
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
  payload: { turn_id: 'turn-1', cwd: '/Users/me/proj', model: 'gpt-5-codex' },
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
      model: 'gpt-5-codex',
      provider: 'openai', // heuristic from `gpt-…` (reconciler-created root)
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
    // The model id (`gpt-5-codex`) heuristically resolves to 'openai', but the
    // root's env-provider wins by first-write — the leaf reads 'gateway' back.
    expect(rows(dataDir).attrsByOrdinal[0]?.provider).toBe('gateway');
  });
});

describe('the reconcilers resolve their gateway with this build as pluginBuild', () => {
  // The reconciler can win the hourly posture throttle just as the session
  // hook can, and a report resolved without the build identity clears the
  // control plane's plugin columns — so reverting the reconciler entry to a
  // bare resolveDataGateway(config) must fail here. Both reconciler entries
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

describe('scope keys — the root from its project, every leaf from where it ran', () => {
  // An scp-form remote's userinfo reads as an email address to a scanner, so
  // the fixture builds it from parts.
  const AT = String.fromCharCode(64);
  const gitUser = `git${AT}`;
  const WORK_KEY = 'github.com/acme/work';
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

  // One shell call. `cwd`, when given, is the command's own working directory
  // on both of its events.
  function exec(callId: string, beginTs: string, endTs: string, cwd?: string): string {
    const own = cwd !== undefined ? { cwd } : {};
    return [
      line({
        timestamp: beginTs,
        type: 'event_msg',
        payload: {
          type: 'exec_command_begin',
          call_id: callId,
          command: ['ls'],
          parsed_cmd: [],
          ...own,
        },
      }),
      line({
        timestamp: endTs,
        type: 'event_msg',
        payload: {
          type: 'exec_command_end',
          call_id: callId,
          command: ['ls'],
          parsed_cmd: [],
          aggregated_output: 'a\n',
          exit_code: 0,
          ...own,
        },
      }),
    ].join('\n');
  }

  // One apply_patch call that changed `paths`.
  function patch(callId: string, beginTs: string, endTs: string, paths: string[]): string {
    const changes = Object.fromEntries(paths.map((p) => [p, { type: 'update' }]));
    return [
      line({
        timestamp: beginTs,
        type: 'event_msg',
        payload: { type: 'patch_apply_begin', call_id: callId, auto_approved: true, changes },
      }),
      line({
        timestamp: endTs,
        type: 'event_msg',
        payload: {
          type: 'patch_apply_end',
          call_id: callId,
          stdout: 'applied',
          stderr: '',
          success: true,
          changes,
        },
      }),
    ].join('\n');
  }

  // Turn 1 runs in the work checkout. Turn 2 runs in a directory in no repository.
  function rollout(): string {
    return [
      line({
        timestamp: '2026-06-20T10:00:00.000Z',
        type: 'session_meta',
        payload: { session_id: SESSION, cwd: workRepo, cli_version: '0.140.0' },
      }),
      line({
        timestamp: '2026-06-20T10:00:01.000Z',
        type: 'turn_context',
        payload: { turn_id: 'turn-1', cwd: workRepo, model: 'gpt-5-codex' },
      }),
      tokenCount('2026-06-20T10:00:04.000Z', { input: 100, output: 50 }),
      exec('call-w', '2026-06-20T10:00:05.000Z', '2026-06-20T10:00:06.000Z'),
      line({
        timestamp: '2026-06-20T10:00:10.000Z',
        type: 'turn_context',
        payload: { turn_id: 'turn-2', cwd: scratch, model: 'gpt-5-codex' },
      }),
      tokenCount('2026-06-20T10:00:14.000Z', { input: 10, output: 5 }),
      exec('call-s', '2026-06-20T10:00:15.000Z', '2026-06-20T10:00:16.000Z'),
    ].join('\n');
  }

  // The scope_key column of the session root, and of every leaf keyed by its
  // message_id (llm_call, the synthetic eventKey) or tool_use_id (tool_call).
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

  it('keys the root by its project and each leaf by the cwd its own turn ran in', async () => {
    seed(transcripts, rollout());

    await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });

    const { root, leaf } = keys(dataDir);
    expect(root).toBe(WORK_KEY);
    expect(leaf.get(`${SESSION}:2026-06-20T10:00:04.000Z:1`)).toBe(WORK_KEY);
    expect(leaf.get('call-w')).toBe(WORK_KEY);
    // Turn 2 moved to a directory in no repository. Its leaves carry no key,
    // and they never inherit the root's.
    expect(leaf.get(`${SESSION}:2026-06-20T10:00:14.000Z:1`)).toBeNull();
    expect(leaf.get('call-s')).toBeNull();
  });

  it('keys a shell call by its own cwd, and a patch by the files it changed', async () => {
    seed(
      transcripts,
      [
        line({
          timestamp: '2026-06-20T10:00:00.000Z',
          type: 'session_meta',
          payload: { session_id: SESSION, cwd: scratch, cli_version: '0.140.0' },
        }),
        line({
          timestamp: '2026-06-20T10:00:01.000Z',
          type: 'turn_context',
          payload: { turn_id: 'turn-1', cwd: scratch, model: 'gpt-5-codex' },
        }),
        tokenCount('2026-06-20T10:00:04.000Z', { input: 100, output: 50 }),
        // A command run in the work checkout from a turn in the scratch directory.
        exec('call-in-work', '2026-06-20T10:00:05.000Z', '2026-06-20T10:00:06.000Z', workRepo),
        // Two files in different directories of one repository agree on its key.
        patch('patch-in-work', '2026-06-20T10:00:07.000Z', '2026-06-20T10:00:08.000Z', [
          join(workRepo, 'src', 'a.ts'),
          join(workRepo, 'b.ts'),
        ]),
        // One file in each checkout: the target names both, so the leaf carries
        // neither key.
        patch('patch-mixed', '2026-06-20T10:00:09.000Z', '2026-06-20T10:00:10.000Z', [
          join(workRepo, 'c.ts'),
          join(personalRepo, 'd.ts'),
        ]),
        line({
          timestamp: '2026-06-20T10:00:11.000Z',
          type: 'turn_context',
          payload: { turn_id: 'turn-2', cwd: workRepo, model: 'gpt-5-codex' },
        }),
        tokenCount('2026-06-20T10:00:12.000Z', { input: 10, output: 5 }),
        // A command run in the scratch directory from a turn in the work checkout.
        exec('call-in-scratch', '2026-06-20T10:00:13.000Z', '2026-06-20T10:00:14.000Z', scratch),
      ].join('\n'),
    );

    await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });

    const { leaf } = keys(dataDir);
    expect(leaf.get('call-in-work')).toBe(WORK_KEY);
    expect(leaf.get('patch-in-work')).toBe(WORK_KEY);
    expect(leaf.get('patch-mixed')).toBeNull();
    expect(leaf.get('call-in-scratch')).toBeNull();
  });

  it('a second pass stamps every row exactly as the first did', async () => {
    seed(transcripts, rollout());
    const opts = { dir: transcripts, now: FIXTURE_NOW };

    await reconcileHistory(config(dataDir), opts);
    const first = keys(dataDir);
    await reconcileHistory(config(dataDir), opts);

    expect(first.root).toBe(WORK_KEY);
    expect(keys(dataDir)).toEqual(first);
  });

  it('a tail chunk that starts mid-turn keys its leaves by nothing, never by the root', async () => {
    const transcriptPath = join(transcripts, `rollout-${SESSION}.jsonl`);
    writeFileSync(transcriptPath, `${rollout()}\n`);
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);
    // The next chunk holds one token_count and no session_meta or turn_context.
    appendFileSync(
      transcriptPath,
      `${tokenCount('2026-06-20T10:00:20.000Z', { input: 7, output: 3 })}\n`,
    );
    await reconcileSessionTail(config(dataDir), SESSION, transcriptPath);

    const { root, leaf } = keys(dataDir);
    expect(root).toBe(WORK_KEY);
    expect(leaf.get(`${SESSION}:2026-06-20T10:00:20.000Z:1`)).toBeNull();
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
          line({
            timestamp: '2026-06-20T10:00:00.000Z',
            type: 'session_meta',
            payload: { session_id: SESSION, cwd: relativeCwd, cli_version: '0.140.0' },
          }),
          line({
            timestamp: '2026-06-20T10:00:01.000Z',
            type: 'turn_context',
            payload: { turn_id: 'turn-1', cwd: relativeCwd, model: 'gpt-5-codex' },
          }),
          tokenCount('2026-06-20T10:00:04.000Z', { input: 100, output: 50 }),
          exec('call-rel', '2026-06-20T10:00:05.000Z', '2026-06-20T10:00:06.000Z'),
        ].join('\n'),
      );

      const home = process.cwd();
      process.chdir(workRepo);
      try {
        // The control: this process directory is a repository the resolver finds.
        expect(resolveRepo('.')).toBe('work');
        await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });
      } finally {
        // Restored before the shared afterEach removes the fixtures: a process
        // still standing inside one cannot delete it on Windows.
        process.chdir(home);
      }

      const { root, leaf } = keys(dataDir);
      expect(root).toBeNull();
      expect(leaf.get(`${SESSION}:2026-06-20T10:00:04.000Z:1`)).toBeNull();
      expect(leaf.get('call-rel')).toBeNull();
    },
  );

  it('a root built from a remoteless repo carries no key', async () => {
    writeFileSync(join(workRepo, '.git', 'config'), '');
    seed(transcripts, rollout());

    await reconcileHistory(config(dataDir), { dir: transcripts, now: FIXTURE_NOW });

    expect(keys(dataDir).root).toBeNull();
  });
});
