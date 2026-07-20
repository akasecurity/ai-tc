import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { DB_FILENAME } from '../../src/paths.ts';
import {
  LIVE_ACTIVITY_WINDOW_MS,
  SqliteActivityRepository,
} from '../../src/repositories/activity.ts';
import { purgeSampleData } from '../../src/sample-purge.ts';
import { seedSampleFixtures } from '../../src/test-fixtures/index.ts';

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
// A fixed midday UTC clock so the "today" window (queried with tz='UTC') is
// deterministic: [2026-06-29T00:00Z, 2026-06-30T00:00Z).
const NOW = Date.parse('2026-06-29T12:00:00.000Z');

let dir: string;
let db: ReturnType<typeof openLocalDatabase>;
let raw: DatabaseSync;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-activity-'));
  db = openLocalDatabase(dir);
  // A second raw connection: fixtures are inserted through it and the repo under
  // test binds to it with the fixed clock (the facade's own repo uses wall time).
  raw = new DatabaseSync(join(dir, DB_FILENAME));
});

afterEach(() => {
  raw.close();
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

function activity(): SqliteActivityRepository {
  return new SqliteActivityRepository(raw, () => NOW);
}

function insertSession(opts: {
  id: string;
  startedAt: number;
  endedAt?: number | null;
  attributes?: Record<string, unknown> | null;
  title?: string;
}): void {
  raw
    .prepare(
      `INSERT INTO audit_events (id, event_type, started_at, ended_at, content, attributes)
       VALUES (?, 'session', ?, ?, ?, ?)`,
    )
    .run(
      opts.id,
      opts.startedAt,
      opts.endedAt ?? null,
      opts.title ?? 'Session',
      opts.attributes === null ? null : JSON.stringify(opts.attributes ?? {}),
    );
}

function insertEvent(opts: {
  id: string;
  sessionId: string;
  type: string;
  startedAt: number;
  endedAt?: number | null;
  title?: string;
  attributes?: Record<string, unknown>;
}): void {
  raw
    .prepare(
      `INSERT INTO audit_events (id, root_session_id, event_type, started_at, ended_at, content, attributes)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      opts.id,
      opts.sessionId,
      opts.type,
      opts.startedAt,
      opts.endedAt ?? null,
      opts.title ?? '',
      JSON.stringify(opts.attributes ?? {}),
    );
}

function insertFinding(opts: { id: string; auditEventId: string }): void {
  raw
    .prepare(
      `INSERT OR IGNORE INTO inspection_definitions (id, rule_id, name, category, severity, definition, version)
       VALUES ('def1', 'rule.secret', 'Secret', 'secret', 'critical', '{}', '1')`,
    )
    .run();
  raw
    .prepare(
      `INSERT INTO inspection_findings
         (id, audit_event_id, inspection_definition_id, span_start, span_end, masked_match, action_taken, confidence)
       VALUES (?, ?, 'def1', 0, 1, '••', 'redact', 1)`,
    )
    .run(opts.id, opts.auditEventId);
}

// A fully-populated session "A" today (active/open), used across the detail tests.
function seedSessionA(): void {
  insertSession({
    id: 'A',
    startedAt: NOW,
    endedAt: null,
    title: 'Add idempotency keys',
    attributes: {
      harness: 'claudecode',
      project: 'payments-api',
      repo: 'globex/payments-api',
      branches: ['feat/idempotency', 'main'],
      host: 'globex-mbp.local',
      cwd: '~/code/payments-api',
      models: ['claude-sonnet-4-6'],
      version: 'Claude Code 2.1.4',
      files: ['src/charge.ts'],
    },
  });
  insertEvent({ id: 'A1', sessionId: 'A', type: 'prompt', startedAt: NOW + 1000, title: 'p1' });
  insertEvent({ id: 'A2', sessionId: 'A', type: 'prompt', startedAt: NOW + 2000, title: 'p2' });
  insertEvent({
    id: 'A3',
    sessionId: 'A',
    type: 'tool_call',
    startedAt: NOW + 3000,
    attributes: { tool: 'Read' },
  });
  insertEvent({
    id: 'A4',
    sessionId: 'A',
    type: 'tool_call',
    startedAt: NOW + 4000,
    attributes: { tool: 'Read' },
  });
  insertEvent({
    id: 'A5',
    sessionId: 'A',
    type: 'tool_call',
    startedAt: NOW + 5000,
    attributes: { tool: 'Bash' },
  });
  insertEvent({
    id: 'A6',
    sessionId: 'A',
    type: 'llm_call',
    startedAt: NOW + 6000,
    attributes: {
      model: 'claude-sonnet-4-6',
      provider: 'anthropic',
      input_tokens: 1000,
      output_tokens: 200,
      cache_creation_input_tokens: 50,
      cache_read_input_tokens: 800,
    },
  });
  insertEvent({
    id: 'A7',
    sessionId: 'A',
    type: 'detection',
    startedAt: NOW + 7000,
    title: 'Redacted Postgres connection string',
    attributes: {
      detail: 'secret masked',
      severity: 'critical',
      link: 'detections',
      targetId: 'fnd1',
    },
  });
  insertFinding({ id: 'f1', auditEventId: 'A7' });
  insertEvent({
    id: 'A8',
    sessionId: 'A',
    type: 'share',
    startedAt: NOW + 8000,
    attributes: { destination: 'newrelic.com', link: 'shares' },
  });
  insertEvent({
    id: 'A9',
    sessionId: 'A',
    type: 'share',
    startedAt: NOW + 9000,
    attributes: { destination: 'vault.globex.com', link: 'shares', internal: true },
  });
  insertEvent({ id: 'A10', sessionId: 'A', type: 'commit', startedAt: NOW + 10_000, title: 'c1' });
}

describe('stats', () => {
  it('counts today sessions/live/tools/findings/egress in the tz window', async () => {
    seedSessionA();
    // Session B today, completed.
    insertSession({
      id: 'B',
      startedAt: NOW - HOUR_MS,
      endedAt: NOW - HOUR_MS / 2,
      attributes: { harness: 'cursor', project: 'matching-core' },
    });
    insertEvent({
      id: 'B1',
      sessionId: 'B',
      type: 'tool_call',
      startedAt: NOW - HOUR_MS + 1000,
      attributes: { tool: 'Grep' },
    });
    insertEvent({
      id: 'B2',
      sessionId: 'B',
      type: 'share',
      startedAt: NOW - HOUR_MS + 2000,
      attributes: { destination: 'newrelic.com' },
    });
    // Session C is 10 days old and closed — excluded from every "today" counter.
    insertSession({
      id: 'C',
      startedAt: NOW - 10 * DAY_MS,
      endedAt: NOW - 10 * DAY_MS + HOUR_MS,
      attributes: { harness: 'codex' },
    });
    insertEvent({
      id: 'C1',
      sessionId: 'C',
      type: 'tool_call',
      startedAt: NOW - 10 * DAY_MS,
      attributes: { tool: 'Read' },
    });

    const stats = await activity().stats('UTC');
    expect(stats.sessionsToday).toBe(2); // A + B
    expect(stats.liveNow).toBe(1); // A is open
    expect(stats.toolCallsToday).toBe(4); // A: 3, B: 1
    expect(stats.findingsToday).toBe(1); // A7's finding
    expect(stats.egressToday).toBe(2); // distinct {newrelic.com, vault.globex.com}
  });

  it('counts a bare-attribute session row too (defensive defaults)', async () => {
    // No harness attribute — but real activity, so it counts.
    insertSession({ id: 'D', startedAt: NOW, attributes: {} });
    insertEvent({ id: 'D1', sessionId: 'D', type: 'prompt', startedAt: NOW });
    const stats = await activity().stats('UTC');
    expect(stats.sessionsToday).toBe(1);
    expect(stats.liveNow).toBe(1); // open + just started → within the live window
  });

  it('sessionsToday ignores zero-activity sessions; liveNow still sees them', async () => {
    // A background `claude` launch: root + bookkeeping children only. It must
    // not inflate "Sessions today" — but a just-opened session that has not
    // produced activity YET is still legitimately live, so liveNow keeps it.
    insertSession({ id: 'G', startedAt: NOW, attributes: {} });
    insertEvent({ id: 'G1', sessionId: 'G', type: 'config_scan', startedAt: NOW });
    insertEvent({ id: 'G2', sessionId: 'G', type: 'hook', startedAt: NOW + 1 });
    const stats = await activity().stats('UTC');
    expect(stats.sessionsToday).toBe(0);
    expect(stats.liveNow).toBe(1);
  });

  it('excludes an idle open session from liveNow (no session-end writer)', async () => {
    // Open (ended_at null) but last activity is hours past the live window: the
    // local store never stamps ended_at, so this MUST NOT read as live.
    insertSession({ id: 'S', startedAt: NOW - 5 * HOUR_MS, attributes: {} });
    insertEvent({
      id: 'S1',
      sessionId: 'S',
      type: 'tool_call',
      startedAt: NOW - 4 * HOUR_MS,
      attributes: { tool: 'Read' },
    });
    const stats = await activity().stats('UTC');
    expect(stats.liveNow).toBe(0);
  });

  it('counts a session whose last activity is exactly on the window edge (>=)', async () => {
    // Last activity at precisely now − window: the boundary is inclusive.
    insertSession({ id: 'S', startedAt: NOW - 2 * HOUR_MS, attributes: {} });
    insertEvent({
      id: 'S1',
      sessionId: 'S',
      type: 'tool_call',
      startedAt: NOW - LIVE_ACTIVITY_WINDOW_MS,
      attributes: { tool: 'Read' },
    });
    const stats = await activity().stats('UTC');
    expect(stats.liveNow).toBe(1);
  });

  it('keeps a session live off a long event that ENDED recently, not its start', async () => {
    // One long-running event: started well outside the window, but its end is
    // inside it — folding ended_at keeps the session live mid-/just-post-work.
    insertSession({ id: 'S', startedAt: NOW - 2 * HOUR_MS, attributes: {} });
    insertEvent({
      id: 'S1',
      sessionId: 'S',
      type: 'tool_call',
      startedAt: NOW - 90 * 60_000, // 90m ago — start alone would be stale
      endedAt: NOW - 60_000, // finished 1m ago
      attributes: { tool: 'Bash' },
    });
    const stats = await activity().stats('UTC');
    expect(stats.liveNow).toBe(1);
  });
});

describe('listSessions', () => {
  beforeEach(() => {
    seedSessionA();
    insertSession({
      id: 'B',
      startedAt: NOW - HOUR_MS,
      endedAt: NOW - HOUR_MS / 2,
      attributes: { harness: 'cursor', project: 'matching-core' },
    });
    insertSession({
      id: 'C',
      startedAt: NOW - 10 * DAY_MS,
      endedAt: NOW - 10 * DAY_MS + HOUR_MS,
      attributes: { harness: 'codex' },
    });
  });

  it('returns session summaries most-recent-first', async () => {
    const res = await activity().listSessions({ limit: 50 });
    expect(res.items.map((s) => s.id)).toEqual(['A', 'B', 'C']);
    expect(res.nextCursor).toBeNull();
    const a = res.items[0];
    expect(a?.harness).toBe('claudecode');
    expect(a?.status).toBe('active');
    expect(a?.endedAt).toBeNull();
    expect(a?.turns).toBe(2);
    expect(a?.findings).toBe(1);
    expect(a?.shares).toBe(2);
  });

  it('includes a bare session row with defensive defaults', async () => {
    // No harness/title attributes — the list must still render these rows
    // (`harness ?? 'claudecode'`), not hide them.
    insertSession({ id: 'Z', startedAt: NOW - 2 * HOUR_MS, attributes: {}, title: 'bare' });
    const res = await activity().listSessions({ limit: 50 });
    const z = res.items.find((s) => s.id === 'Z');
    expect(z).toBeDefined();
    expect(z?.harness).toBe('claudecode');
    expect(z?.title).toBe('bare');
  });

  it('reports an idle open session as completed at its last activity', async () => {
    // No ended_at, but its newest event is well outside the live window — the
    // summary is completed and its endedAt is imputed to that last activity, so
    // the row shows a finite duration instead of an ever-growing "· live".
    insertSession({ id: 'S', startedAt: NOW - 5 * HOUR_MS, attributes: { harness: 'claudecode' } });
    insertEvent({
      id: 'S1',
      sessionId: 'S',
      type: 'tool_call',
      startedAt: NOW - 4 * HOUR_MS,
      attributes: { tool: 'Read' },
    });
    const res = await activity().listSessions({ limit: 50 });
    const s = res.items.find((x) => x.id === 'S');
    expect(s?.status).toBe('completed');
    expect(s?.endedAt).toBe(new Date(NOW - 4 * HOUR_MS).toISOString());
  });

  it('filters by harness', async () => {
    const res = await activity().listSessions({ limit: 50, harness: ['cursor'] });
    expect(res.items.map((s) => s.id)).toEqual(['B']);
  });

  it('filters by claudecode and matches BARE (harness-less) rows too', async () => {
    // A bare root (no $.harness) renders as claudecode via the read-side default;
    // the filter must agree, else "filter by claude-code" hides every real
    // (historically harness-less) session even though they all show as claudecode.
    insertSession({ id: 'Z', startedAt: NOW - 3 * HOUR_MS, attributes: {} });
    const res = await activity().listSessions({ limit: 50, harness: ['claudecode'] });
    // A (explicit claudecode) + Z (bare → claudecode); NOT B (cursor) / C (codex).
    expect(res.items.map((s) => s.id).sort()).toEqual(['A', 'Z']);
  });

  it('matches q against a descendant event detail', async () => {
    const res = await activity().listSessions({ limit: 50, q: 'masked' });
    expect(res.items.map((s) => s.id)).toEqual(['A']);
  });

  it('filters by from lower bound', async () => {
    const res = await activity().listSessions({
      limit: 50,
      from: new Date(NOW - 2 * DAY_MS).toISOString(),
    });
    expect(res.items.map((s) => s.id)).toEqual(['A', 'B']);
  });

  it('keyset-paginates and resumes from the cursor', async () => {
    const first = await activity().listSessions({ limit: 1 });
    expect(first.items.map((s) => s.id)).toEqual(['A']);
    expect(first.nextCursor).not.toBeNull();

    const second = await activity().listSessions({ limit: 1, cursor: first.nextCursor ?? '' });
    expect(second.items.map((s) => s.id)).toEqual(['B']);
  });

  it('restarts from the top on a stale/undecodable cursor', async () => {
    const res = await activity().listSessions({ limit: 1, cursor: 'not-a-cursor' });
    expect(res.items.map((s) => s.id)).toEqual(['A']);
  });
});

// A "ghost": the root the plugin's SessionStart hook records for a background
// `claude` launch that never produces any activity — its only children are
// bookkeeping rows (config scan, hooks). On real stores these outnumber real
// sessions, so the list query can exclude them and always reports how many
// matched, letting the UI collapse them behind a toggle.
describe('listSessions — zero-activity sessions', () => {
  function insertGhost(id: string, startedAt: number): void {
    insertSession({ id, startedAt, attributes: {} });
    insertEvent({ id: `${id}-scan`, sessionId: id, type: 'config_scan', startedAt });
    insertEvent({ id: `${id}-hook`, sessionId: id, type: 'hook', startedAt: startedAt + 1 });
  }

  it('excludeEmpty drops bookkeeping-only sessions and reports emptyCount', async () => {
    seedSessionA();
    insertGhost('G', NOW - HOUR_MS);

    const res = await activity().listSessions({ limit: 50, excludeEmpty: true });
    expect(res.items.map((s) => s.id)).toEqual(['A']);
    expect(res.emptyCount).toBe(1);
  });

  it('without the flag, zero-activity sessions stay listed but are still counted', async () => {
    seedSessionA();
    insertGhost('G', NOW - HOUR_MS);

    const res = await activity().listSessions({ limit: 50 });
    expect(res.items.map((s) => s.id)).toEqual(['A', 'G']);
    expect(res.emptyCount).toBe(1);
  });

  it('emptyCount respects the query filters, not the whole store', async () => {
    seedSessionA();
    insertGhost('G', NOW - HOUR_MS);
    insertGhost('H', NOW - 10 * DAY_MS);

    const res = await activity().listSessions({
      limit: 50,
      excludeEmpty: true,
      from: new Date(NOW - 2 * DAY_MS).toISOString(),
    });
    expect(res.emptyCount).toBe(1); // G only — H is outside the range
  });

  it('a session with real activity is never treated as empty', async () => {
    // One prompt is enough — only hook/config_scan children are bookkeeping.
    insertSession({ id: 'P', startedAt: NOW - HOUR_MS, attributes: {} });
    insertEvent({ id: 'P1', sessionId: 'P', type: 'prompt', startedAt: NOW - HOUR_MS + 1000 });

    const res = await activity().listSessions({ limit: 50, excludeEmpty: true });
    expect(res.items.map((s) => s.id)).toEqual(['P']);
    expect(res.emptyCount).toBe(0);
  });
});

describe('getSession', () => {
  it('assembles detail: tokens, tools, rollups, and drops structural rows', async () => {
    seedSessionA();
    const session = await activity().getSession('A');
    expect(session).not.toBeNull();
    if (!session) return;

    expect(session.host).toBe('globex-mbp.local');
    expect(session.cwd).toBe('~/code/payments-api');
    expect(session.models).toEqual(['claude-sonnet-4-6']);
    expect(session.turns).toBe(2);
    expect(session.findings).toBe(1);
    expect(session.shares).toBe(2);
    expect(session.commits).toBe(1);
    expect(session.tools).toEqual({ Read: 2, Bash: 1 });

    expect(session.tokens.inputTokens).toBe(1000);
    expect(session.tokens.outputTokens).toBe(200);
    expect(session.tokens.cacheCreation).toBe(50);
    expect(session.tokens.cacheRead).toBe(800);
    expect(session.tokens.totalTokens).toBe(2050);
    expect(session.tokens.model).toBe('claude-sonnet-4-6');
    expect(session.tokens.estimatedCostUsd).toBeNull();

    // The llm_call structural row is dropped; the session + others remain.
    const kinds = session.events.map((e) => e.kind);
    expect(kinds).not.toContain('llm_call');
    expect(kinds).toContain('session');
    expect(kinds).toContain('tool');
    expect(kinds).toContain('detection');
    expect(kinds).toContain('share');

    const detection = session.events.find((e) => e.kind === 'detection');
    expect(detection?.severity).toBe('critical');
    expect(detection?.link).toBe('detections');
    expect(detection?.targetId).toBe('fnd1');

    const internalShare = session.events.find((e) => e.id === 'A9');
    expect(internalShare?.internal).toBe(true);
  });

  it('returns null for an unknown id', async () => {
    seedSessionA();
    expect(await activity().getSession('nope')).toBeNull();
  });
});

describe('tokenReports', () => {
  it('groups llm_call leaves per session with a read-time derived cost', async () => {
    seedSessionA();
    const reports = await activity().tokenReports();
    expect(reports).toHaveLength(1);
    const report = reports[0];
    expect(report?.sessionId).toBe('A');
    expect(report?.totalTokens).toBe(2050);
    expect(report?.rollups).toHaveLength(1);
    const roll = report?.rollups[0];
    expect(roll?.provider).toBe('anthropic');
    expect(roll?.model).toBe('claude-sonnet-4-6');
    // Priced by the reference Anthropic map → a positive estimate, not null.
    expect(report?.estimatedCostUsd).toBeGreaterThan(0);
    expect(report?.costIsPartial).toBe(false);
  });

  it('tokenReportForSession returns one breakdown, null for a token-less session', async () => {
    seedSessionA();
    // A session with no llm_call leaves (a tool-only session).
    insertSession({ id: 'T', startedAt: NOW - HOUR_MS, attributes: {} });
    insertEvent({
      id: 'T1',
      sessionId: 'T',
      type: 'tool_call',
      startedAt: NOW - HOUR_MS + 100,
      attributes: { tool: 'Read' },
    });

    const a = await activity().tokenReportForSession('A');
    expect(a?.sessionId).toBe('A');
    expect(a?.rollups).toHaveLength(1);

    expect(await activity().tokenReportForSession('T')).toBeNull();
  });

  it('flags a partial total when a leaf has unknown pricing', async () => {
    seedSessionA();
    // A non-Anthropic, non-local provider → cost null → the total is a lower bound.
    insertEvent({
      id: 'A-mystery',
      sessionId: 'A',
      type: 'llm_call',
      startedAt: NOW + 7000,
      attributes: { model: 'mystery-model', provider: 'mystery', input_tokens: 500 },
    });
    const report = (await activity().tokenReports())[0];
    expect(report?.rollups).toHaveLength(2);
    expect(report?.costIsPartial).toBe(true);
  });

  it('windows leaves by fromMs', async () => {
    seedSessionA(); // its single llm_call leaf is stamped at NOW + 6000
    // A lower bound just after the leaf excludes it → no reports.
    expect(await activity().tokenReports(NOW + 6001)).toHaveLength(0);
    // A lower bound before the leaf includes it.
    expect(await activity().tokenReports(NOW)).toHaveLength(1);
  });
});

describe('harnessFacets', () => {
  it('returns only harnesses present, counting bare rows as claudecode', async () => {
    insertSession({ id: 'A', startedAt: NOW, attributes: { harness: 'claudecode' } });
    insertSession({ id: 'B', startedAt: NOW - HOUR_MS, attributes: { harness: 'cursor' } });
    insertSession({ id: 'Z', startedAt: NOW - 2 * HOUR_MS, attributes: {} }); // bare → claudecode
    const facets = await activity().harnessFacets();
    expect([...facets].sort()).toEqual(['claudecode', 'cursor']);
  });

  it('a store of only bare roots surfaces exactly [claudecode]', async () => {
    insertSession({ id: 'X', startedAt: NOW, attributes: {} });
    insertSession({ id: 'Y', startedAt: NOW - HOUR_MS, attributes: {} });
    expect(await activity().harnessFacets()).toEqual(['claudecode']);
  });

  it('windows facets by fromMs', async () => {
    insertSession({ id: 'A', startedAt: NOW, attributes: { harness: 'claudecode' } });
    insertSession({ id: 'old', startedAt: NOW - 40 * DAY_MS, attributes: { harness: 'codex' } });
    // Only the recent (claudecode) session falls inside the 7-day window.
    expect(await activity().harnessFacets(NOW - 7 * DAY_MS)).toEqual(['claudecode']);
  });
});

// The live OSS capture path writes bare-ish session roots (no title/models,
// tool calls under `tool_name` not `tool`, no `prompt` events) — these verify the
// read side reconstructs the display fields from the real leaf data anyway.
describe('read-side reconstruction from real (non-fixture) capture shape', () => {
  it('groups tool calls by the canonical tool_name attribute', async () => {
    insertSession({ id: 'R', startedAt: NOW, attributes: { harness: 'claudecode' } });
    insertEvent({
      id: 'R-t1',
      sessionId: 'R',
      type: 'tool_call',
      startedAt: NOW + 1,
      attributes: { tool_name: 'Bash', tool_use_id: 'tu1' },
    });
    insertEvent({
      id: 'R-t2',
      sessionId: 'R',
      type: 'tool_call',
      startedAt: NOW + 2,
      attributes: { tool_name: 'Bash', tool_use_id: 'tu2' },
    });
    insertEvent({
      id: 'R-t3',
      sessionId: 'R',
      type: 'tool_call',
      startedAt: NOW + 3,
      attributes: { tool_name: 'Read', tool_use_id: 'tu3' },
    });

    const session = await activity().getSession('R');
    expect(session?.tools).toEqual({ Bash: 2, Read: 1 });
  });

  it('derives turns from distinct llm_call run_key (no prompt events) and models from the leaves', async () => {
    insertSession({ id: 'R', startedAt: NOW, attributes: { harness: 'claudecode' } });
    // Two turns (run_key p1, p2), first turn used two models.
    const leaf = (id: string, at: number, a: Record<string, unknown>) => {
      insertEvent({ id, sessionId: 'R', type: 'llm_call', startedAt: at, attributes: a });
    };
    leaf('R-l1', NOW + 1, {
      model: 'claude-opus-4-8',
      provider: 'anthropic',
      input_tokens: 10,
      run_key: 'p1',
    });
    leaf('R-l2', NOW + 2, {
      model: 'claude-haiku-4-5',
      provider: 'anthropic',
      input_tokens: 5,
      run_key: 'p1',
    });
    leaf('R-l3', NOW + 3, {
      model: 'claude-opus-4-8',
      provider: 'anthropic',
      input_tokens: 20,
      run_key: 'p2',
    });

    const session = await activity().getSession('R');
    expect(session?.turns).toBe(2); // distinct run_keys p1, p2
    expect(session?.models).toEqual(['claude-haiku-4-5', 'claude-opus-4-8']); // distinct, sorted
  });

  it('falls back the title to project, then repo, then a session-id stub when no content', async () => {
    // Empty content (title='') + a project attribute → project is the title.
    insertSession({
      id: 'proj-sess',
      startedAt: NOW,
      title: '',
      attributes: { project: 'payments-api' },
    });
    // Empty content + no project/repo → a short session-id stub.
    insertSession({ id: 'abcdef0123456789', startedAt: NOW - HOUR_MS, title: '', attributes: {} });

    const list = await activity().listSessions({ limit: 50 });
    const byId = new Map(list.items.map((s) => [s.id, s.title]));
    expect(byId.get('proj-sess')).toBe('payments-api');
    expect(byId.get('abcdef0123456789')).toBe('Session abcdef01');
  });
});

describe('activity fixtures + legacy sample purge', () => {
  it('reads the rich fixture sessions, then purgeSampleData removes exactly them', async () => {
    seedSampleFixtures(raw);

    // The repo bound to the facade's connection uses the wall clock — the fixture
    // timestamps are now-relative, so every session is inside the default window.
    const seeded = await db.activity.listSessions({ limit: 50 });
    expect(seeded.items.length).toBe(7);
    expect(seeded.items.every((s) => s.id.startsWith('sample:activity:'))).toBe(true);

    const detail = await db.activity.getSession('sample:activity:payments-idempotency');
    expect(detail?.status).toBe('active');
    expect(detail?.findings).toBe(1);
    expect(detail?.shares).toBe(2);
    expect(detail?.tokens.inputTokens).toBe(128_400);
    expect(detail?.events.some((e) => e.kind === 'session')).toBe(true);

    seedSessionA(); // a real (non-sample) session alongside the legacy rows
    db.purgeSampleData();
    expect(hasSampleActivityRows()).toBe(false);
    const remaining = await db.activity.listSessions({ limit: 50 });
    expect(remaining.items.length).toBe(1);
  });

  it('is a no-op on a store with only real session rows', () => {
    seedSessionA();
    purgeSampleData(raw);
    expect(hasSampleActivityRows()).toBe(false);
    const count = (raw.prepare('SELECT count(*) AS n FROM audit_events').get() as { n: number }).n;
    expect(count).toBeGreaterThan(0);
  });
});

function hasSampleActivityRows(): boolean {
  const row = raw
    .prepare("SELECT count(*) AS n FROM audit_events WHERE id LIKE 'sample:activity:%'")
    .get() as { n: number };
  return row.n > 0;
}
