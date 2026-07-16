import { describe, expect, it } from 'vitest';

import {
  ActivityLink,
  ActivityOverviewResponse,
  ActivitySession,
  ActivitySessionSummary,
  AuditEvent,
  AuditEventKind,
  eventSeverity,
  ExportActivityQuery,
  GetActivitySessionResponse,
  GetActivityStatsQuery,
  GetActivityStatsResponse,
  GetSessionRawLogQuery,
  Harness,
  ListActivitySessionsQuery,
  ListActivitySessionsResponse,
  ListSessionEventsQuery,
  ListSessionEventsResponse,
  SessionStatus,
} from '../../src/zod/activity.ts';
import { Severity } from '../../src/zod/finding.ts';
import { TokenRollup } from '../../src/zod/meta.ts';

// ─── Enums ────────────────────────────────────────────────────────────────────

describe('Harness enum (reused from harness-map.ts)', () => {
  it('accepts the original 5 ids plus the 3 Activity extension ids', () => {
    for (const v of [
      'claudecode',
      'cursor',
      'copilot',
      'codex',
      'windsurf',
      'claudedesktop',
      'chatgpt',
      'api',
    ]) {
      expect(Harness.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(Harness.safeParse('vscode').success).toBe(false);
  });
});

describe('SessionStatus enum', () => {
  it('accepts active, completed, interrupted, error', () => {
    for (const v of ['active', 'completed', 'interrupted', 'error']) {
      expect(SessionStatus.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(SessionStatus.safeParse('paused').success).toBe(false);
  });
});

describe('AuditEventKind enum', () => {
  it('accepts all 11 contract kinds', () => {
    for (const v of [
      'session',
      'prompt',
      'response',
      'tool',
      'hook',
      'detection',
      'share',
      'permission',
      'commit',
      'error',
      'active',
    ]) {
      expect(AuditEventKind.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(AuditEventKind.safeParse('checkpoint').success).toBe(false);
  });
});

describe('ActivityLink enum', () => {
  it('accepts detections, shares, inventory', () => {
    for (const v of ['detections', 'shares', 'inventory']) {
      expect(ActivityLink.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(ActivityLink.safeParse('findings').success).toBe(false);
  });
});

describe('eventSeverity (reused from finding.ts Severity)', () => {
  it('is the exact same schema as Severity — not a locally redefined set', () => {
    expect(eventSeverity).toBe(Severity);
    expect(eventSeverity.meta()?.id).toBe('Severity');
  });

  it('accepts critical, high, medium, low', () => {
    for (const v of ['critical', 'high', 'medium', 'low']) {
      expect(eventSeverity.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(eventSeverity.safeParse('urgent').success).toBe(false);
  });
});

// ─── AuditEvent ───────────────────────────────────────────────────────────────

const validEvent = {
  id: 'ev_0007',
  occurredAt: '2026-07-05T14:19:03Z',
  kind: 'detection',
  title: 'Redacted Postgres connection string',
  detail: 'In pasted context · src/config/database.ts · sent to provider with secret masked',
  tool: null,
  severity: 'critical',
  link: 'detections',
  targetId: 'fnd_5b2c',
  internal: false,
  flagged: false,
};

describe('AuditEvent', () => {
  it('registers as ActivityAuditEvent, not AuditEvent (avoids the AuditEventInput id collision)', () => {
    expect(AuditEvent.meta()?.id).toBe('ActivityAuditEvent');
  });

  it('parses a full detection event', () => {
    expect(AuditEvent.safeParse(validEvent).success).toBe(true);
  });

  it('optional fields are null when absent, not omitted', () => {
    const toolEvent = {
      ...validEvent,
      kind: 'tool',
      tool: 'Bash',
      severity: null,
      link: null,
      targetId: null,
    };
    expect(AuditEvent.safeParse(toolEvent).success).toBe(true);
  });

  it('rejects a missing internal/flagged pair', () => {
    const { internal, flagged, ...rest } = validEvent;
    void internal;
    void flagged;
    expect(AuditEvent.safeParse(rest).success).toBe(false);
  });

  it('rejects an invalid kind', () => {
    expect(AuditEvent.safeParse({ ...validEvent, kind: 'checkpoint' }).success).toBe(false);
  });
});

// ─── ActivitySessionSummary / ActivitySession ─────────────────────────────────

const validSummary = {
  id: 'sess_9f2a71',
  harness: 'claudecode',
  title: 'Add idempotency keys to charge & refund',
  project: 'payments-api',
  repo: 'globex/payments-api',
  branches: ['feat/idempotency', 'main'],
  startedAt: '2026-07-05T14:14:02Z',
  endedAt: null,
  status: 'active',
  turns: 14,
  findings: 1,
  shares: 2,
};

describe('ActivitySessionSummary', () => {
  it('parses a valid active-session summary with null endedAt', () => {
    expect(ActivitySessionSummary.safeParse(validSummary).success).toBe(true);
  });

  it('parses a completed session with a non-null endedAt', () => {
    expect(
      ActivitySessionSummary.safeParse({
        ...validSummary,
        status: 'completed',
        endedAt: '2026-07-05T15:02:11Z',
      }).success,
    ).toBe(true);
  });

  it('rejects an invalid status', () => {
    expect(ActivitySessionSummary.safeParse({ ...validSummary, status: 'paused' }).success).toBe(
      false,
    );
  });

  it('rejects a negative findings count', () => {
    expect(ActivitySessionSummary.safeParse({ ...validSummary, findings: -1 }).success).toBe(false);
  });

  it('does not carry presentational fields (color/icon/short/fill/tone/dot)', () => {
    const keys = Object.keys(ActivitySessionSummary.shape);
    for (const forbidden of ['color', 'icon', 'short', 'fill', 'tone', 'dot']) {
      expect(keys).not.toContain(forbidden);
    }
  });
});

const validTokens = {
  sessionId: 'sess_9f2a71',
  model: 'claude-sonnet-4-6',
  provider: 'anthropic',
  inputTokens: 128400,
  outputTokens: 31200,
  cacheCreation: 42000,
  cacheRead: 486000,
  totalTokens: 687600,
  estimatedCostUsd: null,
};

const validSession = {
  ...validSummary,
  host: 'globex-mbp.local',
  cwd: '~/code/payments-api',
  models: ['claude-sonnet-4-6', 'claude-opus-4-8'],
  version: 'Claude Code 2.1.4',
  tokens: validTokens,
  tools: { Read: 38, Edit: 22, Bash: 17, Grep: 9, Write: 3 },
  files: ['src/services/charge.ts', 'src/services/refund.ts', 'src/db/idempotency.ts'],
  commits: 1,
  events: [validEvent],
};

describe('ActivitySession', () => {
  it('registers as an OpenAPI component now that getActivitySession references it', () => {
    expect(ActivitySession.meta()?.id).toBe('ActivitySession');
  });

  it('parses a full session detail with embedded events', () => {
    expect(ActivitySession.safeParse(validSession).success).toBe(true);
  });

  it('tokens must parse against the shared TokenRollup schema (raw integers, no shorthand keys)', () => {
    const result = ActivitySession.safeParse(validSession);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(TokenRollup.safeParse(result.data.tokens).success).toBe(true);
      expect(result.data.tokens.inputTokens).toBe(128400);
      expect(result.data.tokens.outputTokens).toBe(31200);
    }
  });

  it('estimatedCostUsd accepts null (no price map wired this milestone)', () => {
    expect(ActivitySession.safeParse(validSession).success).toBe(true);
  });

  it('events can be empty', () => {
    expect(ActivitySession.safeParse({ ...validSession, events: [] }).success).toBe(true);
  });

  it('rejects a malformed tools map value', () => {
    expect(
      ActivitySession.safeParse({ ...validSession, tools: { Read: 'thirty-eight' } }).success,
    ).toBe(false);
  });

  it('rejects a negative commits count', () => {
    expect(ActivitySession.safeParse({ ...validSession, commits: -1 }).success).toBe(false);
  });

  it('does not carry presentational fields (color/icon/short/fill/tone/dot)', () => {
    const keys = Object.keys(ActivitySession.shape);
    for (const forbidden of ['color', 'icon', 'short', 'fill', 'tone', 'dot']) {
      expect(keys).not.toContain(forbidden);
    }
  });
});

// ─── getActivityStats ───────────────────────────────────────────────────────

describe('GetActivityStatsQuery', () => {
  it('tz is optional — empty object succeeds', () => {
    expect(GetActivityStatsQuery.safeParse({}).success).toBe(true);
  });

  it('accepts an IANA tz string', () => {
    expect(GetActivityStatsQuery.safeParse({ tz: 'America/Chicago' }).success).toBe(true);
  });
});

describe('GetActivityStatsResponse', () => {
  it('parses the five-counter payload', () => {
    expect(
      GetActivityStatsResponse.safeParse({
        sessionsToday: 3,
        liveNow: 1,
        toolCallsToday: 108,
        findingsToday: 3,
        egressToday: 5,
      }).success,
    ).toBe(true);
  });

  it('rejects a negative counter', () => {
    expect(
      GetActivityStatsResponse.safeParse({
        sessionsToday: -1,
        liveNow: 1,
        toolCallsToday: 108,
        findingsToday: 3,
        egressToday: 5,
      }).success,
    ).toBe(false);
  });
});

// ─── listActivitySessions ───────────────────────────────────────────────────

describe('ListActivitySessionsQuery', () => {
  it('all fields optional — empty object succeeds with limit defaulted to 50', () => {
    const result = ListActivitySessionsQuery.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(50);
    }
  });

  it('accepts q, harness[], from/to, cursor', () => {
    expect(
      ListActivitySessionsQuery.safeParse({
        q: 'postgres',
        harness: ['cursor', 'claudecode'],
        from: '2026-07-01',
        to: '2026-07-07',
        cursor: 'opaque-cursor',
      }).success,
    ).toBe(true);
  });

  it('limit out of range (>100) is rejected', () => {
    expect(ListActivitySessionsQuery.safeParse({ limit: 101 }).success).toBe(false);
  });

  it('limit out of range (<1) is rejected', () => {
    expect(ListActivitySessionsQuery.safeParse({ limit: 0 }).success).toBe(false);
  });

  it('rejects an invalid harness value', () => {
    expect(ListActivitySessionsQuery.safeParse({ harness: ['vscode'] }).success).toBe(false);
  });
});

describe('ListActivitySessionsResponse', () => {
  it('parses items[] with a null nextCursor at the last page', () => {
    expect(
      ListActivitySessionsResponse.safeParse({ items: [validSummary], nextCursor: null }).success,
    ).toBe(true);
  });

  it('accepts an empty items array (no error on zero matches)', () => {
    expect(ListActivitySessionsResponse.safeParse({ items: [], nextCursor: null }).success).toBe(
      true,
    );
  });

  it('rejects a missing nextCursor key', () => {
    expect(ListActivitySessionsResponse.safeParse({ items: [] }).success).toBe(false);
  });
});

// ─── getActivitySession ──────────────────────────────────────────────────────

describe('GetActivitySessionResponse', () => {
  it('is exactly ActivitySession — same schema, not a redefinition', () => {
    expect(GetActivitySessionResponse).toBe(ActivitySession);
  });

  it('parses a full session detail', () => {
    expect(GetActivitySessionResponse.safeParse(validSession).success).toBe(true);
  });
});

// ─── listSessionEvents ────────────────────────────────────────────────────────

describe('ListSessionEventsQuery', () => {
  it('defaults limit to 100 and order to asc', () => {
    const result = ListSessionEventsQuery.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(100);
      expect(result.data.order).toBe('asc');
    }
  });

  it('accepts order=desc and a cursor', () => {
    expect(
      ListSessionEventsQuery.safeParse({ order: 'desc', cursor: 'opaque-cursor' }).success,
    ).toBe(true);
  });

  it('limit out of range (>500) is rejected', () => {
    expect(ListSessionEventsQuery.safeParse({ limit: 501 }).success).toBe(false);
  });

  it('rejects an invalid order value', () => {
    expect(ListSessionEventsQuery.safeParse({ order: 'newest' }).success).toBe(false);
  });
});

describe('ListSessionEventsResponse', () => {
  it('registers as an OpenAPI component now that listSessionEvents references it', () => {
    expect(ListSessionEventsResponse.meta()?.id).toBe('ListSessionEventsResponse');
  });

  it('parses items[] with a null nextCursor', () => {
    expect(
      ListSessionEventsResponse.safeParse({ items: [validEvent], nextCursor: null }).success,
    ).toBe(true);
  });

  it('rejects a missing items key', () => {
    expect(ListSessionEventsResponse.safeParse({ nextCursor: null }).success).toBe(false);
  });
});

// ─── getSessionRawLog ────────────────────────────────────────────────────────

describe('GetSessionRawLogQuery', () => {
  it('defaults format to ndjson', () => {
    const result = GetSessionRawLogQuery.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.format).toBe('ndjson');
    }
  });

  it('accepts format=json', () => {
    expect(GetSessionRawLogQuery.safeParse({ format: 'json' }).success).toBe(true);
  });

  it('rejects an invalid format value', () => {
    expect(GetSessionRawLogQuery.safeParse({ format: 'xml' }).success).toBe(false);
  });
});

// ─── exportActivity ──────────────────────────────────────────────────────────

describe('ExportActivityQuery', () => {
  it('defaults format to csv', () => {
    const result = ExportActivityQuery.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.format).toBe('csv');
    }
  });

  it('accepts format=json with list filters', () => {
    expect(
      ExportActivityQuery.safeParse({ format: 'json', harness: ['cursor'], q: 'settlement' })
        .success,
    ).toBe(true);
  });

  it('rejects an invalid format value', () => {
    expect(ExportActivityQuery.safeParse({ format: 'xml' }).success).toBe(false);
  });
});

// ─── /overview ────────────────────────────────────────────────────────────────

describe('ActivityOverviewResponse', () => {
  it('parses a stats + sessions fan-out payload', () => {
    expect(
      ActivityOverviewResponse.safeParse({
        stats: {
          sessionsToday: 3,
          liveNow: 1,
          toolCallsToday: 108,
          findingsToday: 3,
          egressToday: 5,
        },
        sessions: { items: [validSummary], nextCursor: null },
      }).success,
    ).toBe(true);
  });

  it('rejects a missing sessions key', () => {
    expect(
      ActivityOverviewResponse.safeParse({
        stats: {
          sessionsToday: 3,
          liveNow: 1,
          toolCallsToday: 108,
          findingsToday: 3,
          egressToday: 5,
        },
      }).success,
    ).toBe(false);
  });
});
