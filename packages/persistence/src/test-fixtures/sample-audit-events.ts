import type { DatabaseSync } from 'node:sqlite';

import { sampleActivityId } from './sample-ids.ts';

/**
 * Removable sample dataset for the Activity page, seeded onto the tenant-free
 * local `audit_events` store. There is no live writer for the rich session/
 * timeline attributes yet, so without this the Activity page would render
 * empty; the seed gives it representative data out of the box.
 *
 * Removability: `audit_events` has no `provenance` column, so every seeded row
 * carries the `sample:activity:` id prefix (+ `attributes.provenance='sample'`) —
 * exactly what sample-purge.ts deletes, which the activity tests exercise; real
 * scanned/ingested rows are never touched. Timestamps are materialized relative to
 * seed time so the sessions stay inside the default 7-day range as the clock advances.
 *
 * Two deliberate simplifications vs. the dummy data:
 *  - No descendant `session`-type rows: the "Session started" timeline entry is
 *    the root row itself (its `attributes.detail`), and "Session ended" events are
 *    dropped — a stray `session` descendant would surface as a junk session root.
 *  - Tool-call counts are the actual seeded `tool` events, not the dummy's inflated
 *    totals (every tool_call renders on the timeline), so counters ↔ timeline agree.
 */

const MINUTE_MS = 60_000;

type EventKind =
  | 'prompt'
  | 'response'
  | 'tool'
  | 'hook'
  | 'detection'
  | 'share'
  | 'permission'
  | 'commit'
  | 'error'
  | 'active';

interface SeedEvent {
  /** Minutes after the session start. */
  at: number;
  kind: EventKind;
  title: string;
  detail: string;
  tool?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  link?: 'detections' | 'shares' | 'inventory';
  targetId?: string;
  internal?: boolean;
  flagged?: boolean;
  /** Egress destination host — drives the distinct egress/shares count. */
  destination?: string;
}

interface SeedTokens {
  model: string;
  provider: string;
  input: number;
  output: number;
  cacheCreation: number;
  cacheRead: number;
}

interface SeedSession {
  slug: string;
  harness: string;
  title: string;
  project: string;
  repo: string;
  cwd: string;
  branches: string[];
  models: string[];
  version: string;
  files: string[];
  /** How long ago (minutes) the session started, relative to seed time. */
  startedMinAgo: number;
  /** Session length in minutes; null for a still-live (active) session. */
  durationMin: number | null;
  /** Explicit lifecycle status override (else derived from open/closed). */
  status?: 'interrupted' | 'error';
  /** Root-row detail — the "Session started" timeline line. */
  startDetail: string;
  tokens: SeedTokens;
  events: SeedEvent[];
}

const SAMPLE_SESSIONS: SeedSession[] = [
  {
    slug: 'payments-idempotency',
    harness: 'claudecode',
    title: 'Add idempotency keys to charge & refund',
    project: 'payments-api',
    repo: 'globex/payments-api',
    cwd: '~/code/payments-api',
    branches: ['feat/idempotency', 'main'],
    models: ['claude-sonnet-4-6', 'claude-opus-4-8'],
    version: 'Claude Code 2.1.4',
    files: ['src/services/charge.ts', 'src/services/refund.ts', 'src/db/idempotency.ts'],
    startedMinAgo: 46,
    durationMin: null,
    startDetail: 'claude-sonnet-4-6 · ~/code/payments-api @ feat/idempotency',
    tokens: {
      model: 'claude-sonnet-4-6',
      provider: 'anthropic',
      input: 128_400,
      output: 31_200,
      cacheCreation: 42_000,
      cacheRead: 486_000,
    },
    events: [
      {
        at: 1,
        kind: 'hook',
        title: 'SessionStart · load-context.sh',
        detail: 'Injected git status & current branch into context',
      },
      {
        at: 2,
        kind: 'prompt',
        title: 'Add idempotency keys to the charge and refund endpoints',
        detail: '1,420 tokens · turn 1',
      },
      {
        at: 3,
        kind: 'tool',
        title: 'Read 6 files',
        detail: 'src/services/charge.ts, refund.ts, +4',
        tool: 'Read',
      },
      {
        at: 5,
        kind: 'tool',
        title: 'Edited charge.ts',
        detail: '+48 −12 · idempotencyKey guard on create()',
        tool: 'Edit',
      },
      {
        at: 6,
        kind: 'detection',
        title: 'Redacted Postgres connection string',
        detail: 'In pasted context · src/config/database.ts · sent to provider with secret masked',
        severity: 'critical',
        link: 'detections',
        targetId: 'sample:finding:pg-conn',
      },
      {
        at: 9,
        kind: 'tool',
        title: 'Ran test suite',
        detail: 'npm test · 42 passed, 0 failed',
        tool: 'Bash',
      },
      {
        at: 12,
        kind: 'share',
        title: 'Prometheus · application logs',
        detail: 'POST logs.prometheus-obs.io/v1/ingest · logs',
        link: 'shares',
        destination: 'logs.prometheus-obs.io',
      },
      {
        at: 13,
        kind: 'share',
        title: 'Vault (internal) · secret read',
        detail: 'GET vault.globex.com/v1/secret/data/payments/db · secrets',
        link: 'shares',
        internal: true,
        destination: 'vault.globex.com',
      },
      {
        at: 17,
        kind: 'permission',
        title: 'Approved Bash(git commit)',
        detail: 'Auto-approved by ~/.claude/settings.json',
      },
      {
        at: 18,
        kind: 'commit',
        title: 'Committed 3 files',
        detail: 'feat: idempotency keys for charge/refund · a1f9c2e',
      },
      {
        // Kept near the session start (which is `startedMinAgo` in the past) so
        // this still-open session's last activity stays inside the "live" window
        // and it renders as the demo's one live session.
        at: 45,
        kind: 'active',
        title: 'Working…',
        detail: 'Writing migration for the idempotency table',
      },
    ],
  },
  {
    slug: 'matching-latency',
    harness: 'cursor',
    title: 'Investigate matching latency regression',
    project: 'matching-core',
    repo: 'globex/matching-core',
    cwd: '~/code/matching-core',
    branches: ['perf/profile-orderbook'],
    models: ['claude-sonnet-4-6'],
    version: 'Cursor 0.48',
    files: ['src/order_book.rs', 'benches/throughput.rs'],
    startedMinAgo: 180,
    durationMin: 38,
    startDetail: 'Cursor · claude-sonnet-4-6 · matching-core @ perf/profile-orderbook',
    tokens: {
      model: 'claude-sonnet-4-6',
      provider: 'anthropic',
      input: 94_100,
      output: 18_700,
      cacheCreation: 21_000,
      cacheRead: 210_000,
    },
    events: [
      {
        at: 1,
        kind: 'prompt',
        title: 'Why did p99 match latency jump after the last deploy?',
        detail: '980 tokens · turn 1',
      },
      {
        at: 2,
        kind: 'tool',
        title: 'Grep "order_book"',
        detail: '14 matches across 3 files',
        tool: 'Grep',
      },
      { at: 3, kind: 'tool', title: 'Read order_book.rs', detail: '1,204 lines', tool: 'Read' },
      {
        at: 8,
        kind: 'detection',
        title: 'Warned · large source paste',
        detail: 'order_book.rs (full file · 1,204 lines) attached to prompt',
        severity: 'high',
        link: 'detections',
        targetId: 'sample:finding:large-paste',
      },
      {
        at: 12,
        kind: 'tool',
        title: 'Ran benchmark',
        detail: 'cargo bench throughput · −18% vs baseline',
        tool: 'Bash',
      },
      {
        at: 26,
        kind: 'share',
        title: 'MetricHub · profiling metrics',
        detail: 'POST metrics.metricsync.io/v1/series · metrics',
        link: 'shares',
        destination: 'metrics.metricsync.io',
      },
    ],
  },
  {
    slug: 'deploy-runbook',
    harness: 'claudecode',
    title: 'Deploy runbook + Pulse notifier',
    project: 'infra-iac',
    repo: 'globex/infra-iac',
    cwd: '~/code/infra-iac',
    branches: ['main'],
    models: ['claude-sonnet-4-6'],
    version: 'Claude Code 2.1.4',
    files: ['docs/runbook.md', 'scripts/deploy.sh'],
    startedMinAgo: 300,
    durationMin: 19,
    startDetail: 'Claude Code · infra-iac @ main',
    tokens: {
      model: 'claude-sonnet-4-6',
      provider: 'anthropic',
      input: 41_800,
      output: 12_400,
      cacheCreation: 9_000,
      cacheRead: 96_000,
    },
    events: [
      {
        at: 1,
        kind: 'prompt',
        title: 'Write a deploy runbook and add a Pulse deploy notification',
        detail: '1,120 tokens · turn 1',
      },
      { at: 2, kind: 'tool', title: 'Wrote docs/runbook.md', detail: '+86 lines', tool: 'Write' },
      {
        at: 4,
        kind: 'tool',
        title: 'Edited scripts/deploy.sh',
        detail: '+12 · curl Pulse webhook on success',
        tool: 'Edit',
      },
      {
        at: 5,
        kind: 'detection',
        title: 'Blocked · GitHub PAT in script',
        detail: 'ghp_••••a91 hard-coded in deploy.sh · kept out of prompt',
        severity: 'high',
        link: 'detections',
        targetId: 'sample:finding:gh-pat',
      },
      {
        at: 14,
        kind: 'share',
        title: 'Pulse · deploy webhook',
        detail: 'POST hooks.pulse.io/workflows/… · logs',
        link: 'shares',
        destination: 'hooks.pulse.io',
      },
      {
        at: 18,
        kind: 'commit',
        title: 'Committed 2 files',
        detail: 'docs: deploy runbook + pulse notifier · 7d3e10a',
      },
    ],
  },
  {
    slug: 'crm-export',
    harness: 'claudecode',
    title: 'Customer export job for CRM sync',
    project: 'crm-sync',
    repo: 'globex/crm-sync',
    cwd: '~/code/crm-sync',
    branches: ['feat/nightly-export'],
    models: ['claude-sonnet-4-6', 'claude-haiku-4-5'],
    version: 'Claude Code 2.1.4',
    files: ['src/jobs/partner_sync.py', 'src/export.py'],
    startedMinAgo: 24 * 60 + 120,
    durationMin: 52,
    startDetail: 'Claude Code · crm-sync @ feat/nightly-export',
    tokens: {
      model: 'claude-sonnet-4-6',
      provider: 'anthropic',
      input: 112_600,
      output: 27_000,
      cacheCreation: 18_000,
      cacheRead: 301_000,
    },
    events: [
      {
        at: 1,
        kind: 'prompt',
        title: 'Build a nightly job that exports customer records to the partner SFTP',
        detail: '1,540 tokens · turn 1',
      },
      {
        at: 3,
        kind: 'tool',
        title: 'Read seed/customers.json',
        detail: 'fixture · 240 records',
        tool: 'Read',
      },
      {
        at: 4,
        kind: 'detection',
        title: 'Redacted PII · email + phone',
        detail: '2 fields masked before send · seed/customers.json',
        severity: 'medium',
        link: 'detections',
        targetId: 'sample:finding:pii-crm',
      },
      {
        at: 10,
        kind: 'tool',
        title: 'Wrote src/jobs/partner_sync.py',
        detail: '+74 lines · SFTP upload',
        tool: 'Write',
      },
      {
        at: 22,
        kind: 'share',
        title: 'Amazon S3 · export upload',
        detail: 'PUT backups-prod.s3.amazonaws.com/… · customer data',
        link: 'shares',
        destination: 'backups-prod.s3.amazonaws.com',
      },
      {
        at: 30,
        kind: 'share',
        title: 'acme-partner.com · SFTP (unverified)',
        detail: 'sftp://sftp.acme-partner.com/uploads/… · PII',
        severity: 'high',
        link: 'shares',
        flagged: true,
        destination: 'sftp.acme-partner.com',
      },
      {
        at: 36,
        kind: 'detection',
        title: 'Warned · customer account records',
        detail: 'cust_8841 +12 records referenced in prompt',
        severity: 'medium',
        link: 'detections',
        targetId: 'sample:finding:cust-records',
      },
      {
        at: 48,
        kind: 'commit',
        title: 'Committed 3 files',
        detail: 'feat: nightly partner export · b90c4d1',
      },
    ],
  },
  {
    slug: 'churn-notebook',
    harness: 'claudecode',
    title: 'Churn analysis notebook',
    project: 'analytics-nb',
    repo: 'globex/analytics-nb',
    cwd: '~/code/analytics-nb',
    branches: ['main'],
    models: ['claude-sonnet-4-6'],
    version: 'Claude Code 2.1.4',
    files: ['notebooks/churn.ipynb', 'lib/queries.py'],
    startedMinAgo: 24 * 60 + 300,
    durationMin: 31,
    startDetail: 'Claude Code · analytics-nb @ main',
    tokens: {
      model: 'claude-sonnet-4-6',
      provider: 'anthropic',
      input: 63_300,
      output: 20_900,
      cacheCreation: 12_000,
      cacheRead: 142_000,
    },
    events: [
      {
        at: 1,
        kind: 'prompt',
        title: 'Summarize churn drivers from the warehouse cohort query',
        detail: '1,210 tokens · turn 1',
      },
      {
        at: 3,
        kind: 'tool',
        title: 'Ran cohort query',
        detail: 'lib/queries.py · 18,400 rows',
        tool: 'Bash',
      },
      {
        at: 7,
        kind: 'share',
        title: 'OpenAI · chat completion',
        detail: 'POST api.openai.com/v1/chat/completions · source',
        severity: 'high',
        link: 'shares',
        destination: 'api.openai.com',
      },
      {
        at: 14,
        kind: 'detection',
        title: 'Warned · customer account records',
        detail: 'Account records embedded in notebook output',
        severity: 'medium',
        link: 'detections',
        targetId: 'sample:finding:nb-records',
      },
      {
        at: 29,
        kind: 'tool',
        title: 'Edited churn.ipynb',
        detail: '+2 cells · summary + chart',
        tool: 'Edit',
      },
    ],
  },
  {
    slug: 'notion-mcp',
    harness: 'codex',
    title: 'Scaffold MCP server for Notion',
    project: 'mcp-builder',
    repo: 'globex/mcp-builder',
    cwd: '~/code/mcp-builder',
    branches: ['feat/notion-bridge'],
    models: ['gpt-5-codex'],
    version: 'Codex CLI 0.12',
    files: ['src/server.ts', '.mcp.json'],
    startedMinAgo: 3 * 24 * 60 + 120,
    durationMin: 27,
    startDetail: 'Codex CLI · gpt-5-codex · mcp-builder @ feat/notion-bridge',
    tokens: {
      model: 'gpt-5-codex',
      provider: 'openai',
      input: 58_000,
      output: 22_300,
      cacheCreation: 6_000,
      cacheRead: 88_000,
    },
    events: [
      {
        at: 1,
        kind: 'prompt',
        title: 'Scaffold an MCP server that bridges Notion search',
        detail: '1,030 tokens · turn 1',
      },
      { at: 3, kind: 'tool', title: 'Wrote src/server.ts', detail: '+140 lines', tool: 'Write' },
      {
        at: 7,
        kind: 'permission',
        title: 'Denied Bash(npm publish)',
        detail: 'Blocked by policy · publish not in allow-list',
        severity: 'high',
      },
      {
        at: 10,
        kind: 'tool',
        title: 'Edited .mcp.json',
        detail: 'Registered mcp://notion-bridge',
        tool: 'Edit',
      },
      {
        at: 25,
        kind: 'commit',
        title: 'Committed 2 files',
        detail: 'feat: notion MCP bridge · c41a880',
      },
    ],
  },
  {
    slug: 'ci-release-debug',
    harness: 'claudecode',
    title: 'Debug failing CI on release',
    project: 'infra-iac',
    repo: 'globex/infra-iac',
    cwd: '~/code/infra-iac',
    branches: ['ci/fix-release'],
    models: ['claude-sonnet-4-6'],
    version: 'Claude Code 2.1.3',
    files: ['.github/workflows/release.yml'],
    startedMinAgo: 3 * 24 * 60 + 300,
    durationMin: 14,
    status: 'interrupted',
    startDetail: 'Claude Code · infra-iac @ ci/fix-release',
    tokens: {
      model: 'claude-sonnet-4-6',
      provider: 'anthropic',
      input: 28_700,
      output: 6_100,
      cacheCreation: 4_000,
      cacheRead: 40_000,
    },
    events: [
      {
        at: 1,
        kind: 'prompt',
        title: 'The release workflow fails on the publish step — find out why',
        detail: '870 tokens · turn 1',
      },
      { at: 2, kind: 'tool', title: 'Read release.yml', detail: '92 lines', tool: 'Read' },
      {
        at: 7,
        kind: 'tool',
        title: 'Ran act -j release',
        detail: 'exited 1 · missing NPM_TOKEN secret',
        tool: 'Bash',
      },
      {
        at: 13,
        kind: 'error',
        title: 'Session interrupted',
        detail: 'User cancelled (Ctrl-C) before fix applied',
        severity: 'medium',
      },
    ],
  },
];

// `tool` (contract kind) maps to the DB event_type `tool_call`; every other kind
// is stored under its own name (the DB has no CHECK on event_type, so the seed-only
// kinds — hook/detection/share/permission/commit/error/active — insert fine).
function dbEventType(kind: EventKind): string {
  return kind === 'tool' ? 'tool_call' : kind;
}

/** Inserts the sample Activity dataset (all rows id-prefixed `sample:activity:`). */
export function seedSampleAuditEvents(db: DatabaseSync, now: number = Date.now()): void {
  const insRoot = db.prepare(
    `INSERT OR IGNORE INTO audit_events (id, event_type, started_at, ended_at, content, attributes)
     VALUES (:id, 'session', :startedAt, :endedAt, :title, :attributes)`,
  );
  const insEvent = db.prepare(
    `INSERT OR IGNORE INTO audit_events (id, root_session_id, event_type, started_at, content, attributes)
     VALUES (:id, :sessionId, :type, :startedAt, :title, :attributes)`,
  );
  const insDefinition = db.prepare(
    `INSERT OR IGNORE INTO inspection_definitions (id, rule_id, name, category, severity, definition, version)
     VALUES ('sample:activity:def', 'sample.activity.detection', 'Sample detection', 'secret', 'high', '{}', '1')`,
  );
  const insFinding = db.prepare(
    `INSERT OR IGNORE INTO inspection_findings
       (id, audit_event_id, inspection_definition_id, span_start, span_end, masked_match, action_taken, confidence)
     VALUES (:id, :auditEventId, 'sample:activity:def', 0, 1, '••••', :action, 1)`,
  );

  insDefinition.run();

  for (const s of SAMPLE_SESSIONS) {
    const rootId = sampleActivityId(s.slug);
    const startedAt = now - s.startedMinAgo * MINUTE_MS;
    const endedAt = s.durationMin === null ? null : startedAt + s.durationMin * MINUTE_MS;

    insRoot.run({
      id: rootId,
      startedAt,
      endedAt,
      title: s.title,
      attributes: JSON.stringify({
        harness: s.harness,
        project: s.project,
        repo: s.repo,
        branches: s.branches,
        host: 'globex-mbp.local',
        cwd: s.cwd,
        models: s.models,
        version: s.version,
        files: s.files,
        detail: s.startDetail,
        ...(s.status ? { status: s.status } : {}),
        provenance: 'sample',
      }),
    });

    // One llm_call leaf carries the session's token totals (snake_case keys feed
    // the generated token columns the detail read SUMs).
    insEvent.run({
      id: `${rootId}:llm`,
      sessionId: rootId,
      type: 'llm_call',
      startedAt: startedAt + 30_000,
      title: '',
      attributes: JSON.stringify({
        model: s.tokens.model,
        provider: s.tokens.provider,
        input_tokens: s.tokens.input,
        output_tokens: s.tokens.output,
        cache_creation_input_tokens: s.tokens.cacheCreation,
        cache_read_input_tokens: s.tokens.cacheRead,
        provenance: 'sample',
      }),
    });

    s.events.forEach((e, i) => {
      const eventId = `${rootId}:${String(i)}`;
      insEvent.run({
        id: eventId,
        sessionId: rootId,
        type: dbEventType(e.kind),
        startedAt: startedAt + e.at * MINUTE_MS,
        title: e.title,
        attributes: JSON.stringify({
          detail: e.detail,
          ...(e.tool ? { tool: e.tool } : {}),
          ...(e.severity ? { severity: e.severity } : {}),
          ...(e.link ? { link: e.link } : {}),
          ...(e.targetId ? { targetId: e.targetId } : {}),
          ...(e.internal ? { internal: true } : {}),
          ...(e.flagged ? { flagged: true } : {}),
          ...(e.destination ? { destination: e.destination } : {}),
          provenance: 'sample',
        }),
      });

      // Each detection event gets one inspection finding, so the per-session
      // findings rollup equals its detection count (matching the dummy figures).
      if (e.kind === 'detection') {
        insFinding.run({
          id: `${eventId}:finding`,
          auditEventId: eventId,
          action: 'redact',
        });
      }
    });
  }
}
