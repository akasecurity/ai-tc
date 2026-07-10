import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DetectedFindingWithKey, EventKind, IngestEvent } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../database.ts';
import { DB_FILENAME } from '../paths.ts';
import { SqliteSecurityRepository } from './security.ts';

// PINS the status↔bucket contract between the two resolution read surfaces:
//
//   - SqliteFindingsRepository.listGroupedFindings (per-finding Status column)
//   - SqliteSecurityRepository.severitySummary (caught / needs-remediation)
//
// Both derive from the same latest-resolution-wins SQL (resolution-sql.ts), but
// each classifies the winning row itself — this suite seeds one store with every
// lifecycle scenario and asserts the two surfaces stay coherent, including the
// two DELIBERATE asymmetries (legacy untracked rows and 'dismissed' — see
// deriveInstanceStatus's DECISION note in findings.ts). If a future change makes
// the list call a finding Resolved while the card still counts it as
// needs-remediation (or vice versa), this fails before a dashboard can disagree
// with itself.

const NOW = Date.parse('2026-06-29T12:00:00.000Z');

let dir: string;
let db: ReturnType<typeof openLocalDatabase>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-resolution-consistency-'));
  db = openLocalDatabase(dir);
});

// Raw second connections handed to repos under test — closed before rmSync
// (Windows cannot delete a directory while a DB handle is open).
const rawConnections: DatabaseSync[] = [];

afterEach(() => {
  for (const raw of rawConnections.splice(0)) raw.close();
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

// One event + one finding per scenario; a distinct ruleId per scenario makes
// each list group hold exactly one instance, so group.status IS the instance
// status. All critical, so every scenario lands in the same summary row.
function record(opts: { ruleId: string; kind?: EventKind; findingKey?: string }): void {
  const id = randomUUID();
  const event: IngestEvent = {
    id,
    sourceTool: 'claude-code',
    kind: opts.kind ?? 'prompt',
    occurredAt: new Date(NOW).toISOString(),
    contentHash: id,
    content: 'x',
    ...(opts.kind === 'code_change' ? { metadata: { filePath: `/tmp/${opts.ruleId}.ts` } } : {}),
  };
  const finding: DetectedFindingWithKey = {
    id: randomUUID(),
    eventId: id,
    ruleId: opts.ruleId,
    category: 'secret',
    severity: 'critical',
    span: { start: 0, end: 1 },
    maskedMatch: 'x',
    actionTaken: 'block',
    confidence: 0.9,
    ...(opts.findingKey ? { findingKey: opts.findingKey } : {}),
  };
  db.recordCapture(event, [finding]);
}

function security(): SqliteSecurityRepository {
  const raw = new DatabaseSync(join(dir, DB_FILENAME));
  rawConnections.push(raw);
  return new SqliteSecurityRepository(raw, () => NOW);
}

describe('list status ↔ severity-card bucket consistency', () => {
  it('every lifecycle scenario classifies coherently across both surfaces', async () => {
    // 1. In-flight: born handled → caught.
    record({ ruleId: 'r-inflight' });
    // 2. At-rest, never resolved → open, needs remediation.
    record({ ruleId: 'r-open', kind: 'code_change', findingKey: 'k-open' });
    // 3. At-rest, fixed at source → resolved, caught.
    record({ ruleId: 'r-resolved', kind: 'code_change', findingKey: 'k-resolved' });
    db.resolutions.insertResolution({
      findingKey: 'k-resolved',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW,
      evidence: '{}',
    });
    // 4. At-rest, resolved then REDETECTED (latest row wins via rowid tiebreak
    //    on identical created_at) → open again, needs remediation.
    record({ ruleId: 'r-redetected', kind: 'code_change', findingKey: 'k-redetected' });
    db.resolutions.insertResolution({
      findingKey: 'k-redetected',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW,
      evidence: '{}',
    });
    db.resolutions.insertResolution({
      findingKey: 'k-redetected',
      status: 'open',
      method: 'redetected',
      resolvedAt: NOW,
      evidence: '{}',
    });
    // 5. At-rest, legacy untracked (finding_key NULL): the list shows it open
    //    (it exists and is unremediated) but the card counts it in NEITHER
    //    bucket — only in total (documented severitySummary exclusion).
    record({ ruleId: 'r-legacy', kind: 'code_change' });
    // 6. At-rest, dismissed: the list surfaces the dismissed label, the card
    //    still counts it as needs-remediation (never understate exposure —
    //    see the DECISION note on deriveInstanceStatus).
    record({ ruleId: 'r-dismissed', kind: 'code_change', findingKey: 'k-dismissed' });
    db.resolutions.insertResolution({
      findingKey: 'k-dismissed',
      status: 'dismissed',
      method: 'false-positive',
      resolvedAt: NOW,
      evidence: '{}',
    });

    const list = await db.findings.listGroupedFindings({});
    // A group's id IS its ruleId (buildFindingGroups groups by rule).
    const statusByRule = new Map(list.items.map((g) => [g.id, g.status]));
    expect(statusByRule.get('r-inflight')).toBe('handled');
    expect(statusByRule.get('r-open')).toBe('open');
    expect(statusByRule.get('r-resolved')).toBe('resolved');
    expect(statusByRule.get('r-redetected')).toBe('open');
    expect(statusByRule.get('r-legacy')).toBe('open');
    expect(statusByRule.get('r-dismissed')).toBe('dismissed');

    const summary = await security().severitySummary();
    const critical = summary.bySeverity.find((s) => s.severity === 'critical');
    // caught = handled (1) + resolved (1); openAtRest = open (1) + redetected
    // (1) + dismissed (1); legacy contributes to count ONLY (6 > 2 + 3).
    expect(critical).toEqual({ severity: 'critical', count: 6, caught: 2, openAtRest: 3 });
    expect(summary.total).toBe(6);
    expect(summary.needsRemediation).toBe(3);

    // The coherence contract, spelled out: a finding the list calls handled or
    // resolved is exactly a finding the card counts as caught — with the two
    // documented exceptions (legacy untracked: open but unbucketed; dismissed:
    // labeled dismissed but counted as needing remediation).
    const caughtStatuses = ['handled', 'resolved'];
    const caughtCount = [...statusByRule.entries()].filter(
      ([, s]) => s !== undefined && caughtStatuses.includes(s),
    ).length;
    expect(critical?.caught).toBe(caughtCount);
  });
});
