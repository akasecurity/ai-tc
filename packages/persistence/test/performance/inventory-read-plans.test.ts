/**
 * How SQLite executes the Inventory page's project findings reads: the findings
 * count of every listed project, the projects that need attention, and one
 * project's findings by category.
 *
 * A project's findings are reached through its sessions: the session root names
 * the project, each capture names its session, and each finding names its
 * capture. The plan must start from the project's sessions
 * (`idx_audit_project_t`), seek each session's events inside the window
 * (`idx_audit_session`), and probe each event's findings by index. Any other
 * order passes over every event or every finding the store holds.
 *
 * The statements are captured from the reads as the repository issues them and
 * never restated here.
 */
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { SqliteInventoryAssetsRepository } from '../../src/repositories/inventory-assets.ts';
import { captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import type { RecordedQuery } from '../helpers/query-plans.ts';
import {
  classifyPlanRow,
  explain,
  indexOwners,
  recordingConnection,
} from '../helpers/query-plans.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const DAY_MS = 86_400_000;
const PROJECTS = 4;
const SESSIONS_PER_PROJECT = 3;
const CAPTURES_PER_SESSION = 5;

let store: OwnedTempStore;
let db: LocalDatabase;
let repo: SqliteInventoryAssetsRepository;
let recorded: RecordedQuery[];
let projectId: string;

beforeAll(() => {
  store = createTempStore('aka-inv-plans-', { migrated: true });
  db = store.open();
  for (let p = 0; p < PROJECTS; p += 1) {
    const resolved = db.ensureInventory({
      project: {
        url: `https://github.com/org/repo-${String(p)}.git`,
        name: `repo-${String(p)}`,
        attributes: {},
      },
    });
    if (resolved.sourceProjectId === undefined) throw new Error('no project id');
    projectId = resolved.sourceProjectId;
    for (let s = 0; s < SESSIONS_PER_PROJECT; s += 1) {
      const sessionId = randomUUID();
      db.auditEvents.insertAuditEvent({
        id: sessionId,
        eventType: 'session',
        startedAt: new Date(Date.now() - 10 * DAY_MS).toISOString(),
        sourceProjectId: resolved.sourceProjectId,
        attributes: { cwd: '/work' },
      });
      for (let c = 0; c < CAPTURES_PER_SESSION; c += 1) {
        const event = captureEvent({
          kind: 'code_change',
          occurredAt: new Date(Date.now() - c * DAY_MS).toISOString(),
          metadata: { sessionId, filePath: `src/f${String(c)}.ts` },
        });
        db.recordCapture(event, [captureFinding(event.id)]);
      }
    }
  }
  recorded = [];
  repo = new SqliteInventoryAssetsRepository(recordingConnection(store.openRaw(), recorded));
});

afterAll(() => {
  store.destroy();
});

/** The statements a read issued that reach a finding. */
async function findingStatements(read: () => Promise<unknown>): Promise<RecordedQuery[]> {
  recorded.length = 0;
  await read();
  return recorded.filter((q) => q.sql.includes('inspection_findings'));
}

/**
 * Each read, and the tables it passes over in full. The attention count walks
 * the project list itself (`source_project p`, one row per project) and probes
 * each project; nothing walks the events or the findings.
 */
const READS: [string, () => Promise<unknown>, string[]][] = [
  ['listProjects', () => repo.listProjects(), []],
  ['getInventoryStats', () => repo.getInventoryStats(), ['SCAN p']],
  ['getProjectSensitiveData', () => repo.getProjectSensitiveData(projectId), []],
];

describe('inventory project findings plans', () => {
  it.each(READS)('%s reaches findings in one statement', async (_name, read) => {
    expect(await findingStatements(read)).toHaveLength(1);
  });

  it.each(READS)(
    '%s starts from the project sessions and seeks events and findings by index',
    async (_name, read, fullScans) => {
      const [statement] = await findingStatements(read);
      if (statement === undefined) throw new Error('the read reached no finding');
      const raw = store.openRaw();
      const owners = indexOwners(raw);
      const steps = explain(raw, statement).map((row) => classifyPlanRow(row.detail, owners));

      expect(steps.filter((s) => s.kind === 'full-table').map((s) => s.detail)).toEqual(fullScans);
      expect(steps.filter((s) => s.kind === 'full-index')).toEqual([]);
      const searches = steps.filter((s) => s.kind === 'search').map((s) => s.detail);
      const first = searches.find((d) => d.includes('idx_audit_'));
      expect(first).toContain('idx_audit_project_t');
      expect(
        searches.some((d) => d.includes('idx_audit_session (root_session_id=? AND started_at>?)')),
      ).toBe(true);
      expect(
        searches.some((d) => /USING (COVERING )?INDEX idx_inspection_findings_event/.test(d)),
      ).toBe(true);
    },
  );
});
