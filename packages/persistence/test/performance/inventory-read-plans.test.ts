/**
 * How SQLite executes the Inventory page's project findings reads: the findings
 * count of every listed project, the projects that need attention, and one
 * project's findings by category. Also the MCP list's tools-used count, which
 * reads the window's tool calls once for the page through `idx_audit_type_t`.
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

import { configInventoryInputs } from '@akasecurity/schema';
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
const TOOL_CALLS = 400;

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

describe('inventory MCP tools-used plan', () => {
  let mcpStore: OwnedTempStore;
  let mcpRepo: SqliteInventoryAssetsRepository;
  const mcpRecorded: RecordedQuery[] = [];

  beforeAll(() => {
    mcpStore = createTempStore('aka-inv-mcp-plans-', { migrated: true });
    const db = mcpStore.open();
    db.inventory.upsert(
      { objectType: 'harness', identityKey: 'claude-code', title: 'claude-code', attributes: {} },
      Date.now(),
    );
    const scannedAt = new Date().toISOString();
    db.recordConfigScan({
      items: configInventoryInputs({
        scannedAt,
        skills: [],
        hooks: [],
        mcpServers: [{ name: 'github', scope: 'user', transport: 'stdio', command: 'npx' }],
        configFiles: [],
        errors: [],
      }),
      scanEvent: {
        id: randomUUID(),
        eventType: 'config_scan',
        startedAt: scannedAt,
        attributes: {},
      },
    });
    for (let t = 0; t < TOOL_CALLS; t += 1) {
      db.auditEvents.insertAuditEvent({
        id: randomUUID(),
        eventType: 'tool_call',
        startedAt: new Date(Date.now() - (t % 60) * DAY_MS).toISOString(),
        attributes: { tool_name: t % 2 === 0 ? `mcp__github__tool_${String(t % 7)}` : 'Bash' },
      });
    }
    mcpRepo = new SqliteInventoryAssetsRepository(
      recordingConnection(mcpStore.openRaw(), mcpRecorded),
    );
  });

  afterAll(() => {
    mcpStore.destroy();
  });

  async function toolCallStatements(): Promise<RecordedQuery[]> {
    mcpRecorded.length = 0;
    await mcpRepo.listAssets({ type: ['mcp'] });
    return mcpRecorded.filter((q) => q.sql.includes("'tool_call'"));
  }

  it('reads the tool calls once for the page', async () => {
    expect(await toolCallStatements()).toHaveLength(1);
  });

  it("seeks the window's tool calls by index and walks nothing in full", async () => {
    const [statement] = await toolCallStatements();
    if (statement === undefined) throw new Error('the list read no tool call');
    const raw = mcpStore.openRaw();
    const owners = indexOwners(raw);
    const steps = explain(raw, statement).map((row) => classifyPlanRow(row.detail, owners));

    expect(steps.filter((s) => s.kind === 'full-table' || s.kind === 'full-index')).toEqual([]);
    expect(
      steps.some(
        (s) =>
          s.kind === 'search' &&
          s.detail.includes('idx_audit_type_t (event_type=? AND started_at>?)'),
      ),
    ).toBe(true);
  });
});
