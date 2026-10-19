import { randomUUID } from 'node:crypto';

import type { DetectedFinding } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// The Inventory projects read views must never surface a Claude Code worktree
// CHECKOUT as a project: pre-worktree-fix plugins minted a source_project row
// per `.claude/worktrees/*` session, and an older plugin can re-mint one at any
// time. The checkout is already part of its head project.

const store = useTempStore('aka-inv-projects-', { migrated: true });
let db: LocalDatabase;

beforeEach(() => {
  db = store.open();
});

describe('worktree-checkout ghost rows', () => {
  it('are hidden from listProjects and the project stat, browsable or not', async () => {
    db.sourceProject.upsert(
      { url: 'https://github.com/org/payments-api.git', name: 'payments-api', attributes: {} },
      Date.now(),
    );
    db.sourceProject.upsert(
      {
        url: '/home/dev/payments-api/.claude/worktrees/busy-allen-cbd90f',
        name: 'busy-allen-cbd90f',
        attributes: {},
      },
      Date.now(),
    );

    const projects = await db.inventoryAssets.listProjects();
    expect(projects.items.map((p) => p.name)).toEqual(['payments-api']);

    // The search path composes the same guard (AND, not a replaced WHERE).
    const searched = await db.inventoryAssets.listProjects('busy-allen');
    expect(searched.items).toEqual([]);

    const stats = await db.inventoryAssets.getInventoryStats();
    expect(stats.byType.project).toBe(1);
  });

  it('hides Windows (backslash-separated) checkout ghosts too', async () => {
    db.sourceProject.upsert(
      {
        url: 'C:\\dev\\payments-api\\.claude\\worktrees\\wt-x',
        name: 'wt-x',
        attributes: {},
      },
      Date.now(),
    );

    const projects = await db.inventoryAssets.listProjects();
    expect(projects.items).toEqual([]);
    const stats = await db.inventoryAssets.getInventoryStats();
    expect(stats.byType.project).toBe(0);
  });

  it('keeps a remote-less repo keyed by a plain root path visible', async () => {
    db.sourceProject.upsert(
      { url: '/home/dev/local-only-repo', name: 'local-only-repo', attributes: {} },
      Date.now(),
    );

    const projects = await db.inventoryAssets.listProjects();
    expect(projects.items.map((p) => p.name)).toEqual(['local-only-repo']);
  });
});

const DAY_MS = 86_400_000;

/**
 * A session in `url`'s project whose captures, `ago` ms back, carry the given findings, and
 * optionally a config scan under the session carrying one posture finding.
 */
function sessionWithFindings(
  url: string | null,
  captures: { ago: number; findings: Partial<DetectedFinding>[]; filePath?: string }[],
  options: { postureScan?: boolean } = {},
): string | undefined {
  const sessionId = randomUUID();
  const resolved = db.ensureInventory(
    url === null ? {} : { project: { url, name: url.split('/').pop() ?? url, attributes: {} } },
  );
  db.auditEvents.insertAuditEvent({
    id: sessionId,
    eventType: 'session',
    startedAt: new Date(Date.now() - 40 * DAY_MS).toISOString(),
    ...(resolved.sourceProjectId === undefined
      ? {}
      : { sourceProjectId: resolved.sourceProjectId }),
    attributes: { cwd: '/work' },
  });
  for (const capture of captures) {
    const event = captureEvent({
      kind: capture.filePath === undefined ? 'prompt' : 'code_change',
      occurredAt: new Date(Date.now() - capture.ago).toISOString(),
      metadata: {
        sessionId,
        ...(capture.filePath === undefined ? {} : { filePath: capture.filePath }),
      },
    });
    db.recordCapture(
      event,
      capture.findings.map((f) => captureFinding(event.id, f)),
    );
  }
  if (options.postureScan === true) {
    db.recordConfigScan({
      items: [],
      scanEvent: {
        id: randomUUID(),
        eventType: 'config_scan',
        startedAt: new Date(Date.now() - DAY_MS).toISOString(),
        parentId: sessionId,
        rootSessionId: sessionId,
        attributes: {},
      },
      definitions: [
        {
          ruleId: 'hook-conflict',
          version: '1',
          name: 'Overlapping hooks',
          category: 'config',
          severity: 'medium',
          definition: '{}',
        },
      ],
      findings: [
        {
          ruleId: 'hook-conflict',
          version: '1',
          span: { start: 0, end: 4 },
          maskedMatch: 'lint',
          actionTaken: 'warn',
          confidence: 0.7,
        },
      ],
    });
  }
  return resolved.sourceProjectId;
}

describe('project findings', () => {
  it("counts the findings in the project's sessions over the last 30 days", async () => {
    const id = sessionWithFindings('https://github.com/org/payments-api.git', [
      { ago: DAY_MS, findings: [{}, {}] },
      { ago: 29 * DAY_MS, findings: [{}] },
      { ago: 31 * DAY_MS, findings: [{}, {}, {}] },
    ]);
    sessionWithFindings('https://github.com/org/other.git', [{ ago: DAY_MS, findings: [{}] }]);
    sessionWithFindings(null, [{ ago: DAY_MS, findings: [{}] }]);

    const { items } = await db.inventoryAssets.listProjects();

    expect(items.find((p) => p.id === id)?.findingsCount).toBe(3);
    expect(items.find((p) => p.name === 'other.git')?.findingsCount).toBe(1);
  });

  it('counts across every session of the project', async () => {
    const url = 'https://github.com/org/payments-api.git';
    const id = sessionWithFindings(url, [{ ago: DAY_MS, findings: [{}] }]);
    sessionWithFindings(url, [{ ago: 2 * DAY_MS, findings: [{}, {}] }]);

    const { items } = await db.inventoryAssets.listProjects();

    expect(items.find((p) => p.id === id)?.findingsCount).toBe(3);
  });

  it('is zero for a project whose findings are all older than the window', async () => {
    const id = sessionWithFindings('https://github.com/org/payments-api.git', [
      { ago: 31 * DAY_MS, findings: [{}] },
    ]);

    const { items } = await db.inventoryAssets.listProjects();

    expect(items.find((p) => p.id === id)?.findingsCount).toBe(0);
  });

  it("leaves out the posture findings of the sessions' config scans", async () => {
    const url = 'https://github.com/org/payments-api.git';
    const id = sessionWithFindings(url, [{ ago: DAY_MS, findings: [{}] }], { postureScan: true });
    sessionWithFindings('https://github.com/org/quiet.git', [], { postureScan: true });

    const { items } = await db.inventoryAssets.listProjects();
    const stats = await db.inventoryAssets.getInventoryStats();

    expect(items.find((p) => p.id === id)?.findingsCount).toBe(1);
    expect(items.find((p) => p.name === 'quiet.git')?.findingsCount).toBe(0);
    expect(stats.attention).toBe(1);
  });

  it('counts a project with a finding in the window once toward attention', async () => {
    sessionWithFindings('https://github.com/org/payments-api.git', [
      { ago: DAY_MS, findings: [{}, {}] },
      { ago: 2 * DAY_MS, findings: [{}] },
    ]);
    sessionWithFindings('https://github.com/org/quiet.git', [{ ago: 31 * DAY_MS, findings: [{}] }]);
    sessionWithFindings('/home/dev/payments-api/.claude/worktrees/wt-a', [
      { ago: DAY_MS, findings: [{}] },
    ]);

    const stats = await db.inventoryAssets.getInventoryStats();

    expect(stats.attention).toBe(1);
  });
});

describe('project sensitive data', () => {
  const URL = 'https://github.com/org/payments-api.git';

  it('groups the findings in the window by category, worst severity first', async () => {
    const id = sessionWithFindings(URL, [
      {
        ago: DAY_MS,
        filePath: 'src/a.ts',
        findings: [{ category: 'secret', severity: 'high' }],
      },
      {
        ago: 2 * DAY_MS,
        filePath: 'src/b.ts',
        findings: [{ category: 'secret', severity: 'critical' }],
      },
      {
        ago: 3 * DAY_MS,
        filePath: 'src/a.ts',
        findings: [{ category: 'pii', severity: 'medium' }],
      },
      { ago: 4 * DAY_MS, findings: [{ category: 'pii', severity: 'low' }] },
      {
        ago: 31 * DAY_MS,
        filePath: 'src/old.ts',
        findings: [{ category: 'financial', severity: 'critical' }],
      },
    ]);
    if (id === undefined) throw new Error('no project');

    const data = await db.inventoryAssets.getProjectSensitiveData(id);

    expect(data?.items.map((c) => [c.category, c.files, c.severity])).toEqual([
      ['secret', 2, 'critical'],
      ['pii', 1, 'medium'],
    ]);
  });

  it('names the newest finding of each category', async () => {
    const id = sessionWithFindings(URL, [
      { ago: 5 * DAY_MS, filePath: 'src/a.ts', findings: [{ category: 'secret' }] },
      { ago: DAY_MS, filePath: 'src/b.ts', findings: [{ category: 'secret' }] },
    ]);
    if (id === undefined) throw new Error('no project');

    const [secret] = (await db.inventoryAssets.getProjectSensitiveData(id))?.items ?? [];
    const age = Date.now() - Date.parse(secret?.lastDetectedAt ?? '');

    expect(age).toBeGreaterThanOrEqual(DAY_MS);
    expect(age).toBeLessThan(2 * DAY_MS);
  });

  it('is empty for a project with no finding in the window, and null for an unknown one', async () => {
    const id = sessionWithFindings(URL, [{ ago: 31 * DAY_MS, findings: [{}] }]);
    if (id === undefined) throw new Error('no project');

    expect(await db.inventoryAssets.getProjectSensitiveData(id)).toEqual({ items: [] });
    expect(await db.inventoryAssets.getProjectSensitiveData('nope')).toBeNull();
  });

  it('leaves out the posture findings of config scans', async () => {
    const id = sessionWithFindings(URL, [{ ago: DAY_MS, findings: [{ category: 'pii' }] }], {
      postureScan: true,
    });
    if (id === undefined) throw new Error('no project');

    const data = await db.inventoryAssets.getProjectSensitiveData(id);

    expect(data?.items.map((c) => c.category)).toEqual(['pii']);
  });

  it("leaves out another project's findings", async () => {
    const id = sessionWithFindings(URL, [{ ago: DAY_MS, findings: [{ category: 'pii' }] }]);
    sessionWithFindings('https://github.com/org/other.git', [
      { ago: DAY_MS, findings: [{ category: 'secret' }] },
    ]);
    if (id === undefined) throw new Error('no project');

    const data = await db.inventoryAssets.getProjectSensitiveData(id);

    expect(data?.items.map((c) => c.category)).toEqual(['pii']);
  });
});
