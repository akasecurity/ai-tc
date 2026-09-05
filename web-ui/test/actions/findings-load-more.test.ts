import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir, type LocalDatabase, openLocalDatabase } from '@akasecurity/persistence';
import type { DetectedFinding, IngestEvent } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import {
  loadMoreFindingInstances,
  loadMoreFindingTypes,
} from '../../app/(app)/findings/actions.ts';
import { emptyStore } from '../helpers/store-templates.ts';

/**
 * The findings list's "Load more" actions.
 *
 * These are READ actions that take a query from the browser, so the property
 * that matters is the boundary: an action is a POST endpoint anything can
 * reach, and a hand-rolled body must be rejected rather than reaching the store
 * as a query.
 *
 * Setup follows the four steps every web-ui Server Action test needs: redirect
 * the home dir by mocking `node:os` (the action resolves ~/.aka from it, and
 * n/no-process-env rules out an env override), stub `next/cache`, and close and
 * drop the memoised DB handle on globalThis around every test.
 */
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// app/lib/db.ts memoises its handle on globalThis across requests and HMR
// reloads, so it must be closed and dropped between tests or the next action
// reads the PREVIOUS test's store.
function dropMemoisedDb(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

let home: string;
let dir: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-findings-more-'));
  osHome.dir = home;
  // dataDir()'s argument is the ~/.aka ROOT, not the home — with the mock in
  // place the no-argument form resolves to exactly what the action will open.
  dir = dataDir();
  // Schema by file copy rather than a migration this test would only repeat.
  emptyStore.seed(dir);
  dropMemoisedDb();
});

afterEach(() => {
  dropMemoisedDb();
  removeTree(home);
});

/** Seed `n` findings through a second handle, then drop the memoised one. */
function seed(n: number): void {
  const db = openLocalDatabase(dir);
  for (let i = 0; i < n; i += 1) {
    const id = randomUUID();
    const event: IngestEvent = {
      id,
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: new Date(Date.UTC(2026, 0, 1) + i * 1000).toISOString(),
      contentHash: randomUUID(),
      content: 'x',
      metadata: { repo: 'acme/api', filePath: `f${String(i)}.ts` },
    };
    const finding: DetectedFinding = {
      id: randomUUID(),
      eventId: id,
      ruleId: `rule-${String(i % 4)}`,
      category: 'secret',
      severity: 'critical',
      span: { start: 0, end: 1 },
      maskedMatch: 'masked',
      actionTaken: 'block',
      confidence: 0.9,
    };
    db.recordCapture(event, [finding]);
  }
  db.close();
  dropMemoisedDb();
}

describe('loadMoreFindingInstances', () => {
  it('returns the page after the cursor without repeating a row', async () => {
    seed(12);
    const first = await loadMoreFindingInstances({ limit: 5 });
    expect(first.items).toHaveLength(5);
    expect(first.nextCursor).not.toBeNull();

    const second = await loadMoreFindingInstances({ limit: 5, cursor: first.nextCursor });
    const ids = new Set([...first.items, ...second.items].map((i) => i.id));
    expect(ids.size).toBe(first.items.length + second.items.length);
  });

  it('reports totals over the whole scope, not the page', async () => {
    seed(12);
    const page = await loadMoreFindingInstances({ limit: 5 });
    expect(page.totals.findings).toBe(12);
  });

  it('rejects a malformed query at the boundary', async () => {
    seed(1);
    // A severity outside the enum, a limit past the ceiling, and a wrong-typed
    // filter each have to be refused rather than reaching the store.
    await expect(loadMoreFindingInstances({ severity: ['bogus'] })).rejects.toThrow();
    await expect(loadMoreFindingInstances({ limit: 9999 })).rejects.toThrow();
    await expect(loadMoreFindingInstances({ tool: 'not-an-array' })).rejects.toThrow();
    await expect(loadMoreFindingInstances(null)).rejects.toThrow();
  });

  it('accepts an empty query', async () => {
    seed(2);
    const res = await loadMoreFindingInstances({});
    expect(res.totals.findings).toBe(2);
  });
});

describe('loadMoreFindingTypes', () => {
  it('returns the page after the cursor without repeating a type', async () => {
    seed(12);
    const first = await loadMoreFindingTypes({ limit: 2 });
    expect(first.items).toHaveLength(2);
    expect(first.nextCursor).not.toBeNull();

    const second = await loadMoreFindingTypes({ limit: 2, cursor: first.nextCursor });
    const ids = new Set([...first.items, ...second.items].map((g) => g.id));
    expect(ids.size).toBe(first.items.length + second.items.length);
  });

  it('rejects a malformed query at the boundary', async () => {
    seed(1);
    await expect(loadMoreFindingTypes({ status: ['nope'] })).rejects.toThrow();
    await expect(loadMoreFindingTypes({ limit: -1 })).rejects.toThrow();
    await expect(loadMoreFindingTypes('a string')).rejects.toThrow();
  });

  it('counts types across the whole scope, not just the page', async () => {
    seed(12);
    const page = await loadMoreFindingTypes({ limit: 2 });
    expect(page.items).toHaveLength(2);
    expect(page.totals.types).toBe(4);
  });
});

// The detail panel's read: one type's findings, which is the half the old
// grouped read folded in as a bounded preview. It is the same action the flat
// view drives, scoped by `subtype`.
describe('loadMoreFindingInstances scoped to one type', () => {
  it('returns only that type’s findings, and pages them', async () => {
    seed(12);
    const page = await loadMoreFindingInstances({ subtype: ['rule-0'], limit: 5 });
    expect(page.items.length).toBeGreaterThan(0);
    expect(new Set(page.items.map((i) => i.subtype))).toEqual(new Set(['rule-0']));
  });

  it('rejects a malformed subtype at the boundary', async () => {
    seed(1);
    await expect(loadMoreFindingInstances({ subtype: 'rule-0' })).rejects.toThrow();
    await expect(loadMoreFindingInstances({ subtype: [1] })).rejects.toThrow();
  });
});
