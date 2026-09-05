import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir, type LocalDatabase, openLocalDatabase } from '@akasecurity/persistence';
import type { DetectedFinding, IngestEvent, Severity, SourceTool } from '@akasecurity/schema';
import type { ComponentProps, ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { FindingsClient } from '../../app/(app)/findings/FindingsClient.tsx';
import FindingsPage from '../../app/(app)/findings/page.tsx';
import { emptyStore } from '../helpers/store-templates.ts';

// The By-type route issues THREE reads — the type list, the selected type's
// findings, and (only for a `?finding=` deep link) a single-row seek — and
// which one feeds which panel is the whole point of the split:
//
//   the type list  — narrowed by the TYPE-level dimensions: severity and `q`
//   the findings   — narrowed by the FINDING-level ones: provider, action,
//                    status, pinned to the selected type
//
// Every piece is covered elsewhere. The two query builders are pinned in
// findings-filters, the store reads in persistence, the panels in dashboard-ui.
// What none of them can see is the WIRING, because a query is just an object:
// send a finding-level filter to the type read and a reader's selected type
// vanishes from under them the moment they toggle a provider — silently, with
// the type, the lint and every existing assertion still green.
//
// So this suite drives the page itself. It is an async Server Component, which
// is a plain async function returning an element, so calling it and reading the
// props it hands down needs no renderer and no DOM. The store is real; only
// `homedir()` is redirected, since the page resolves ~/.aka from it and
// `n/no-process-env` rules out an env override.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

let home: string;
let dir: string;

// app/lib/db memoises its handle on globalThis across requests and HMR reloads,
// so a suite that does not drop it reads the PREVIOUS test's temp store.
function dropMemoisedDb(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-findings-page-'));
  osHome.dir = home;
  dir = dataDir();
  emptyStore.seed(dir);
  dropMemoisedDb();
});

afterEach(() => {
  dropMemoisedDb();
  removeTree(home);
});

interface SeedRow {
  ruleId: string;
  severity: Severity;
  sourceTool: SourceTool;
  action: 'block' | 'warn';
  file: string;
}

function seed(rows: SeedRow[]): void {
  const db = openLocalDatabase(dir);
  rows.forEach((row, i) => {
    const id = randomUUID();
    const event: IngestEvent = {
      id,
      sourceTool: row.sourceTool,
      kind: 'prompt',
      occurredAt: new Date(Date.UTC(2026, 0, 1) + i * 1000).toISOString(),
      contentHash: randomUUID(),
      content: 'x',
      metadata: { repo: 'acme/api', filePath: row.file },
    };
    const finding: DetectedFinding = {
      id: randomUUID(),
      eventId: id,
      ruleId: row.ruleId,
      category: 'secret',
      severity: row.severity,
      span: { start: 0, end: 1 },
      maskedMatch: 'masked',
      actionTaken: row.action,
      confidence: 0.9,
    };
    db.recordCapture(event, [finding]);
  });
  db.close();
  dropMemoisedDb();
}

// The fixture STRADDLES every boundary asserted below, which is what makes the
// assertions non-vacuous: two types at different severities, and within the
// selected type two findings on different providers with different actions.
// With one type, or with every finding alike, the cases below would pass
// whichever read the page used and prove nothing.
const CRITICAL_RULE = 'aws-key';
const LOW_RULE = 'todo-note';

function seedStraddlingFixture(): void {
  seed([
    {
      ruleId: CRITICAL_RULE,
      severity: 'critical',
      sourceTool: 'claude-code',
      action: 'block',
      file: 'a.ts',
    },
    {
      ruleId: CRITICAL_RULE,
      severity: 'critical',
      sourceTool: 'codex',
      action: 'warn',
      file: 'b.ts',
    },
    { ruleId: LOW_RULE, severity: 'low', sourceTool: 'claude-code', action: 'warn', file: 'c.ts' },
  ]);
}

type ClientProps = ComponentProps<typeof FindingsClient>;
type GroupedProps = Extract<ClientProps, { view: 'grouped' }>;

// Render the route the way Next calls it — `searchParams` arrives as a promise —
// and return the props it hands the client component.
//
// `element.type` is asserted rather than assumed: if the page ever returns a
// wrapper instead, every prop below reads `undefined`, and a suite that only
// checked the numbers would report the wrong reason for going red.
async function renderPage(params: Record<string, string> = {}): Promise<GroupedProps> {
  const element = (await FindingsPage({
    searchParams: Promise.resolve(params),
  })) as ReactElement<ClientProps>;
  expect(element.type).toBe(FindingsClient);
  const props = element.props;
  expect(props.view).toBe('grouped');
  return props as GroupedProps;
}

describe('findings page — the two panels are separately scoped', () => {
  it('lists every type and selects the first when nothing is pinned', async () => {
    seedStraddlingFixture();
    const props = await renderPage();

    expect(props.types.items.map((t) => t.id)).toEqual([CRITICAL_RULE, LOW_RULE]);
    expect(props.types.totals).toEqual({ findings: 3, types: 2 });
    // Worst severity first, so the default selection is the critical one.
    expect(props.selectedRule).toBe(CRITICAL_RULE);
    expect(props.instances?.items).toHaveLength(2);
  });

  it('pins the panel to ?rule= and reads only that type’s findings', async () => {
    seedStraddlingFixture();
    const props = await renderPage({ rule: LOW_RULE });

    expect(props.selectedRule).toBe(LOW_RULE);
    expect(props.instances?.items.map((i) => i.subtype)).toEqual([LOW_RULE]);
    // The list is untouched by the selection — it is not a filter.
    expect(props.types.items).toHaveLength(2);
  });

  // Severity is a property of the RULE, so it selects types. If it reached the
  // panel query instead it would keep every row or none, and if it reached
  // NEITHER the list would not narrow at all.
  it('sends severity to the type list', async () => {
    seedStraddlingFixture();
    const props = await renderPage({ severity: 'low' });

    expect(props.types.items.map((t) => t.id)).toEqual([LOW_RULE]);
    expect(props.selectedRule).toBe(LOW_RULE);
  });

  // Provider/action/status vary BETWEEN one type's findings, so they narrow the
  // panel and leave the list alone. This is the case that would go red if they
  // were sent to the type read: the list would drop to one type and the
  // selection would move.
  it('sends provider to the findings panel and leaves the type list alone', async () => {
    seedStraddlingFixture();
    const props = await renderPage({ provider: 'codex' });

    expect(props.types.items.map((t) => t.id)).toEqual([CRITICAL_RULE, LOW_RULE]);
    expect(props.selectedRule).toBe(CRITICAL_RULE);
    expect(props.instances?.items.map((i) => i.file)).toEqual(['b.ts']);
  });

  // The trade the level split makes, asserted rather than left implicit: the
  // panel can come back empty while the type stays listed and selected. The
  // view says so; it is not a state to engineer away.
  it('leaves the selection intact when a finding-level filter empties the panel', async () => {
    seedStraddlingFixture();
    const props = await renderPage({ rule: LOW_RULE, provider: 'codex' });

    expect(props.types.items.map((t) => t.id)).toContain(LOW_RULE);
    expect(props.selectedRule).toBe(LOW_RULE);
    expect(props.instances?.items).toEqual([]);
  });

  it('falls back to the first listed type when ?rule= names one the filters exclude', async () => {
    seedStraddlingFixture();
    // The critical type is filtered out of the list, so a panel showing it
    // would sit beside a list that disowns it.
    const props = await renderPage({ rule: CRITICAL_RULE, severity: 'low' });

    expect(props.types.items.map((t) => t.id)).toEqual([LOW_RULE]);
    expect(props.selectedRule).toBe(LOW_RULE);
  });
});

describe('findings page — the ?finding= deep link', () => {
  async function firstFindingId(rule: string): Promise<string> {
    const db = openLocalDatabase(dir);
    try {
      const res = await db.findings.listFindingInstances({ subtype: [rule] });
      return res.items[0]?.id ?? '';
    } finally {
      db.close();
      dropMemoisedDb();
    }
  }

  it('selects a linked finding’s TYPE and hands the drawer that finding', async () => {
    seedStraddlingFixture();
    const id = await firstFindingId(LOW_RULE);
    expect(id).not.toBe('');

    const props = await renderPage({ finding: id });
    expect(props.selectedRule).toBe(LOW_RULE);
    expect(props.deepLinkedInstance?.id).toBe(id);
    expect(props.deepLinkedInstance?.groupId).toBe(LOW_RULE);
  });

  it('overrides a ?rule= that disagrees with it', async () => {
    seedStraddlingFixture();
    const id = await firstFindingId(LOW_RULE);

    // Both params present and pointing at different types: the finding wins,
    // or the drawer would open on a row the panel beside it does not list.
    const props = await renderPage({ finding: id, rule: CRITICAL_RULE });
    expect(props.selectedRule).toBe(LOW_RULE);
  });

  // A deep link cannot select a type the list does not contain. `includeId`
  // appends the target when it survives the type-level filters, but a severity
  // filter that excludes it leaves nothing to append — and selecting it anyway
  // renders a panel beside a list that disowns it, which the client resolves by
  // showing "Select a type" and no drawer at all. Falling back to a listed type
  // keeps the page coherent.
  it('falls back to a listed type when a filter excludes the linked finding’s own', async () => {
    seedStraddlingFixture();
    const id = await firstFindingId(LOW_RULE);

    const props = await renderPage({ finding: id, severity: 'critical' });

    // The low-severity type is filtered out, so it cannot be the selection.
    expect(props.types.items.map((t) => t.id)).toEqual([CRITICAL_RULE]);
    expect(props.selectedRule).toBe(CRITICAL_RULE);
    // And the drawer does not open over a different type's findings.
    expect(props.deepLinkedInstance).toBeNull();
  });

  it('opens no drawer for an unknown id, and does not blank the page', async () => {
    seedStraddlingFixture();
    const props = await renderPage({ finding: 'no-such-finding' });

    expect(props.deepLinkedInstance).toBeNull();
    // The page still renders its list and a selection.
    expect(props.types.items).toHaveLength(2);
    expect(props.selectedRule).toBe(CRITICAL_RULE);
  });
});

describe('findings page — an empty store', () => {
  it('selects nothing and reads no findings rather than guessing a type', async () => {
    const props = await renderPage();

    expect(props.types.items).toEqual([]);
    expect(props.selectedRule).toBe('');
    // No type means no panel query to make — not an empty one against a type
    // that does not exist.
    expect(props.instances).toBeNull();
  });
});
