import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir, type LocalDatabase, openLocalDatabase } from '@akasecurity/persistence';
import type {
  DetectedFinding,
  DetectionCategory,
  IngestEvent,
  Severity,
} from '@akasecurity/schema';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import SecurityPage from '../../app/(app)/security/page.tsx';
import { WidgetNavigation } from '../../app/(app)/security/WidgetNavigation.tsx';
import { emptyStore } from '../helpers/store-templates.ts';

// The Security route hands each widget a set of deep links, and which WINDOW a
// link carries is decided per widget: the page reads `inspection_findings` three
// ways — whole-store for the severity summary, range-scoped for enforcement, top
// sources and the recommendations.
//
// A link carrying the wrong window is still a perfectly valid URL. It typechecks,
// it lints, it renders, and it opens a findings page — just not one holding the
// number the user clicked. Nothing but a fixture straddling the boundary can tell
// the two apart, which is why this suite exists rather than trusting the builders'
// own unit tests: those prove `severityHref` omits a range, not that the PAGE
// called it for the severity card.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

let home: string;
let dir: string;

function dropMemoisedDb(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-security-page-'));
  osHome.dir = home;
  dir = dataDir();
  emptyStore.seed(dir);
  dropMemoisedDb();
});

afterEach(() => {
  dropMemoisedDb();
  removeTree(home);
});

const DAY_MS = 24 * 60 * 60 * 1000;
const INSIDE_RULE = 'aws-key';
const OUTSIDE_RULE = 'stale-key';

function seed(
  rows: {
    ruleId: string;
    severity: Severity;
    daysAgo: number;
    repo: string;
    category: DetectionCategory;
    /** `code_change` makes the finding at-rest, which is what `open` means. */
    kind?: IngestEvent['kind'];
    findingKey?: string;
  }[],
): void {
  const db = openLocalDatabase(dir);
  rows.forEach((row, i) => {
    const id = randomUUID();
    const event: IngestEvent = {
      id,
      sourceTool: 'claude-code',
      kind: row.kind ?? 'prompt',
      occurredAt: new Date(Date.now() - row.daysAgo * DAY_MS + i * 1000).toISOString(),
      contentHash: randomUUID(),
      content: 'x',
      metadata: { repo: row.repo, filePath: 'src/db.ts' },
    };
    const finding: DetectedFinding = {
      id: randomUUID(),
      eventId: id,
      ruleId: row.ruleId,
      category: row.category,
      severity: row.severity,
      span: { start: 0, end: 1 },
      maskedMatch: `masked-${String(i)}`,
      actionTaken: 'block',
      confidence: 0.9,
      ...(row.findingKey ? { findingKey: row.findingKey } : {}),
    };
    db.recordCapture(event, [finding]);
  });
  db.close();
  dropMemoisedDb();
}

// The fixture straddles the default 7d window: one finding inside it, one forty
// days back. With every row recent, a link carrying the range and one omitting it
// would open the SAME list, and every assertion below would hold whichever the
// page built.
//
// The two sit in different CATEGORIES on purpose. The recommendations card buckets
// by category, so same-category rows would collapse into one bucket whichever
// window was read — leaving the card's own window unfalsifiable, which is exactly
// how an earlier version of this fixture passed while the page read a window it did
// not link to.
/**
 * Two OPEN at-rest findings, in different categories.
 *
 * The recommendations card is scoped by status, not by the range selector, so its
 * fixture has to be `code_change` — a prompt finding derives as `handled` and would
 * make every assertion below read zero.
 */
function seedOpenFixture(): void {
  seed([
    {
      ruleId: INSIDE_RULE,
      severity: 'critical',
      daysAgo: 1,
      repo: 'acme/api',
      category: 'secret',
      kind: 'code_change',
      findingKey: 'open-1',
    },
    {
      // 400 days old and still open — the row a window would have hidden.
      ruleId: OUTSIDE_RULE,
      severity: 'high',
      daysAgo: 400,
      repo: 'acme/legacy',
      category: 'pii',
      kind: 'code_change',
      findingKey: 'open-2',
    },
  ]);
}

function seedStraddlingFixture(): void {
  seed([
    { ruleId: INSIDE_RULE, severity: 'critical', daysAgo: 1, repo: 'acme/api', category: 'secret' },
    { ruleId: OUTSIDE_RULE, severity: 'high', daysAgo: 40, repo: 'acme/legacy', category: 'pii' },
  ]);
}

/** Every element in the returned tree, walking props as well as children. */
function flatten(node: unknown, into: ReactElement[] = []): ReactElement[] {
  if (Array.isArray(node)) {
    for (const child of node) flatten(child, into);
    return into;
  }
  if (node === null || typeof node !== 'object') return into;
  const props: unknown = (node as { props?: unknown }).props;
  if ('type' in node) into.push(node as ReactElement);
  if (props === null || typeof props !== 'object') return into;
  for (const value of Object.values(props as Record<string, unknown>)) flatten(value, into);
  return into;
}

/**
 * The props the page handed the view whose function is named `name`.
 *
 * Matched by display name rather than by identity so the walk does not have to
 * import all five views, and asserted to exist: a page that stopped rendering one
 * would otherwise read as `undefined` and every assertion below would report the
 * wrong reason for going red.
 */
async function propsOf(
  name: string,
  params: { range?: string } = {},
): Promise<Record<string, unknown>> {
  const element = await SecurityPage({ searchParams: Promise.resolve(params) });
  const match = flatten(element).find(
    (el) => typeof el.type === 'function' && (el.type as { name?: string }).name === name,
  );
  if (!match) throw new Error(`${name} is not rendered by the security page`);
  return match.props as Record<string, unknown>;
}

describe('the security route carries each widget its own window', () => {
  it('is a fixture the two windows disagree on', async () => {
    // The control for the range assertions below. If both findings ever fall inside
    // the default window, a range-carrying link and an all-time one open the same
    // list and those assertions stop discriminating.
    seedStraddlingFixture();
    const db = openLocalDatabase(dir);
    try {
      expect((await db.security.topSources('7d')).items.length).toBe(1);
      expect((await db.security.topSources('3m')).items.length).toBe(2);
      // The severity summary is whole-store, so it sees both.
      expect((await db.security.severitySummary()).total).toBe(2);
    } finally {
      db.close();
      dropMemoisedDb();
    }
  });

  it('recommends an old unfixed finding that every window would have hidden', async () => {
    // The control for the status scope. `seedOpenFixture` holds one finding 400
    // days old; if the card were windowed at all, this row would vanish — which is
    // the failure the scope change exists to prevent.
    seedOpenFixture();
    const items = (await propsOf('RecommendedActionsCard')).items as {
      subjects: { id: string }[];
    }[];
    expect(items.map((i) => i.subjects[0]?.id).sort()).toEqual([INSIDE_RULE, OUTSIDE_RULE].sort());
  });

  it('recommends nothing once every finding is resolved', async () => {
    // The other half of the control: the card is empty because nothing is
    // outstanding, not because nothing is recent.
    seedOpenFixture();
    const db = openLocalDatabase(dir);
    for (const key of ['open-1', 'open-2']) {
      db.resolutions.insertResolution({
        findingKey: key,
        status: 'resolved',
        method: 'fixed-at-source',
        resolvedAt: Date.now(),
        evidence: '',
      });
    }
    db.close();
    dropMemoisedDb();
    expect((await propsOf('RecommendedActionsCard')).items).toEqual([]);
  });

  it('gives the severity card links that carry NO range', async () => {
    seedStraddlingFixture();
    const hrefs = (await propsOf('SeverityCardView')).severityHrefs as Record<string, string>;
    expect(hrefs.critical).toBe('/findings?severity=critical&view=flat');
    for (const href of Object.values(hrefs)) expect(href).not.toContain('range=');
  });

  it('gives the enforcement card links that carry the selected range', async () => {
    seedStraddlingFixture();
    const hrefs = (await propsOf('EnforcementCardView')).actionHrefs as Record<string, string>;
    expect(hrefs.blocked).toBe('/findings?action=blocked&view=flat&range=7d');
  });

  it('follows the range selector rather than hardcoding the default', async () => {
    seedStraddlingFixture();
    const hrefs = (await propsOf('EnforcementCardView', { range: '3m' })).actionHrefs as Record<
      string,
      string
    >;
    expect(hrefs.blocked).toBe('/findings?action=blocked&view=flat&range=3m');
  });

  it('links each repo source, and only within the window', async () => {
    seedStraddlingFixture();
    const hrefs = (await propsOf('TopSourcesCardView')).sourceHrefs as Record<string, string>;
    // The 40-day-old repo is outside the default window, so it is not a source at
    // all — the map covers exactly what the widget lists.
    expect(Object.values(hrefs)).toEqual(['/findings?view=flat&range=7d&repo=acme%2Fapi']);
  });

  it('links each recommendation to its own rule, scoped to open', async () => {
    seedOpenFixture();
    const items = (await propsOf('RecommendedActionsCard')).items as {
      action: { href: string };
      subjects: { id: string }[];
    }[];
    const byRule = new Map(items.map((i) => [i.subjects[0]?.id, i.action.href]));
    expect(byRule.get(INSIDE_RULE)).toBe(`/findings?type=${INSIDE_RULE}&status=open&view=flat`);
    expect(byRule.get(OUTSIDE_RULE)).toBe(`/findings?type=${OUTSIDE_RULE}&status=open&view=flat`);
  });

  it('gives the recommendations card a working "View all"', async () => {
    seedStraddlingFixture();
    expect((await propsOf('RecommendedActionsCard')).viewAllHref).toBe(
      '/findings?status=open&view=flat',
    );
  });

  it('leaves scan coverage unlinked', async () => {
    // Its number is a curated capability constant rather than a measurement, so no
    // findings query could corroborate it and a supported provider with no findings
    // would land on an empty list.
    //
    // Asserted over the prop NAMES rather than one invented name: `providerHrefs`
    // exists nowhere, so `not.toHaveProperty('providerHrefs')` could never fail, and
    // an hrefs prop added under any other spelling would pass it.
    seedStraddlingFixture();
    const props = await propsOf('ScanCoverageCardView');
    expect(Object.keys(props).filter((k) => /href/i.test(k))).toEqual([]);
    // The control: its siblings DO carry one, so the filter is looking for something
    // that really appears on this page.
    expect(Object.keys(await propsOf('SeverityCardView')).filter((k) => /href/i.test(k))).toEqual([
      'severityHrefs',
    ]);
  });

  it('renders the widgets inside the client-navigation wrapper', async () => {
    // The props walk below descends through wrappers, so without this the whole
    // wrapper could be removed from the route with every case here still green —
    // and its own suite mounts the component itself, so it would not notice either.
    seedStraddlingFixture();
    const element = await SecurityPage({ searchParams: Promise.resolve({}) });
    const wrapper = flatten(element).find((el) => el.type === WidgetNavigation);
    expect(wrapper, 'the security page does not render WidgetNavigation').toBeDefined();
    // …and the widgets are INSIDE it, not siblings of it: a wrapper around nothing
    // intercepts nothing.
    const inside = flatten((wrapper as ReactElement<{ children?: unknown }>).props.children);
    const names = inside.map((el) => (typeof el.type === 'function' ? el.type.name : ''));
    expect(names).toContain('SeverityCardView');
    expect(names).toContain('EnforcementCardView');
  });

  it('links only the enforcement kinds that have findings', async () => {
    // `enforcementActions` zero-fills all three kinds and the card renders every
    // tile whenever the total is non-zero, so an ungated map sends "Redacted 0" to
    // an empty list.
    seedStraddlingFixture();
    const hrefs = (await propsOf('EnforcementCardView')).actionHrefs as Record<string, string>;
    // The fixture's two findings are both `actionTaken: 'block'`.
    expect(Object.keys(hrefs)).toEqual(['blocked']);
  });

  it('hands the builder a per-rule destination, scoped to open findings', async () => {
    // The page supplies `hrefForRule`, so every row resolves to that rule's own
    // `?type=` link rather than a generic list — and to `status=open`, because the
    // card counts open findings and the two have to describe one set.
    //
    // The declining branch is not reachable from here: every recommendation the
    // store can produce names a rule. It is covered where it renders, in
    // dashboard-ui's `RecommendedActionsCardView` suite.
    seedOpenFixture();
    const items = (await propsOf('RecommendedActionsCard')).items as {
      action: { href?: string };
      subjects: { id: string }[];
    }[];
    expect(items.length).toBeGreaterThan(0);
    for (const item of items) {
      expect(item.subjects[0]?.id).toBeTruthy();
      expect(item.action.href).toContain('type=');
      expect(item.action.href).toContain('status=open');
      // No range: the card is a to-do list, so an old unfixed finding must survive.
      expect(item.action.href).not.toContain('range=');
    }
  });

  it('links only the severities that have findings', async () => {
    // `severitySummary` zero-fills all four, so an unconditional map would send
    // "Medium 0" to a list holding nothing.
    seedStraddlingFixture();
    const hrefs = (await propsOf('SeverityCardView')).severityHrefs as Record<string, string>;
    // The fixture holds one critical and one high, and no medium or low at all.
    expect(Object.keys(hrefs).sort()).toEqual(['critical', 'high']);
  });
});
