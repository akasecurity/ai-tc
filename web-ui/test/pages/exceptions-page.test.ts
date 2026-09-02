import { mkdtempSync, rmSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { BLOCKED_WINDOW_MS, isBlockedRowApprovable } from '@akasecurity/dashboard-ui';
import { maskMatch } from '@akasecurity/detections';
import {
  BLOCKED_DETECTIONS_RETENTION_MS,
  dataDir,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  type LocalDatabase,
  openLocalDatabase,
  readFingerprintKey,
} from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BlockedDetectionInput } from '@akasecurity/schema';
import type { ComponentProps, ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { ExceptionDetailClient } from '../../app/(app)/exceptions/[id]/ExceptionDetailClient.tsx';
import ExceptionDetailPage from '../../app/(app)/exceptions/[id]/page.tsx';
import { ExceptionsClient } from '../../app/(app)/exceptions/ExceptionsClient.tsx';
import ExceptionsPage from '../../app/(app)/exceptions/page.tsx';
import { withBundledPacks } from '../helpers/store-templates.ts';

// The exceptions route issues TWO reads of the same blocked-detections ledger,
// over two different windows, and hands both to the client — and which read
// feeds which consumer is the whole point:
//
//   the strip   — the lookback chip the user picked, 30 minutes by default
//   the dialog  — the full retention window, because the rotate confirmation
//                 has to name what a one-way action costs, and rotation
//                 invalidates every row in the ledger, not just the visible ones
//
// Every piece of that is covered somewhere else. The predicate is pinned in
// dashboard-ui's meta suite, the copy alongside it, and the agreement between
// the retention constant and the hours the copy names in the actions suite.
// What none of them can see is the WIRING, because a count is just a number:
// feed the dialog the 30-minute read and it understates a destructive action by
// however many rows fell outside the chip — silently, with the type, the lint
// and every existing assertion still green.
//
// So this suite drives the page itself. It is an async Server Component, which
// is a plain async function returning an element, so calling it and reading the
// props it hands down needs no renderer and no DOM. The store, the fingerprint
// key file and the ledger writes are all real (the repository's house style);
// only `homedir()` is redirected, since the page resolves ~/.aka from it and
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
function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

// A value from the bundled rule's own `examples`, so no secret-shaped literal
// lives in this file and the fixture stays in step with the rule definition.
const RULE_ID = 'secrets/aws-access-key';
const example = bundledDetections()
  .flatMap((p) => p.rules)
  .find((r) => r.id === RULE_ID)?.examples?.[0];
if (example === undefined) {
  throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
}
const VALUE: string = example;

// One ledger row shaped as the hook writes it: the keyed fingerprint and masked
// preview of the detected value, never the value.
function ledgerEntry(overrides: Partial<BlockedDetectionInput> = {}): BlockedDetectionInput {
  const key = loadOrCreateFingerprintKey(dir);
  return {
    reference: 'blk-0001',
    ruleId: RULE_ID,
    category: 'secret',
    valueFingerprint: fingerprintValue(key, VALUE),
    keyVersion: key.version,
    maskedValue: maskMatch(VALUE),
    sessionId: null,
    repo: null,
    ...overrides,
  };
}

// Write a ledger row through the real repository, optionally back-dated.
// `blocked_at` is stamped inside the write from `Date.now()` and exceptions.ts
// takes no injectable clock, so moving the clock across that one call is the
// only seam — which keeps the row shape in step with `recordBlocked` instead of
// hand-rolling its SQL. The handle opens BEFORE the clock moves so migrations
// and default seeding still stamp real times.
async function seedBlocked(entry: BlockedDetectionInput, agedMs = 0): Promise<void> {
  const at = Date.now() - agedMs;
  const store = openLocalDatabase(dir);
  const clock = vi.spyOn(Date, 'now').mockReturnValue(at);
  try {
    await store.exceptions.recordBlocked(entry);
  } finally {
    clock.mockRestore();
    store.close();
  }
}

type ClientProps = ComponentProps<typeof ExceptionsClient>;

// Render the route the way Next calls it — `searchParams` arrives as a promise —
// and return the props it hands the client component.
//
// `element.type` is asserted rather than assumed: if the page ever returns a
// wrapper instead, every prop below reads `undefined`, and a suite that only
// checked the numbers would report the wrong reason for going red.
async function renderPage(params: { all?: string; window?: string } = {}): Promise<ClientProps> {
  const element = (await ExceptionsPage({
    searchParams: Promise.resolve(params),
  })) as ReactElement<ClientProps>;
  expect(element.type).toBe(ExceptionsClient);
  return element.props;
}

// Two rows outside the default chip but inside retention, one row inside both.
// The gap between the two windows IS the property under test, so the fixture
// has to straddle it: with every row recent, both reads return the same list
// and the assertions below hold whichever one the page passes down.
const AGED_MS = 12 * 60 * 60 * 1000;
const RECENT = 'blk-recent';
const AGED = ['blk-aged-1', 'blk-aged-2'];

async function seedStraddlingFixture(): Promise<void> {
  await seedBlocked({ ...ledgerEntry(), reference: RECENT });
  for (const reference of AGED) {
    await seedBlocked({ ...ledgerEntry(), reference }, AGED_MS);
  }
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-exp-'));
  osHome.dir = home;
  dir = dataDir();
  // The schema and the installed ruleset arrive as a file copy: both are
  // identical every test, and migrating plus re-reading the bundled set per
  // test is what put this suite's `beforeEach` over the Windows hook ceiling.
  withBundledPacks.seed(dir);
  resetSingleton();
});

afterEach(() => {
  resetSingleton();
  removeTree(home);
});

describe('the exceptions route wires each ledger read to the consumer that needs it', () => {
  it('is a fixture the two windows disagree on', async () => {
    // The control for everything below. If the aged rows ever stop falling
    // outside the default chip — the chip widens, the retention window
    // narrows, the ageing seam stops working — the assertions that follow go
    // on passing while proving nothing, because both reads would return the
    // same three rows. Pin the disagreement itself so that failure is loud.
    expect(AGED_MS).toBeGreaterThan(BLOCKED_WINDOW_MS['30m']); // the default chip
    expect(AGED_MS).toBeGreaterThan(BLOCKED_WINDOW_MS['1h']); // the other chip driven below
    expect(AGED_MS).toBeLessThan(BLOCKED_DETECTIONS_RETENTION_MS);

    await seedStraddlingFixture();
    const props = await renderPage();
    expect(props.blocked.map((b) => b.reference)).toEqual([RECENT]);
  });

  it('counts the rotate cost over the whole retention window, not the selected chip', async () => {
    await seedStraddlingFixture();

    const props = await renderPage();

    // Three rows are still approvable and rotation invalidates all three. The
    // strip shows one of them. Taking the count from the strip's read would
    // put "1" in front of a user about to make every one of them unapprovable.
    expect(props.approvableBlocked).toBe(1 + AGED.length);
    expect(props.blocked).toHaveLength(1);
  });

  it('keeps the strip on the selected chip while the count stays whole', async () => {
    await seedStraddlingFixture();

    // The mirror of the case above: widening the STRIP's read to retention
    // would make the two agree again — and pass the assertion above — while
    // silently overriding the window the user chose.
    const props = await renderPage({ window: '1h' });

    expect(props.blockedWindow).toBe('1h');
    expect(props.blocked.map((b) => b.reference)).toEqual([RECENT]);
    expect(props.approvableBlocked).toBe(1 + AGED.length);
  });

  it('agrees with the strip only when the chip spans the retention window', async () => {
    await seedStraddlingFixture();

    // The widest chip is exactly the retention window, so here the two reads
    // legitimately coincide. Recorded so a future red is never "fixed" by
    // defaulting the chip wider: this is the one setting under which the
    // property this suite guards is invisible.
    expect(BLOCKED_WINDOW_MS['24h']).toBe(BLOCKED_DETECTIONS_RETENTION_MS);

    const props = await renderPage({ window: '24h' });

    expect(props.blocked).toHaveLength(1 + AGED.length);
    expect(props.approvableBlocked).toBe(1 + AGED.length);
  });

  it('counts only the rows a rotation actually takes something from', async () => {
    // A row recorded under a superseded key is already unapprovable, so
    // counting it would overstate the loss — the count is a filter over the
    // retention read, not its length. Both halves of the derivation are
    // therefore load-bearing, and this pins the half the window cases cannot
    // see: they would all pass with the predicate dropped.
    await seedStraddlingFixture();
    const current = loadOrCreateFingerprintKey(dir);
    await seedBlocked(
      { ...ledgerEntry(), reference: 'blk-old-key', keyVersion: current.version - 1 },
      AGED_MS,
    );

    const props = await renderPage();

    expect(props.approvableBlocked).toBe(1 + AGED.length);
    // The row is retained and listed under the widest chip — invalidated, not
    // deleted — so its absence from the count is the predicate at work rather
    // than the row having aged out of the read.
    const widest = await renderPage({ window: '24h' });
    expect(
      widest.blocked
        .filter((b) => !isBlockedRowApprovable(b, widest.keyState))
        .map((b) => b.reference),
    ).toEqual(['blk-old-key']);
  });

  it('reports nothing approvable when the fingerprint key file is gone', async () => {
    // No key means no row can be matched, so the note must claim no cost at
    // all rather than a count the reader cannot act on. The page resolves the
    // key defensively; this pins that an absent key reaches the count as zero
    // instead of taking the route down.
    await seedStraddlingFixture();
    expect(readFingerprintKey(dir)).not.toBeNull();
    rmSync(join(dir, 'exception.key'), { force: true });
    // The removal is asserted through the reader rather than trusted: a
    // renamed key file would otherwise leave this case deleting nothing and
    // asserting a state the page never reaches.
    expect(readFingerprintKey(dir)).toBeNull();

    const props = await renderPage();

    expect(props.keyState.status).toBe('absent');
    expect(props.approvableBlocked).toBe(0);
    // Still listed: the ledger is a record of what was blocked either way.
    expect(props.blocked).toHaveLength(1);
  });
});

// The other thing this route hands down that nothing else can see: the instant
// every relative label and every lifecycle badge on the page is measured
// against.
//
// A MISSING instant is a compile error — `renderedAt` is required on the client
// and on each view under it — so what these cover is the failure that still
// typechecks: an instant captured once and reused. Hoisting `renderInstant()`
// to module scope, or replacing it with a `const` beside the imports, keeps the
// whole route green while a long-lived dashboard process renders every age
// against the instant it booted.
describe('the exceptions route captures its render instant per request', () => {
  // Only Date is faked: this suite does real file and store I/O, and faking the
  // timer APIs as well would stall it.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('hands the client the clock as it stood for THIS render', () => {
    const at = Date.parse('2026-08-01T00:30:00.000Z');
    vi.setSystemTime(at);
    return renderPage().then((props) => {
      expect(props.renderedAt).toBe(at);
    });
  });

  it('captures a new instant on the next request, rather than reusing one', async () => {
    vi.setSystemTime(Date.parse('2026-08-01T00:30:00.000Z'));
    const first = await renderPage();
    vi.setSystemTime(Date.parse('2026-08-01T02:30:00.000Z'));
    const second = await renderPage();

    expect(second.renderedAt - first.renderedAt).toBe(2 * 60 * 60 * 1000);
  });
});

// The same property for the DETAIL route, which no other suite reaches.
//
// exception-detail-client.test.ts renders ExceptionDetailClient directly with an
// instant of its own, so it pins the client-to-view half and structurally cannot
// see the half above it — the `renderedAt={renderInstant()}` on [id]/page.tsx.
// Replace that call with a literal and every assertion in that suite stays green
// while the detail route serves one fixed instant for the life of the process.
//
// It matters more here than on the list route: `exceptionState` gates the revoke
// form, so a stuck instant does not merely age a label, it decides whether a
// whole subtree renders.
describe('the exception detail route captures its render instant per request', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  async function seedGrant(): Promise<string> {
    const store = openLocalDatabase(dir);
    try {
      // A synthetic fingerprint: this route reads the grant by id prefix and
      // never matches it against a value, so minting a real one would only
      // couple the test to the key file for nothing.
      const created = await store.exceptions.create({
        ruleId: RULE_ID,
        category: 'secret',
        valueFingerprint: 'a'.repeat(64),
        keyVersion: 1,
        maskedValue: maskMatch(VALUE),
        scope: 'permanent',
        expiresAt: null,
        maxUses: null,
        justification: 'test fixture',
        conditions: null,
        createdBy: 'tester',
        createdVia: 'web-add',
      });
      return created.id;
    } finally {
      store.close();
    }
  }

  // The page wraps the client in layout markup, so the props are reached by
  // walking to the client element rather than read off the wrapper — which would
  // hand back `undefined` for every one of them and fail for the wrong reason.
  // `toBeDefined` is what separates those two outcomes.
  async function renderDetail(
    idPrefix: string,
  ): Promise<ComponentProps<typeof ExceptionDetailClient>> {
    const element = (await ExceptionDetailPage({
      params: Promise.resolve({ id: idPrefix }),
    })) as ReactElement<{ children?: unknown }>;
    const found = flatten(element.props.children).find(
      (child) => child.type === ExceptionDetailClient,
    );
    expect(found).toBeDefined();
    return (found as ReactElement<ComponentProps<typeof ExceptionDetailClient>>).props;
  }

  function flatten(node: unknown): ReactElement[] {
    if (Array.isArray(node)) return node.flatMap(flatten);
    if (node !== null && typeof node === 'object' && 'type' in node) return [node as ReactElement];
    return [];
  }

  it('hands the client the clock as it stood for THIS render', async () => {
    const id = await seedGrant();
    const at = Date.parse('2026-08-01T00:30:00.000Z');
    vi.setSystemTime(at);

    const props = await renderDetail(id.slice(0, 8));

    expect(props.renderedAt).toBe(at);
  });

  it('captures a new instant on the next request, rather than reusing one', async () => {
    const id = await seedGrant();
    vi.setSystemTime(Date.parse('2026-08-01T00:30:00.000Z'));
    const first = await renderDetail(id.slice(0, 8));
    vi.setSystemTime(Date.parse('2026-08-01T02:30:00.000Z'));
    const second = await renderDetail(id.slice(0, 8));

    expect(second.renderedAt - first.renderedAt).toBe(2 * 60 * 60 * 1000);
  });
});
