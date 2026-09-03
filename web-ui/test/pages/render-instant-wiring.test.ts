import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir, type LocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { emptyStore } from '../helpers/store-templates.ts';

// Every route that renders a relative label captures ONE instant per request
// and hands it to each consumer below it. `exceptions-page.test.ts` pins that
// for its own two routes; six others had no page test at all, so the line that
// does it — `const renderedAt = renderInstant()` — was covered by nothing.
//
// What makes that worth a test rather than a glance is that it still typechecks
// when it goes wrong. `renderedAt` is required, so a MISSING one is a compile
// error; what compiles is an instant captured once and reused — hoisting the
// call to module scope, or replacing it with a `const` beside the imports —
// which leaves a long-lived dashboard process rendering every age against the
// instant it booted.
//
// Rather than knowing where each route puts the prop, this walks the element
// tree the page returns and collects EVERY `renderedAt` it finds. That is the
// stronger assertion: it says every consumer on the route got this request's
// instant, not merely that one did.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

let home: string;
let dir: string;

function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-instant-'));
  osHome.dir = home;
  dir = dataDir();
  // None of the six routes below reads `installed_packs` (they read
  // activity/data-shares/findings/security/inventory/vault store surfaces
  // only), so the schema alone is enough — no need for the full bundled
  // ruleset a route that scans against detections would require.
  emptyStore.seed(dir);
  resetSingleton();
  vi.useFakeTimers({ toFake: ['Date'] });
});

afterEach(() => {
  vi.useRealTimers();
  resetSingleton();
  removeTree(home);
});

/**
 * Every `renderedAt` prop anywhere in the tree, in document order. Walks props
 * as well as children, since a route may hand the instant to a component it
 * passes as a prop rather than nests.
 */
function collectRenderedAt(node: unknown, into: number[] = []): number[] {
  if (Array.isArray(node)) {
    for (const child of node) collectRenderedAt(child, into);
    return into;
  }
  if (node === null || typeof node !== 'object') return into;

  // Not every object reached here is an element — a props value may be a plain
  // object, a date, anything — so `props` is read as unknown and narrowed,
  // rather than cast to an element shape the node may not have.
  const props: unknown = (node as { props?: unknown }).props;
  if (props === null || typeof props !== 'object') return into;

  const bag = props as Record<string, unknown>;
  if (typeof bag.renderedAt === 'number') into.push(bag.renderedAt);
  for (const value of Object.values(bag)) collectRenderedAt(value, into);
  return into;
}

// The six routes, each called the way Next calls it. An empty store is enough:
// every read returns nothing and the page still renders its tree, which is
// where the prop lives.
const ROUTES = [
  {
    name: 'activity',
    load: () => import('../../app/(app)/activity/page.tsx'),
  },
  {
    name: 'data-shares',
    load: () => import('../../app/(app)/data-shares/page.tsx'),
  },
  {
    name: 'findings',
    load: () => import('../../app/(app)/findings/page.tsx'),
  },
  {
    name: 'security',
    load: () => import('../../app/(app)/security/page.tsx'),
  },
  {
    name: 'inventory',
    load: () => import('../../app/(app)/inventory/page.tsx'),
  },
  {
    // The one route that hoists `renderInstant()` to a local and hands it to
    // more than one consumer (VaultLookupClient, VaultDashboardClient) — the
    // shape where a second consumer can quietly be given a different value.
    // `collectRenderedAt` already walks props as well as children, so nothing
    // else needed to change to catch that here.
    name: 'vault',
    load: () => import('../../app/(app)/vault/page.tsx'),
  },
] as const;

// `vault/page.tsx`'s component is synchronous and takes no arguments; the
// other five take `searchParams` as a promise, the way Next hands it.
// `await`ing a non-promise return still resolves, so only the call shape
// differs.
async function render(route: (typeof ROUTES)[number]): Promise<number[]> {
  const mod = await route.load();
  const element =
    route.name === 'vault'
      ? await (mod.default as () => unknown)()
      : await (mod.default as (props: { searchParams: Promise<object> }) => unknown)({
          searchParams: Promise.resolve({}),
        });
  return collectRenderedAt(element);
}

describe.each(ROUTES)('the $name route captures its render instant per request', (route) => {
  it('hands every consumer the clock as it stood for THIS render', async () => {
    const at = Date.parse('2026-08-01T00:30:00.000Z');
    vi.setSystemTime(at);

    const found = await render(route);

    // The positive control. A route that stopped passing the prop — or one
    // whose tree shape moved past this walker — yields an empty list, and
    // `every` on an empty array is vacuously true.
    expect(found.length).toBeGreaterThan(0);
    expect(found.every((v) => v === at)).toBe(true);
  });

  it('captures a new instant on the next request, rather than reusing one', async () => {
    vi.setSystemTime(Date.parse('2026-08-01T00:30:00.000Z'));
    const first = await render(route);
    vi.setSystemTime(Date.parse('2026-08-01T02:30:00.000Z'));
    const second = await render(route);

    expect(first.length).toBeGreaterThan(0);
    expect(second.length).toBeGreaterThan(0);
    // NaN on an empty list rather than a non-null assertion, so a route that
    // stopped passing the prop fails the subtraction instead of being asserted
    // past it.
    const firstAt = first.at(0) ?? Number.NaN;
    const secondAt = second.at(0) ?? Number.NaN;
    expect(secondAt - firstAt).toBe(2 * 60 * 60 * 1000);
  });
});
