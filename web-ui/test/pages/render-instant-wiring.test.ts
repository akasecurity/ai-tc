import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir,
  type LocalDatabase,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { emptyStore } from '../helpers/store-templates.ts';
import { tempHomes } from '../helpers/temp-home.ts';
import { setRequestHeaders } from '../setup/next-headers-stub.ts';

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
// tree the page returns and collects EVERY `renderedAt` it finds, so a route
// with more than one consumer would be caught if one of them silently got a
// different value. None of the six routes below is actually that shape today
// — each has exactly one `renderedAt`-bearing element (`findings` has three,
// but they are mutually exclusive branches) — so this generalizes correctly
// without currently exercising the multi-consumer case; do not read the
// walker's existence as proof that case is covered.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

const newHome = tempHomes('aka-web-instant-');

let home: string;
let dir: string;

function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = newHome();
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
});

/**
 * Every value of the prop named `key` anywhere in the tree, in document order.
 * Walks props as well as children, since a route may hand a value to a
 * component it passes as a prop rather than nests.
 */
function collectProp(node: unknown, key: string, into: unknown[] = []): unknown[] {
  if (Array.isArray(node)) {
    for (const child of node) collectProp(child, key, into);
    return into;
  }
  if (node === null || typeof node !== 'object') return into;

  // Not every object reached here is an element — a props value may be a plain
  // object, a date, anything — so `props` is read as unknown and narrowed,
  // rather than cast to an element shape the node may not have.
  const props: unknown = (node as { props?: unknown }).props;
  if (props === null || typeof props !== 'object') return into;

  const bag = props as Record<string, unknown>;
  if (key in bag) into.push(bag[key]);
  for (const value of Object.values(bag)) collectProp(value, key, into);
  return into;
}

/** Every `renderedAt` prop anywhere in the tree, in document order. */
function collectRenderedAt(node: unknown): number[] {
  return collectProp(node, 'renderedAt').filter((v): v is number => typeof v === 'number');
}

// The seven routes, each called the way Next calls it. An empty store is
// enough for six of them: every read returns nothing and the page still renders
// its tree, which is where the prop lives.
//
// `prepare` exists for the seventh. The settings route renders its sync panel
// only on an ATTACHED machine and renders nothing at all otherwise, which is
// the honest shape but leaves this file's positive control — a non-empty list
// of instants — vacuously unsatisfiable on a fresh temp home. So that route
// says what state it has to be in first.
const ROUTES = [
  {
    name: 'activity',
    prepare: () => undefined,
    load: () => import('../../app/(app)/activity/page.tsx'),
  },
  {
    name: 'data-shares',
    prepare: () => undefined,
    load: () => import('../../app/(app)/data-shares/page.tsx'),
  },
  {
    name: 'findings',
    prepare: () => undefined,
    load: () => import('../../app/(app)/findings/page.tsx'),
  },
  {
    name: 'security',
    prepare: () => undefined,
    load: () => import('../../app/(app)/security/page.tsx'),
  },
  {
    name: 'inventory',
    prepare: () => undefined,
    load: () => import('../../app/(app)/inventory/page.tsx'),
  },
  {
    // NOT a multi-consumer route, despite this file's earlier claim: the page
    // also renders `<VaultLookupClient />`, but that component takes zero
    // props — only `VaultDashboardClient` gets `renderedAt`. Single consumer,
    // same shape as the other five; added for its zero-argument page function
    // (below), which none of the others have.
    name: 'vault',
    prepare: () => undefined,
    load: () => import('../../app/(app)/vault/page.tsx'),
  },
  {
    // The one route whose panel is conditional. Its instant reaches the sync
    // panel, which a standalone machine does not render — so the prop's whole
    // wiring is invisible here unless the machine is attached, keyed and
    // sharing, which is what `prepare` arranges.
    name: 'settings',
    prepare: () => {
      const endpoint = 'https://plane.example.com';
      const at = '2026-08-01T00:00:00.000Z';
      const base = join(home, '.aka');
      applyOnboarding(
        {
          runMode: 'attached',
          controlPlane: { endpoint, attachedAt: at },
          historySyncConsent: {
            acknowledgedAt: at,
            payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
            endpoint,
          },
        },
        base,
      );
      writeControlPlaneCredential(settingsDir(base), {
        specVersion: 1,
        endpoint,
        apiKey: 'k',
      });
    },
    load: () => import('../../app/(app)/settings/page.tsx'),
  },
] as const;

// `vault/page.tsx` and `settings/page.tsx` are synchronous and take no
// arguments; the other five take `searchParams` as a promise, the way Next
// hands it.
// `await`ing a non-promise return still resolves, so only the call shape
// differs.
interface Route {
  name: string;
  prepare: () => void;
  load: () => Promise<{ default: unknown }>;
}

async function renderElement(route: Route): Promise<unknown> {
  route.prepare();
  const mod = await route.load();
  return route.name === 'vault' || route.name === 'settings'
    ? await (mod.default as () => unknown)()
    : await (mod.default as (props: { searchParams: Promise<object> }) => unknown)({
        searchParams: Promise.resolve({}),
      });
}

async function render(route: Route): Promise<number[]> {
  return collectRenderedAt(await renderElement(route));
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

// ─── The locale, the instant's sibling ───────────────────────────────────────
//
// Each route also resolves ONE locale per request, from the request's
// Accept-Language header, and hands it to every consumer that formats a count
// or a time (app/lib/render-locale.ts). The prop is required, so a MISSING one
// is a compile error; what compiles is a route that passes a literal, or that
// resolves the locale without reading the request — every reader then gets
// en-US whatever their browser says. So the header here names de-DE BELOW a
// lower-weighted first entry: a route that ignored the header, or read only its
// first tag, would hand down something else.

/** Every `locale` prop anywhere in the tree. */
function collectLocale(node: unknown): string[] {
  return collectProp(node, 'locale').filter((v): v is string => typeof v === 'string');
}

const LOCALE_ROUTES: readonly Route[] = [
  ...ROUTES.filter((route) => route.name !== 'data-shares' && route.name !== 'vault'),
  {
    name: 'policies',
    prepare: () => undefined,
    load: () => import('../../app/(app)/policies/page.tsx'),
  },
];

describe.each(LOCALE_ROUTES)('the $name route resolves its locale per request', (route) => {
  afterEach(() => {
    setRequestHeaders({});
  });

  it('hands every consumer the locale the request asked for', async () => {
    setRequestHeaders({ 'accept-language': 'en;q=0.4, de-DE' });
    const found = collectLocale(await renderElement(route));
    // The positive control, as above: an empty list satisfies `every`.
    expect(found.length).toBeGreaterThan(0);
    expect(found.every((locale) => locale === 'de-DE')).toBe(true);
  });

  it('falls back to en-US for a request that names no locale', async () => {
    const found = collectLocale(await renderElement(route));
    expect(found.length).toBeGreaterThan(0);
    expect(found.every((locale) => locale === 'en-US')).toBe(true);
  });
});

// A Server Component formats some values ITSELF rather than handing a consumer
// the locale — the summary strips' counts and the Security chart's date labels
// — so the prop walk above cannot see whether those read the request. ar-EG is
// the header here because it formats even an EMPTY store's values differently:
// its digits are Arabic-Indic (`0` is `٠`) and its month names Arabic, so a
// value formatted in any Latin-digit locale is caught without seeding a row.
describe('a Server Component formats its own values in the request’s locale', () => {
  const ARABIC_DIGIT = /[\u0660-\u0669]/;
  const LATIN = /[0-9A-Za-z]/;

  beforeEach(() => {
    setRequestHeaders({ 'accept-language': 'ar-EG' });
  });
  afterEach(() => {
    setRequestHeaders({});
  });

  /** The `value` of every summary-strip cell in the tree. */
  function stripValues(node: unknown): string[] {
    return collectProp(node, 'items')
      .flat()
      .map((item) => (item as { value?: unknown }).value)
      .filter((v): v is string => typeof v === 'string');
  }

  it.each([
    { name: 'activity', load: () => import('../../app/(app)/activity/page.tsx') },
    { name: 'detections', load: () => import('../../app/(app)/detections/page.tsx') },
  ])('the $name summary strip', async ({ name, load }) => {
    const values = stripValues(await renderElement({ name, prepare: () => undefined, load }));
    expect(values.length).toBeGreaterThan(0);
    for (const value of values) {
      expect(value).toMatch(ARABIC_DIGIT);
      expect(value).not.toMatch(LATIN);
    }
  });

  it('the security chart’s date labels', async () => {
    const security = ROUTES.find((route) => route.name === 'security');
    if (security === undefined) throw new Error('no security route');
    const labels = collectProp(await renderElement(security), 'points')
      .flat()
      .map((point) => (point as { label?: unknown }).label)
      .filter((v): v is string => typeof v === 'string');
    // Zero-filled buckets exist on an empty store, one per day of the range.
    expect(labels.length).toBeGreaterThan(0);
    for (const label of labels) {
      expect(label).toMatch(ARABIC_DIGIT);
      expect(label).not.toMatch(LATIN);
    }
  });
});
