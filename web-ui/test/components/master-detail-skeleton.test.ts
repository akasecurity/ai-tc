import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

/**
 * A `loading.tsx` describes a layout it cannot see. `MasterDetailSkeleton` is
 * shared by four routes whose real clients differ in two ways that both show on
 * reveal — the list column's WIDTH, and whether the two columns exist at all
 * below `lg` — and nothing in either file can measure the other.
 *
 * Both halves have been wrong here. A skeleton one width for every route slid
 * the detail pane sideways on reveal; and the Policies client is one stacked
 * column until `lg` (`grid-cols-1 … lg:grid-cols-[320px_1fr]`) while its
 * skeleton painted a fixed-width list beside a detail pane at every width, so
 * under 1024px the reveal was a relayout rather than a slide.
 *
 * So the pairing is derived from the real sources rather than restated: change
 * a client's column width or its breakpoint gating and the route's skeleton
 * fails here, naming it.
 */

/** Repo-root relative: one route's real layout lives in `packages/`, not in `web-ui/`. */
const repo = (p: string) => fileURLToPath(new URL(`../../../${p}`, import.meta.url));
const app = (p: string) => repo(`web-ui/${p}`);

/** `--spacing` is 4px, so a `w-<n>` token is 4n. Same arithmetic as `h-12.5` = 50px. */
const SPACING_PX = 4;

/**
 * Where each route's REAL layout lives. `root` carries the breakpoint gating;
 * `width` carries the list column's width, which for a flex row sits on the list
 * Card and for Inventory is a different package entirely. A route is discovered
 * from the tree (below), so a fifth master/detail page has to be added here
 * deliberately rather than inheriting whatever the default happens to be.
 */
const REAL_LAYOUTS: Record<string, { root: string; width?: string }> = {
  activity: { root: 'web-ui/app/(app)/activity/ActivityClient.tsx' },
  detections: { root: 'web-ui/app/(app)/detections/DetectionsClient.tsx' },

  inventory: {
    root: 'web-ui/app/(app)/inventory/InventoryClient.tsx',
    width: 'packages/dashboard-ui/src/inventory/InventoryNav.tsx',
  },
  policies: { root: 'web-ui/app/(app)/policies/PoliciesClient.tsx' },
};

/** Every route whose `loading.tsx` reaches for the shared master/detail skeleton. */
function routesUsingSkeleton(): string[] {
  const appDir = app('app/(app)');
  return readdirSync(appDir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .filter((e) => {
      try {
        return readFileSync(`${appDir}/${e.name}/loading.tsx`, 'utf8').includes(
          'MasterDetailSkeleton',
        );
      } catch {
        return false;
      }
    })
    .map((e) => e.name)
    .sort();
}

/** The root element's class string — the one line carrying the shared transition. */
function rootClasses(source: string): string {
  const line = source.split('\n').find((l) => l.includes('transition-shadow duration-150'));
  expect(line, 'no root element found (the `transition-shadow duration-150` line)').toBeDefined();
  return line ?? '';
}

/** What `loading.tsx` claims: the width token, and whether it gates on `lg`. */
function skeletonClaim(source: string): { width: string; stacks: boolean } {
  const call = source.slice(source.indexOf('<MasterDetailSkeleton'));
  return {
    width: /listWidth="([^"]+)"/.exec(call)?.[1] ?? 'w-85',
    stacks: call.slice(0, call.indexOf('/>')).includes('stacksBelowLg'),
  };
}

describe('MasterDetailSkeleton describes the layout each route actually reveals', () => {
  const routes = routesUsingSkeleton();

  it('finds the master/detail routes, and each one is mapped to its real layout', () => {
    // A floor, not an exact set: the guard below is per route, so a new one must
    // arrive here rather than silently taking the default width.
    expect(routes.length).toBeGreaterThanOrEqual(4);
    expect(routes.filter((r) => !(r in REAL_LAYOUTS))).toEqual([]);
  });

  for (const route of routes) {
    const layout = REAL_LAYOUTS[route];
    // An unmapped route is reported by the mapping test above, by name. Without
    // this the describe body below throws at COLLECTION instead, which fails the
    // file with an ENOENT naming neither the route nor what is missing.
    if (!layout) continue;

    describe(route, () => {
      const claim = skeletonClaim(readFileSync(app(`app/(app)/${route}/loading.tsx`), 'utf8'));
      const real = rootClasses(readFileSync(repo(layout.root), 'utf8'));
      // Two side by side at every width, or one stacked column until `lg`.
      const realStacks = real.includes('grid-cols-1') && real.includes('lg:grid-cols-[');

      it('matches the client on whether the columns exist below lg', () => {
        expect(claim.stacks).toBe(realStacks);
      });

      it('spells the width at the breakpoint the column exists at', () => {
        // A stacked route's column has no width below `lg` — it stretches. The
        // prefix is what keeps the token from applying where there is no column,
        // and Tailwind only emits it because the call site spells it literally.
        expect(claim.width.startsWith('lg:')).toBe(realStacks);
      });

      it('reserves the real list column width', () => {
        const px = Number(/^(?:lg:)?w-(\d+(?:\.\d+)?)$/.exec(claim.width)?.[1]) * SPACING_PX;
        // A grid states its column directly; a flex row carries it on the list Card.
        const fromGrid = /grid-cols-\[(\d+)px_1fr\]/.exec(real)?.[1];
        const fromCard = fromGrid
          ? undefined
          : /w-(\d+) shrink-0 flex-col/.exec(
              readFileSync(repo(layout.width ?? layout.root), 'utf8'),
            )?.[1];
        const realPx = fromGrid ? Number(fromGrid) : Number(fromCard) * SPACING_PX;

        expect(realPx, 'could not read the real list width').toBeGreaterThan(0);
        expect(px).toBe(realPx);
      });
    });
  }
});
