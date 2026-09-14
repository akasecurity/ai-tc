import { readdirSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

// Two `SearchField`s on one page must not give their clear buttons the same
// accessible name.
//
// `label` is a REQUIRED prop for exactly this reason — a page with two search
// boxes needs them told apart, and a default would name both. `clearLabel` is
// not required, and its default reintroduced the ambiguity one control over:
// the Inventory page renders `InventoryNav` and, once a project is selected,
// `ProjectPane` side by side, and both clear buttons came out as "Clear
// search". A screen-reader user listing buttons heard it twice with nothing
// saying which field each one empties, and the two fields are the two halves of
// that page — so guessing wrong throws away the wrong query (WCAG 4.1.2).
//
// This lives in web-ui rather than beside the component because the property is
// about REACHABILITY: which fields land on one page is a fact about the app's
// composition, and `@akasecurity/dashboard-ui` cannot see it. The component's
// own suite pins the button; this pins the pairing.
//
// It is DERIVED rather than a list of known pages. A hand-listed pair would go
// stale the first time a page grew a second search field, which is the failure
// this exists to catch.

const ROOT = new URL('../../', import.meta.url);
const SOURCE_DIRS = ['packages/dashboard-ui/src', 'web-ui/app'];

/** Every `.tsx` under a directory, recursively. */
function tsxFiles(dir: URL): URL[] {
  const out: URL[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    // A trailing slash is what makes `new URL` treat the segment as a
    // directory rather than replacing the last path component.
    if (entry.isDirectory()) out.push(...tsxFiles(new URL(`${entry.name}/`, dir)));
    else if (entry.name.endsWith('.tsx')) out.push(new URL(entry.name, dir));
  }
  return out;
}

const ALL = SOURCE_DIRS.flatMap((d) => tsxFiles(new URL(`${d}/`, ROOT))).map((url) => ({
  path: url.pathname.slice(ROOT.pathname.length),
  source: readFileSync(url, 'utf8'),
}));

/**
 * A file that renders a search field, the components it exports (which is how
 * another file reaches it), and the `clearLabel` each of its fields declares —
 * `null` where it takes the default.
 *
 * The label is compared as the EXPRESSION TEXT, not as a rendered string: two
 * different expressions are presumed to name two different things, which is the
 * most a source scan can honestly claim.
 */
const renderers = ALL.filter((f) => f.source.includes('<SearchField')).map((f) => ({
  path: f.path,
  // `m[1]` is typed `string | undefined` because TS cannot know the group
  // matched; a capturing group that did match always yields a string, so the
  // filter narrows rather than discards.
  exports: [...f.source.matchAll(/export function (\w+)/g)]
    .map((m) => m[1])
    .filter((name): name is string => name !== undefined),
  clearLabels: [...f.source.matchAll(/<SearchField\b[\s\S]*?\/>/g)].map((el) => {
    const named = /\bclearLabel=(\{[\s\S]*?\}|"[^"]*")/.exec(el[0]);
    return named?.[1] ?? null;
  }),
}));

/** A path's last segment. `split` always yields one element; `at(-1)` does not say so. */
const basename = (path: string): string => path.slice(path.lastIndexOf('/') + 1);

/** Which renderers a page file reaches: its own fields, plus those it composes. */
function reachedBy(file: (typeof ALL)[number]) {
  return renderers.filter(
    (r) =>
      r.path === file.path || r.exports.some((name) => new RegExp(`<${name}\\b`).test(file.source)),
  );
}

describe('a page with two search fields names both clear buttons', () => {
  // The premise. If this stops finding renderers the assertions below hold
  // vacuously, and a page could grow a colliding pair with this file green.
  it('finds the search fields to reason about', () => {
    expect(renderers.length).toBeGreaterThanOrEqual(6);
    expect(renderers.flatMap((r) => r.clearLabels).length).toBe(renderers.length);
  });

  // Deliberately an OVER-approximation: this asks whether two fields are
  // reachable from one page, not whether they are mounted at the same instant.
  // Findings reaches two that are mutually exclusive today — `FindingsToolbarView`
  // renders on the flat/files views and `FindingTypesListView` on the grouped one
  // — so its distinct names are insurance rather than a fix. Modelling which JSX
  // branches can be live together is the fragile alternative, and a wrong model
  // is worse than a conservative one: this errs toward naming a button.
  const pages = ALL.map((f) => ({ file: f, reached: reachedBy(f) })).filter(
    (p) => p.reached.length > 1,
  );

  it('finds the pages that reach more than one', () => {
    expect(pages.length).toBeGreaterThan(0);
  });

  for (const { file, reached } of pages) {
    const where = reached.map((r) => basename(r.path)).join(' + ');

    it(`${basename(file.path)} (${where}): every clear button is named`, () => {
      for (const r of reached) {
        expect(
          r.clearLabels,
          `${r.path} renders beside another search field, so its clear button cannot take the default name`,
        ).not.toContain(null);
      }
    });

    it(`${basename(file.path)} (${where}): no two share a name`, () => {
      const labels = reached.flatMap((r) => r.clearLabels);
      expect(new Set(labels).size, `duplicate clearLabel among ${where}`).toBe(labels.length);
    });
  }
});
