import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// SheetContent's width is a DEFAULT that call sites inherit by saying nothing,
// which is what makes it worth pinning: `web-ui`'s findings sheet passes only
// `p-0`, so an edit to the string below changes a panel in a file the edit does
// not touch, in another package, with nothing in that package's diff to show it.
// That is not hypothetical — widening this from `max-w-md` to `max-w-xl` moved
// that sheet 448px → 576px, and no test in either package noticed.
//
// Two properties, not one. The exact token is pinned so a change is deliberate.
// The `w-full` + `max-w-*` PAIRING is pinned separately because it is the part
// that carries meaning: `w-full` alone is a full-bleed panel on every viewport,
// and a `max-w-*` alone leaves the panel sized by its content. A sweep that
// dropped either would leave the other reading as intact.
//
// Same precedent as border-field.test.ts: pin the exact string, and end every
// fragment on a DELIMITED token — `max-w-xl` is not a substring of `max-w-2xl`,
// but `\b` is what keeps that true if the scale ever gains a `max-w-xlarge`.

const SOURCE = readFileSync(fileURLToPath(new URL('../src/sheet.tsx', import.meta.url)), 'utf8');

/** The one class string that styles the panel, found by the anchor that opens it. */
function panelClasses(): string {
  const line = SOURCE.split('\n').find((l) => l.includes('fixed inset-y-0'));
  if (line === undefined) throw new Error('sheet.tsx: no line matching `fixed inset-y-0`');
  return line;
}

describe('SheetContent default width', () => {
  it('is bounded — the panel takes the viewport up to a cap, never past it', () => {
    const classes = panelClasses();
    // Both halves, or the assertion passes on a panel that is one or the other.
    expect(classes).toMatch(/\bw-full\b/);
    expect(classes).toMatch(/\bmax-w-[a-z0-9[\]%.-]+/);
  });

  it('caps at max-w-xl, so a call site passing no width gets that panel', () => {
    expect(panelClasses()).toMatch(/\bmax-w-xl\b/);
  });

  it('reads the real panel line rather than any string in the file', () => {
    // The positive control: without it, a `panelClasses` that silently returned
    // the whole file would satisfy every assertion above.
    expect(panelClasses()).toContain('z-50');
    expect(panelClasses().split('\n')).toHaveLength(1);
  });
});
