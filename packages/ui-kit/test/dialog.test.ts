import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// DialogFooter's alignment is a DEFAULT that call sites inherit by saying
// nothing, which is exactly what makes it worth pinning — the same argument
// sheet.test.ts makes for SheetContent's width, and for the same reason: an
// edit to the string below moves the action row of every dialog in this repo
// and downstream, in files the edit does not touch, with nothing in their
// diffs to show it.
//
// It carried no `justify` until now, so the buttons laid out from the LEFT
// edge. Every consumer wanted the other thing and said so separately or not at
// all: some passed `justify-end`, one pushed its buttons over with a
// `<span className="flex-1" />` spacer, and the rest simply shipped
// left-aligned. A default nobody agrees with is a default that gets
// re-specified at each call site until someone counts them.
//
// Two properties, not one. The token is pinned so a change is deliberate. The
// `flex` + `justify-end` PAIRING is pinned separately because `justify-end`
// alone does nothing without a flex container, and a sweep that dropped
// `flex` would leave the other reading as intact.

const SOURCE = readFileSync(fileURLToPath(new URL('../src/dialog.tsx', import.meta.url)), 'utf8');

/** The one class string that styles the footer, found by the anchor that opens it. */
function footerClasses(): string {
  const line = SOURCE.split('\n').find((l) => l.includes("border-t border-border px-5 py-3.5"));
  if (line === undefined) throw new Error('dialog.tsx: no line matching the footer class string');
  return line;
}

describe('DialogFooter default alignment', () => {
  it('lays its actions out in a row', () => {
    // Both halves, or the assertion passes on a footer that is one or the other.
    expect(footerClasses()).toMatch(/\bflex\b/);
    expect(footerClasses()).not.toMatch(/\bflex-col\b/);
  });

  it('right-aligns them, so a call site passing no justify gets that', () => {
    expect(footerClasses()).toMatch(/\bjustify-end\b/);
  });

  it('reads the real footer line rather than any string in the file', () => {
    // The positive control: without it, a `footerClasses` that silently
    // returned the whole file would satisfy every assertion above.
    expect(footerClasses()).toContain('shrink-0');
    expect(footerClasses().split('\n')).toHaveLength(1);
  });
});
