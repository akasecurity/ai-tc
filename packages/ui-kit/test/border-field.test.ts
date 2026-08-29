import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// A field is TWO decisions that have to hold together, so both are pinned in one
// fragment. `--color-border-field` exists because `border-border` is 1.26:1 light
// and 1.42:1 dark; `bg-surface-2` exists because Card, DialogContent and
// SheetContent are all `bg-surface`, so a `bg-surface` field had a fill identical
// to the panel under it and the border was left drawing a rectangle against its
// own colour. Revert either half and the control goes back to reading as a
// floating outline.
//
// Nothing pinned either choice, so a sweep normalising these class strings
// against their neighbours would revert them with no signal — and SelectContent
// one function below IS `border-border bg-surface`, which makes the trigger look
// like the inconsistency rather than the fix.
//
// Same precedent as badge.test.ts: pin the exact string so a change is
// deliberate. The fragments are long enough that the prose in each file's own
// docblock — which names the tokens while explaining the choice — cannot satisfy
// them, which is the failure mode a bare token search would have.

const read = (rel: string): string =>
  readFileSync(fileURLToPath(new URL(`../src/${rel}`, import.meta.url)), 'utf8');

const EXPECTED: { file: string; component: string; edge: string; why: string }[] = [
  {
    file: 'input.tsx',
    component: 'Input',
    edge: 'rounded-lg border border-border-field bg-surface-2',
    why: 'a fill one step off the panel under it, and an edge that clears 3:1 on that fill',
  },
  {
    file: 'select.tsx',
    component: 'SelectTrigger',
    edge: 'rounded-lg border border-border-field bg-surface-2',
    why: 'the same shape as Input, and it sits in the same forms',
  },
  {
    file: 'select.tsx',
    component: 'SelectContent',
    edge: 'rounded-lg border border-border bg-surface',
    why: 'a floating surface over a scrim — it does NOT share the problem, and pinning it records that the difference is deliberate',
  },
];

describe('the field boundary', () => {
  for (const { file, component, edge, why } of EXPECTED) {
    it(`${component}: ${why}`, () => {
      expect(read(file)).toContain(edge);
    });
  }

  // The two pairings that must not come back, in either fill: a control edge on
  // the ordinary border at 1.26:1. Written as exact fragments rather than a token
  // search, because `border-border` is a prefix of `border-border-field`.
  it.each(['bg-surface', 'bg-surface-2'])(
    'leaves no field edge on the ordinary border (%s)',
    (fill) => {
      const offenders = ['input.tsx', 'select.tsx'].filter((file) =>
        read(file).includes(`rounded-lg border border-border ${fill} px-3`),
      );
      expect(offenders).toEqual([]);
    },
  );

  // The fill half, stated on its own: a field whose fill equals the panel under
  // it. Card/DialogContent/SheetContent are all bg-surface, so `bg-surface` on
  // these two controls is that collision by definition.
  it('leaves no field on the same fill as its container', () => {
    const offenders = ['input.tsx', 'select.tsx'].filter((file) =>
      read(file).includes('border-border-field bg-surface px-3'),
    );
    expect(offenders).toEqual([]);
  });
});
