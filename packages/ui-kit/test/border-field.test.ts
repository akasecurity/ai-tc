import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// --color-border-field exists because `border-border` is 1.26:1 light and 1.42:1
// dark against `bg-surface`, and a field's border is the only thing marking
// where the control begins. Nothing pinned that choice, so a sweep normalising
// these class strings against their neighbours would revert it with no signal —
// and SelectContent one function below IS `border-border`, which makes the
// trigger look like the inconsistency rather than the fix.
//
// Same precedent as badge.test.ts: pin the exact string so a change is
// deliberate. The fragments are long enough that the prose in each file's own
// docblock — which names both tokens while explaining the choice — cannot
// satisfy them, which is the failure mode a bare token search would have.

const read = (rel: string): string =>
  readFileSync(fileURLToPath(new URL(`../src/${rel}`, import.meta.url)), 'utf8');

const EXPECTED: { file: string; component: string; edge: string; why: string }[] = [
  {
    file: 'input.tsx',
    component: 'Input',
    edge: 'rounded-lg border border-border-field bg-surface',
    why: 'a field on a panel of its own colour; the border is the whole boundary',
  },
  {
    file: 'select.tsx',
    component: 'SelectTrigger',
    edge: 'rounded-lg border border-border-field bg-surface',
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

  // The pairing that must not come back: a control edge on its own fill at
  // 1.26:1. Written as the exact fragment rather than a token search, because
  // `border-border` is a prefix of `border-border-field`.
  it('leaves no field edge on the ordinary border', () => {
    const offenders = ['input.tsx', 'select.tsx'].filter((file) =>
      read(file).includes('rounded-lg border border-border bg-surface px-3'),
    );
    expect(offenders).toEqual([]);
  });
});
