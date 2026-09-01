import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// A field is TWO decisions that have to hold together, so both are pinned in one
// fragment. `--color-border-field` exists because `border-border` is 1.26:1 light
// and 1.42:1 dark; `bg-surface-2` exists because the containers a form lives in —
// Card, DialogContent, SheetContent — are all `bg-surface`, so a `bg-surface`
// field had a fill identical to the panel under it and the border was left
// drawing a rectangle against its own colour. Revert either half and the control
// goes back to reading as a floating outline.
//
// That container premise is RESOLVED from those three files rather than restated
// here, and the difference is not cosmetic: with it written as a literal, changing
// `card.tsx` to `bg-surface-2` collided every field at 1.000:1 and this suite
// stayed green — worse, the positive pins below then REQUIRED `bg-surface-2` on
// the fields, so the suite mandated the collision it exists to forbid.
//
// Nothing pinned either choice, so a sweep normalising these class strings
// against their neighbours would revert them with no signal — and SelectContent
// one function below IS `border-border bg-surface`, which makes the trigger look
// like the inconsistency rather than the fix.
//
// Same precedent as badge.test.ts: pin the exact string so a change is
// deliberate. Every pinned fragment ends on a DELIMITED token, because
// `bg-surface` is a prefix of `bg-surface-2` exactly as `border-border` is of
// `border-border-field`: an undelimited `…bg-surface` pin was satisfiable by
// `…bg-surface-2`, and SelectContent passed this suite while wearing the
// trigger's new fill.

const cache = new Map<string, string>();
const read = (rel: string): string => {
  const hit = cache.get(rel);
  if (hit !== undefined) return hit;
  const src = readFileSync(fileURLToPath(new URL(`../src/${rel}`, import.meta.url)), 'utf8');
  cache.set(rel, src);
  return src;
};

/**
 * The fill of a container a form renders inside, read from the container itself.
 * `anchor` picks the one class string that styles it, so a hover/child rule
 * carrying its own `bg-*` cannot be mistaken for the container's own fill.
 */
function containerFill(file: string, anchor: string): string {
  const line = read(file)
    .split('\n')
    .find((l) => l.includes(anchor));
  if (line === undefined) throw new Error(`${file}: no line matching ${anchor}`);
  const match = /\bbg-surface(?:-\d)?\b/.exec(line);
  if (match === null) throw new Error(`${file}: no bg-surface* token on the ${anchor} line`);
  return match[0];
}

/**
 * A focus fragment matched as a DECISION rather than as today's spelling of it.
 *
 * Tailwind v4 split v3's `outline-none` in two: `outline-none` sets
 * `outline-style: none` flat, while `outline-hidden` also re-emits a transparent
 * outline under `forced-colors: active`, which the system then paints. Windows
 * High Contrast Mode discards box-shadow rings and author border colours — which
 * is exactly `ring-*` and `border-primary` — so `outline-hidden` is the spelling
 * that keeps an indicator there at all.
 *
 * Pinning either spelling literally makes the other fail this suite, and a move
 * from `none` to `hidden` is the REPAIR. A pin that reds on a repair reads as a
 * regression and gets reverted — the same failure this file's header describes
 * for the container premise, one property over: an assertion that mandates the
 * state it exists to forbid. So the outline token alternates and every other
 * token stays exact.
 */
function focusPattern(fragment: string): RegExp {
  return new RegExp(
    fragment
      .split(' ')
      .map((token) =>
        /^(?:focus:)?outline-(?:none|hidden)$/.test(token)
          ? '(?:focus:)?outline-(?:none|hidden)'
          : token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
      )
      .join(' '),
  );
}

const CONTAINERS = [
  { file: 'card.tsx', component: 'Card', anchor: 'rounded-xl border border-border' },
  { file: 'dialog.tsx', component: 'DialogContent', anchor: 'rounded-2xl border border-border' },
  { file: 'sheet.tsx', component: 'SheetContent', anchor: 'fixed inset-y-0' },
] as const;

const EXPECTED: {
  file: string;
  component: string;
  edge: string;
  /**
   * The focus indicator. REQUIRED, and `null` is how a component declares it has
   * none — an optional key skipped with `continue` is the same silently-skips
   * shape as the `alsoContains` hole this suite already closed once: a focusable
   * component added below would get no pin and no complaint.
   */
  focus: string | null;
  why: string;
}[] = [
  {
    file: 'input.tsx',
    component: 'Input',
    edge: 'rounded-lg border border-border-field bg-surface-2 px-3',
    focus:
      'focus:border-primary focus:outline-hidden focus-visible:ring-2 focus-visible:ring-primary/40',
    why: 'a fill one step off the panel under it, and an edge that clears 3:1 on that fill',
  },
  {
    file: 'select.tsx',
    component: 'SelectTrigger',
    edge: 'rounded-lg border border-border-field bg-surface-2 px-3',
    focus:
      'focus:border-primary focus:outline-hidden focus-visible:ring-2 focus-visible:ring-primary/40',
    why: 'the same shape as Input, and it sits in the same forms',
  },
  {
    file: 'select.tsx',
    component: 'SelectContent',
    // Delimited by `shadow-lg`, which is also the reason it keeps `bg-surface`:
    // it is separated by ELEVATION rather than by a fill step. Radix Select ships
    // no overlay primitive, so there is no scrim doing that job.
    edge: 'rounded-lg border border-border bg-surface shadow-lg',
    focus: null, // a popup, not a control — nothing to focus
    why: 'elevated rather than inset — it does NOT share the problem, and pinning it records that the difference is deliberate',
  },
];

describe('the field boundary', () => {
  // The premise every fill assertion rests on. Read from the containers, so a
  // container that moves fails HERE with its own name rather than silently
  // turning the pins below into a mandate for the collision.
  it('every container a form renders in shares one fill', () => {
    const fills = CONTAINERS.map(({ file, component, anchor }) => ({
      component,
      fill: containerFill(file, anchor),
    }));
    expect(new Set(fills.map((f) => f.fill)).size, JSON.stringify(fills)).toBe(1);
  });

  // Read from the SOURCE, not from `edge`. Comparing the resolved container against
  // the fixture literal validates the fixture against itself: reverting input.tsx to
  // `bg-surface` left this assertion green (it fails 2 others, so nothing was
  // uncovered overall — but this one reads as a fill guard and was not one).
  it('the field fill is one step off that container fill, not equal to it', () => {
    const container = containerFill(CONTAINERS[0].file, CONTAINERS[0].anchor);
    for (const { component, file, edge } of EXPECTED) {
      if (component === 'SelectContent') continue; // elevated, deliberately equal
      const shape = edge.replace(/\bbg-surface(?:-\d)?\b/, container);
      expect(
        read(file),
        `${component} (${file}) must not sit on its container's own fill`,
      ).not.toContain(shape);
    }
  });

  for (const { file, component, edge, why } of EXPECTED) {
    it(`${component}: ${why}`, () => {
      expect(read(file)).toContain(edge);
    });
  }

  // The FOCUS half, pinned for the two components a user can focus. It sits at the
  // far end of the class string, outside every `edge` fragment above, and nothing
  // reached it — deleting the ring from the four dashboard-ui search inputs that
  // were given it passed 365/365 there. SelectContent carries none by design: it
  // is a popup, not a control.
  //
  // This asserts the ring is PRESENT, not that it clears 3:1 between states. It
  // does not — `ring-primary/40` paints outside the border box, so its backdrop is
  // the container, giving 2.019:1 light and 2.325:1 dark (2.157:1 is that figure
  // over --color-surface-2, i.e. the field's own fill, which is the one surface the
  // ring never has behind it). Raising it means moving --color-primary's alpha for
  // every focus ring in both products.
  //
  // Nor does it assert anything about FORCED COLORS, where a `ring-*` box-shadow and
  // an author border colour are both discarded. That is why the outline token is
  // matched as a decision rather than as a spelling — see `focusPattern`.
  for (const { file, component, focus } of EXPECTED) {
    if (focus === null) continue; // declared above as having none
    it(`${component}: keeps its focus ring`, () => {
      expect(read(file)).toMatch(focusPattern(focus));
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
  // it. The container fill is resolved, so this tracks card.tsx rather than a
  // literal that would go on passing after card.tsx moved.
  it('leaves no field on the same fill as its container', () => {
    const container = containerFill(CONTAINERS[0].file, CONTAINERS[0].anchor);
    const offenders = ['input.tsx', 'select.tsx'].filter((file) =>
      read(file).includes(`border-border-field ${container} px-3`),
    );
    expect(offenders).toEqual([]);
  });
});
