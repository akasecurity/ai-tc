import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// A field is TWO decisions, and this package makes both by hand.
//
// `border-border-field` is the edge: `border-border` measures 1.26:1 light and
// 1.42:1 dark, under the 3:1 a control boundary is asked for. `bg-surface-2` (or
// `bg-surface` on the page canvas) is the fill: a field whose fill equals the
// fill under it leaves that edge drawing a rectangle against its own colour,
// which is compliant and reads as a floating outline.
//
// ui-kit's `Input` and `SelectTrigger` carry both in one place, pinned by
// border-field.test.ts there. The controls below are hand-rolled — a search
// wrapper around a `bg-transparent` input, a DropdownMenu trigger — so each
// spells the pair itself and nothing was pinning any of them. That is not a
// hypothetical gap: five of these six sat on `border-border` while ui-kit's two
// were correct, and two were missed by a survey that went looking for the other
// four. Neither miss was about size — `InventoryNav` is `h-8.5` like
// `SessionListView` and was found. What hid them was SHAPE: SessionListView puts
// its border on a WRAPPER around a `bg-transparent` input, so a search for
// bordered `<input>` elements never saw it, and HarnessSelect puts its border
// COLOUR behind a conditional, so a search for the literal pairing missed that.
//
// Both premises these assertions rest on are RESOLVED rather than restated: the
// container fill is read from ui-kit's `card.tsx`, and the canvas collision from
// `theme.css`. Written as literals, changing `card.tsx` to `bg-surface-2` left
// this suite green while every field collided at 1.000:1 — and the positive pins
// then REQUIRED the collision.
//
// Same precedent as border-field.test.ts: pin the exact string so a change is
// deliberate. These files also carry legitimate `border-border` on cards,
// dividers and chips, so the negative cases are built FROM each pinned fragment
// rather than searching for a token — a bare token search cannot tell a field's
// edge from the card it sits in. Where a control's edge colour is CONDITIONAL,
// the conditional expression is pinned, not the token: an unanchored whole-file
// search for `'border-border-field'` passed while HarnessSelect's ternary arms
// were swapped, putting its resting state on primary blue and its filtered state
// on plain grey.

const require_ = createRequire(import.meta.url);
const UI_KIT_SRC = dirname(require_.resolve('@akasecurity/ui-kit'));

const cache = new Map<string, string>();
const readFile = (abs: string): string => {
  const hit = cache.get(abs);
  if (hit !== undefined) return hit;
  const src = readFileSync(abs, 'utf8');
  cache.set(abs, src);
  return src;
};

const read = (rel: string): string =>
  readFile(fileURLToPath(new URL(`../../src/${rel}`, import.meta.url)));

/** ui-kit's `Card` fill — the surface every Card-hosted field renders on. */
function cardFill(): string {
  const line = readFile(join(UI_KIT_SRC, 'card.tsx'))
    .split('\n')
    .find((l) => l.includes('rounded-xl border border-border'));
  if (line === undefined) throw new Error('card.tsx: no Card class string found');
  const match = /\bbg-surface(?:-\d)?\b/.exec(line);
  if (match === null) throw new Error('card.tsx: no bg-surface* token on the Card line');
  return match[0];
}

/**
 * The fill a CANVAS-level field must not take: in light, `--color-canvas` and
 * `--color-surface-2` are the same hex, so a `bg-surface-2` field on the page has
 * no fill of its own. Resolved from theme.css so the day those two stop matching,
 * this stops asserting a collision that no longer exists.
 */
function canvasCollisionFill(): string {
  const css = readFile(join(UI_KIT_SRC, 'styles/theme.css'));
  const valueOf = (token: string): string => {
    const match = new RegExp(`--color-${token}:\\s*#[0-9a-f]{3,8}`, 'i').exec(css);
    if (match === null) throw new Error(`theme.css: --color-${token} not found`);
    return match[0].slice(match[0].indexOf('#')).toLowerCase();
  };
  const canvas = valueOf('canvas');
  const twin = (['surface-2', 'surface-3', 'surface'] as const).find((t) => valueOf(t) === canvas);
  if (twin === undefined) throw new Error('theme.css: no surface token shares the canvas hex');
  return `bg-${twin}`;
}

const FIELDS: {
  file: string;
  control: string;
  on: 'a Card' | 'the page canvas';
  edge: string;
  fill: string;
  alsoContains?: string;
}[] = [
  {
    file: 'findings/FindingsToolbarView.tsx',
    control: 'the findings search',
    on: 'the page canvas',
    edge: 'rounded-lg border border-border-field bg-surface pl-9 pr-3',
    fill: 'bg-surface',
  },
  {
    file: 'detections/DetectionsListView.tsx',
    control: 'the detections search',
    on: 'a Card',
    edge: 'rounded-lg border border-border-field bg-surface-2 pl-9 pr-3',
    fill: 'bg-surface-2',
  },
  {
    file: 'inventory/InventoryNav.tsx',
    control: 'the assets search',
    on: 'a Card',
    edge: 'rounded-lg border border-border-field bg-surface-2 pl-9 pr-3',
    fill: 'bg-surface-2',
  },
  {
    file: 'inventory/ProjectPane.tsx',
    control: 'the project-files search',
    on: 'a Card',
    edge: 'rounded-lg border border-border-field bg-surface-2 pl-9 pr-8',
    fill: 'bg-surface-2',
  },
  {
    file: 'activity/SessionListView.tsx',
    control: 'the sessions search',
    on: 'a Card',
    // The border sits on the WRAPPER: the input inside it is bg-transparent, so
    // this element is the whole visible control and carries both decisions.
    edge: 'rounded-lg border border-border-field bg-surface-2 px-2.5',
    fill: 'bg-surface-2',
  },
  {
    file: 'activity/HarnessSelect.tsx',
    control: 'the harness filter',
    on: 'a Card',
    // Its border COLOUR is conditional — border-border-field at rest, primary
    // once a subset is chosen — so the fragment carries the fill and the shape,
    // and the resting colour is pinned as the CONDITIONAL below, not as a token.
    edge: 'rounded-lg border bg-surface-2 px-2.5',
    fill: 'bg-surface-2',
    alsoContains: "all ? 'border-border-field'",
  },
];

describe('the hand-rolled field boundary', () => {
  for (const { file, control, on, edge, alsoContains } of FIELDS) {
    it(`${control}: an edge that clears 3:1 and a fill a step off ${on}`, () => {
      const source = read(file);
      expect(source).toContain(edge);
      if (alsoContains !== undefined) expect(source).toContain(alsoContains);
    });
  }

  // The edge half. Built by swapping this control's own edge token back, so it
  // matches the field and never the card or divider beside it.
  for (const { file, control, edge } of FIELDS) {
    const collided = edge.replace('border-border-field', 'border-border');
    if (collided === edge) continue; // HarnessSelect: colour is pinned via alsoContains
    it(`${control}: its edge is not back on the ordinary border`, () => {
      expect(read(file)).not.toContain(collided);
    });
  }

  // The fill half, which no token search can express: what makes a fill wrong is
  // the fill of the thing UNDER it, which is not in the class string. Both
  // container fills are resolved — ui-kit's Card, and the canvas/surface-2
  // same-hex identity in theme.css.
  for (const { file, control, on, edge, fill } of FIELDS) {
    it(`${control}: its fill is not the same as ${on}`, () => {
      const container = on === 'a Card' ? cardFill() : canvasCollisionFill();
      expect(read(file)).not.toContain(edge.replace(fill, container));
    });
  }
});
