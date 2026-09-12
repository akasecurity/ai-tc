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
// border-field.test.ts there. The controls below are not those primitives, so
// each is pinned here. That is not a hypothetical gap: five of the six sat on
// `border-border` while ui-kit's two were correct, and two were missed by a
// survey that went looking for the other four. Neither miss was about size —
// `InventoryNav` is `h-8.5` like `SessionListView` and was found. What hid them
// was SHAPE: SessionListView put its border on a WRAPPER around a
// `bg-transparent` input, so a search for bordered `<input>` elements never saw
// it, and HarnessSelect puts its border COLOUR behind a conditional, so a search
// for the literal pairing missed that.
//
// The SEARCH fields are no longer hand-rolled — all six render `SearchField`
// (shared/SearchField.tsx), and BOTH halves live there: the focus rule, and the
// edge/fill pair, which `SURFACE_CLASS` resolves from a `surface` prop naming
// what the field sits on. A call site can no longer put either back on
// `border-border` by hand, because it never spells them.
//
// So the six are pinned in ONE place now, and the call-site table below asserts
// a different thing: which surface each one declares. That is still a per-site
// decision — what makes a fill wrong is the fill of the thing UNDER it, which
// the component cannot see.
//
// Centralizing buys one assertion where there were five and opens one hole in
// exchange: a call site that goes back to spelling its own `<input>` keeps a
// correct-looking `surface` fragment while losing the edge, fill and ring
// together. `renders through the shared field` below is what closes it, and it
// is the reason the shared half may be asserted once.
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

/**
 * A focus fragment matched as a DECISION rather than as today's spelling of it.
 *
 * Tailwind v4 split v3's `outline-none` in two: `outline-none` sets
 * `outline-style: none` flat, while `outline-hidden` also re-emits a transparent
 * outline under `forced-colors: active`, which the system then paints. Windows
 * High Contrast Mode discards box-shadow rings and author border colours — which
 * is exactly `ring-*` and `border-primary`, i.e. BOTH cues these six controls
 * carry — so `outline-hidden` is the spelling that keeps an indicator there.
 *
 * Pinning either spelling literally makes the other fail, and a move from `none`
 * to `hidden` is the REPAIR. A pin that reds on a repair reads as a regression and
 * gets reverted — the same failure this file's header describes for the container
 * premise, one property over: an assertion that mandates the state it exists to
 * forbid. So the outline token alternates and every other token stays exact.
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

/**
 * What each call site DECLARES, which is the half that cannot move into the
 * shared component: the surface it sits on. `shared` says the control renders
 * through SearchField — whose edge, fill and focus rule are asserted once,
 * below — rather than spelling an input of its own.
 */
const FIELDS: {
  file: string;
  control: string;
  on: 'a Card' | 'the page canvas';
  /** The `surface` value this call site must declare, or its own edge fragment. */
  edge: string;
  shared: boolean;
  /** The whole focus treatment, for the controls that still own one. */
  focus?: string;
  alsoContains?: string;
}[] = [
  {
    file: 'findings/FindingsToolbarView.tsx',
    control: 'the findings search',
    on: 'the page canvas',
    edge: 'surface="canvas"',
    shared: true,
  },
  {
    file: 'findings/FindingTypesListView.tsx',
    control: 'the finding-types search',
    on: 'a Card',
    edge: 'surface="card"',
    shared: true,
  },
  {
    file: 'detections/DetectionsListView.tsx',
    control: 'the detections search',
    on: 'a Card',
    edge: 'surface="card"',
    shared: true,
  },
  {
    file: 'inventory/InventoryNav.tsx',
    control: 'the assets search',
    on: 'a Card',
    edge: 'surface="card"',
    shared: true,
  },
  {
    file: 'inventory/ProjectPane.tsx',
    control: 'the project-files search',
    on: 'a Card',
    edge: 'surface="card"',
    shared: true,
  },
  {
    file: 'activity/SessionListView.tsx',
    control: 'the sessions search',
    on: 'a Card',
    edge: 'surface="card"',
    shared: true,
  },
  {
    file: 'activity/HarnessSelect.tsx',
    control: 'the harness filter',
    on: 'a Card',
    // The one control here that is still hand-rolled, so it spells the pair
    // itself. Its border COLOUR is conditional — border-border-field at rest,
    // primary once a subset is chosen — so the fragment carries the fill and the
    // shape, and the resting colour is pinned as the CONDITIONAL below, not as a
    // token.
    edge: 'rounded-lg border bg-surface-2 px-2.5',
    shared: false,
    alsoContains: "all ? 'border-border-field'",
    focus: 'focus:outline-hidden focus-visible:ring-2 focus-visible:ring-primary/40',
  },
];

/**
 * The shared field's own two decisions, in their one home. The edge and fill are
 * read as the `SURFACE_CLASS` entry each `surface` resolves to, so the table
 * above pins WHICH surface a call site picked and this pins what that MEANS.
 */
const SHARED_FIELD = 'shared/SearchField.tsx';
const SHARED_FOCUS = 'focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/40';
const SHARED_EDGE: Record<'a Card' | 'the page canvas', string> = {
  'a Card': "card: 'rounded-lg border border-border-field bg-surface-2'",
  'the page canvas': "canvas: 'rounded-lg border border-border-field bg-surface'",
};

describe('the field boundary this package draws by hand', () => {
  // The FOCUS half. Pinned separately from `edge` because it lives at the far end
  // of the class string and one control expresses it through `focus-within` on a
  // wrapper rather than `focus`/`focus-visible` on the control itself.
  //
  // It is pinned at all because it was the one property of these six that nothing
  // reached: deleting the ring from all four search inputs passed 365/365, one
  // property over from the gap this file's header diagnoses. And pinning it found
  // a second defect — SessionListView's wrapper carried NO focus rule while its
  // inner input suppressed the native outline, so focusing that search changed
  // nothing on screen at all.
  //
  // What this does NOT assert is that the indicator clears 3:1 between states. It
  // does not: the border swap is 2.070:1 light / 1.729:1 dark and the ring adds
  // 2.019:1 / 2.325:1 on its own pixels, both under SC 2.4.13. (2.157:1 is that
  // dark figure taken over --color-surface-2 — the field's own fill, which is the
  // one surface a ring painted OUTSIDE the border box never has behind it.) These
  // match the ui-kit primitives, and moving that bar is a change to
  // --color-primary's alpha across both products.
  //
  // Nor does it assert anything under FORCED COLORS, where the ring's box-shadow
  // and the focused border colour are both discarded — see `focusPattern` and
  // theme.css's closing paragraph.
  it('every search field: keeps a focus indicator', () => {
    expect(read(SHARED_FIELD)).toMatch(focusPattern(SHARED_FOCUS));
  });

  // The edge and fill halves, now asserted where they are spelled rather than at
  // six call sites. Both surfaces are pinned, because a `surface` declared by a
  // call site says nothing on its own until this says what it resolves to.
  for (const [on, entry] of Object.entries(SHARED_EDGE)) {
    it(`every search field on ${on}: an edge that clears 3:1 and a fill a step off it`, () => {
      expect(read(SHARED_FIELD)).toContain(entry);
    });

    it(`every search field on ${on}: its edge is not back on the ordinary border`, () => {
      expect(read(SHARED_FIELD)).not.toContain(
        entry.replace('border-border-field', 'border-border'),
      );
    });
  }

  // The fill half, which no token search can express: what makes a fill wrong is
  // the fill of the thing UNDER it, which is not in the class string. Both
  // container fills are RESOLVED — ui-kit's Card, and the canvas/surface-2
  // same-hex identity in theme.css — so the day either stops holding, this stops
  // asserting a collision that no longer exists.
  for (const [on, entry] of Object.entries(SHARED_EDGE)) {
    it(`every search field on ${on}: its fill is not the same as ${on}`, () => {
      const container = on === 'a Card' ? cardFill() : canvasCollisionFill();
      expect(entry, `${on}: no bg-surface* token in its class`).toMatch(/\bbg-surface(?:-\d)?\b/);
      expect(read(SHARED_FIELD)).not.toContain(entry.replace(/\bbg-surface(?:-\d)?\b/, container));
    });
  }

  // What lets the assertion above stand for six controls. Without it a call site
  // could go back to its own `<input>`, keep an edge fragment this file still
  // matches, and lose the ring with every test here green — which is the
  // five-into-one trade stated in the header, paid for.
  for (const { file, control, shared, edge } of FIELDS) {
    if (!shared) continue;
    it(`${control}: renders through the shared field`, () => {
      // Matched as ONE element rather than as two independent substring hits:
      // `<SearchField` somewhere and `surface="card"` somewhere else is also
      // satisfied by a hand-rolled input beside an unrelated tag, which is the
      // join this case exists to hold.
      expect(read(file)).toMatch(
        new RegExp(`<SearchField\\b[^>]*${edge.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 's'),
      );
    });
  }

  for (const { file, control, focus } of FIELDS) {
    if (focus === undefined) continue;
    it(`${control}: keeps a focus indicator of its own`, () => {
      expect(read(file)).toMatch(focusPattern(focus));
    });
  }

  // For a shared control this asserts WHICH surface it declares; for the one
  // hand-rolled control it asserts the pair spelled in place.
  for (const { file, control, on, edge, alsoContains } of FIELDS) {
    it(`${control}: declares the surface it sits on (${on})`, () => {
      const source = read(file);
      expect(source).toContain(edge);
      if (alsoContains !== undefined) expect(source).toContain(alsoContains);
    });
  }

  // The edge and fill halves for the control that still spells them itself.
  // Scoped to `shared: false` because a shared control's `edge` is the surface it
  // DECLARES — it carries no colour token to swap, and the negatives that matter
  // for it are asserted against SHARED_FIELD above.
  //
  // Built by swapping this control's own edge token back, so it matches the field
  // and never the card or divider beside it.
  for (const { file, control, edge, shared } of FIELDS) {
    if (shared) continue;
    const collided = edge.replace('border-border-field', 'border-border');
    if (collided === edge) continue; // HarnessSelect: colour is pinned via alsoContains
    it(`${control}: its edge is not back on the ordinary border`, () => {
      expect(read(file)).not.toContain(collided);
    });
  }

  for (const { file, control, on, edge, shared } of FIELDS) {
    if (shared) continue;
    it(`${control}: its fill is not the same as ${on}`, () => {
      const container = on === 'a Card' ? cardFill() : canvasCollisionFill();
      // The fill token is DERIVED from this control's own edge fragment, by the
      // same regex `cardFill` uses, rather than restated in a second field that
      // had to be edited in lockstep with it.
      expect(edge, `${control}: no bg-surface* token in its edge fragment`).toMatch(
        /\bbg-surface(?:-\d)?\b/,
      );
      expect(read(file)).not.toContain(edge.replace(/\bbg-surface(?:-\d)?\b/, container));
    });
  }
});
