import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// A field is TWO decisions, and this package makes both by hand.
//
// `border-border-field` is the edge: `border-border` measures 1.26:1 light and
// 1.42:1 dark, under the 3:1 a control boundary is asked for. `bg-surface-2` (or
// `bg-surface` on the page canvas) is the fill: a field whose fill equals the
// fill under it leaves that edge drawing a rectangle against its own colour,
// which is compliant and reads as a floating outline. Revert either half and the
// control goes back to looking like an outline on nothing.
//
// ui-kit's `Input` and `SelectTrigger` carry both in one place, pinned by
// border-field.test.ts there. The controls below are hand-rolled — a search
// wrapper around a `bg-transparent` input, a DropdownMenu trigger — so each
// spells the pair itself and nothing was pinning any of them. That is not a
// hypothetical gap: four of these six sat on `border-border` for months while
// ui-kit's two were correct, and the fifth and sixth were missed by a survey that
// went looking for the other four, because one is `h-8.5` rather than `h-9` and
// the other puts its border colour behind a conditional.
//
// Same precedent as border-field.test.ts: pin the exact string so a change is
// deliberate. These files also carry legitimate `border-border` on cards,
// dividers and chips, so the negative cases are built FROM each pinned fragment
// rather than searching for a token — a bare token search cannot tell a field's
// edge from the card it sits in.

const read = (rel: string): string =>
  readFileSync(fileURLToPath(new URL(`../../src/${rel}`, import.meta.url)), 'utf8');

const FIELDS: {
  file: string;
  control: string;
  on: string;
  edge: string;
  fill: string;
  containerFill: string;
  alsoContains?: string;
}[] = [
  {
    file: 'findings/FindingsToolbarView.tsx',
    control: 'the findings search',
    on: 'the page canvas',
    edge: 'rounded-lg border border-border-field bg-surface pl-9 pr-3',
    fill: 'bg-surface',
    // In light the canvas and --color-surface-2 are the same hex, so a
    // bg-surface-2 field on the canvas is the collision, not the safe choice.
    containerFill: 'bg-surface-2',
  },
  {
    file: 'detections/DetectionsListView.tsx',
    control: 'the detections search',
    on: 'a Card',
    edge: 'rounded-lg border border-border-field bg-surface-2 pl-9 pr-3',
    fill: 'bg-surface-2',
    containerFill: 'bg-surface',
  },
  {
    file: 'inventory/InventoryNav.tsx',
    control: 'the assets search',
    on: 'a Card',
    edge: 'rounded-lg border border-border-field bg-surface-2 pl-9 pr-3',
    fill: 'bg-surface-2',
    containerFill: 'bg-surface',
  },
  {
    file: 'inventory/ProjectPane.tsx',
    control: 'the project-files search',
    on: 'a Card',
    edge: 'rounded-lg border border-border-field bg-surface-2 pl-9 pr-8',
    fill: 'bg-surface-2',
    containerFill: 'bg-surface',
  },
  {
    file: 'activity/SessionListView.tsx',
    control: 'the sessions search',
    on: 'a Card',
    // The border sits on the WRAPPER: the input inside it is bg-transparent, so
    // this element is the whole visible control and carries both decisions.
    edge: 'rounded-lg border border-border-field bg-surface-2 px-2.5',
    fill: 'bg-surface-2',
    containerFill: 'bg-surface',
  },
  {
    file: 'activity/HarnessSelect.tsx',
    control: 'the harness filter',
    on: 'a Card',
    // Its border COLOUR is conditional — border-border-field at rest, primary
    // once a subset is chosen — so the fragment carries the fill and the shape,
    // and the resting colour is asserted separately.
    edge: 'rounded-lg border bg-surface-2 px-2.5',
    fill: 'bg-surface-2',
    containerFill: 'bg-surface',
    alsoContains: "'border-border-field'",
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
    if (collided === edge) continue; // HarnessSelect: colour is not in the fragment
    it(`${control}: its edge is not back on the ordinary border`, () => {
      expect(read(file)).not.toContain(collided);
    });
  }

  // The fill half, which no token search can express: what makes a fill wrong is
  // the fill of the thing UNDER it, which is not in the class string.
  for (const { file, control, on, edge, fill, containerFill } of FIELDS) {
    const collided = edge.replace(fill, containerFill);
    it(`${control}: its fill is not the same as ${on}`, () => {
      expect(read(file)).not.toContain(collided);
    });
  }
});
