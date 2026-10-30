// @vitest-environment jsdom
//
// SEVERITY_DASH is only worth anything if it REACHES the pixels, in both places
// that have to agree: the line in the chart and the chip in the legend that says
// which line it is. A table guarded only by severity-channel.test.ts stays green
// while neither renders it.
//
// AreaChart gates its <svg> on a measured width from a ResizeObserver, which
// jsdom does not implement, so the observer is stubbed to report one. Without it
// the chart renders nothing and every assertion about a line would hold
// vacuously — which `every severity line has geometry` is here to catch.
import { act } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { COLORS } from '../../src/lib/colors.ts';
import {
  type FindingsChartPoint,
  FindingsOverTimeCardView,
} from '../../src/security/FindingsOverTimeCardView.tsx';
import { SEVERITY_DASH } from '../../src/security/meta.ts';
import { type MttrChartPoint, MttrTrendCardView } from '../../src/security/MttrTrendCardView.tsx';
import { dashMask } from '../../src/shared/dash.ts';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const HOUR_MS = 60 * 60 * 1000;

const FINDINGS: FindingsChartPoint[] = [
  { label: 'Jul 1', critical: 3, high: 5, medium: 8, low: 13 },
  { label: 'Jul 2', critical: 2, high: 4, medium: 6, low: 11 },
];

const MTTR: MttrChartPoint[] = [
  {
    label: 'Jul 1',
    critical: 2 * HOUR_MS,
    high: 5 * HOUR_MS,
    medium: 9 * HOUR_MS,
    low: 26 * HOUR_MS,
  },
  {
    label: 'Jul 2',
    critical: 1 * HOUR_MS,
    high: 4 * HOUR_MS,
    medium: 7 * HOUR_MS,
    low: 25 * HOUR_MS,
  },
];

const SEVERITIES = [
  { key: 'critical', label: 'Critical', stroke: COLORS.sevCritical },
  { key: 'high', label: 'High', stroke: COLORS.sevHigh },
  { key: 'medium', label: 'Medium', stroke: COLORS.sevMedium },
  { key: 'low', label: 'Low', stroke: COLORS.sevLow },
] as const;

const MEASURED_WIDTH = 600;

class StubResizeObserver {
  constructor(private readonly cb: ResizeObserverCallback) {}
  observe(): void {
    this.cb([{ contentRect: { width: MEASURED_WIDTH } } as ResizeObserverEntry], this);
  }
  unobserve(): void {
    // Nothing to release: the callback fires once, from `observe`.
  }
  disconnect(): void {
    // Nothing to release: the callback fires once, from `observe`.
  }
}

let mounted: MountedRoot;

/** Both cards, so a dash wired into one of them only goes red here. */
const CARDS = {
  'findings over time': (
    <FindingsOverTimeCardView points={FINDINGS} granularity="day" isLoading={false} error={null} />
  ),
  'time to remediate': <MttrTrendCardView points={MTTR} isLoading={false} error={null} />,
} as const;

/** The same two cards with no chart to toggle, which renders the static legend. */
const STATIC_CARDS = {
  'findings over time': (
    <FindingsOverTimeCardView points={[]} granularity="day" isLoading error={null} />
  ),
  'time to remediate': <MttrTrendCardView points={[]} isLoading error={null} />,
} as const;

/** The line for one severity, found by the stroke the chart paints it with. */
function linePath(stroke: string): SVGPathElement {
  const el = mounted.host.querySelector<SVGPathElement>(`svg path[stroke="${stroke}"]`);
  if (!el) throw new Error(`no line for stroke ${stroke}`);
  return el;
}

/** The chip inside one legend entry (the first span; any value follows). */
function swatch(label: string): HTMLElement {
  const button = [...mounted.host.querySelectorAll('button')].find((b) =>
    (b.getAttribute('title') ?? '').includes(label),
  );
  if (!button) throw new Error(`no legend entry for ${label}`);
  const el = button.querySelector('span');
  if (!el) throw new Error(`no chip for ${label}`);
  return el;
}

/**
 * Drive the chart's hover so the tooltip renders.
 *
 * Scoped to the chart's own container: a bare `querySelector('svg')` over the
 * card returns the CardIcon's glyph, which is the first <svg> in the header and
 * carries no handler, so the move lands on nothing and the tooltip never opens.
 * jsdom reports a zero-sized rect, which leaves `clientX` as the whole offset.
 */
function hover(): void {
  const svg = mounted.host.querySelector('div.relative > svg');
  if (!svg) throw new Error('no chart svg to hover');
  act(() => {
    svg.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: 300 }));
  });
}

/**
 * The tooltip's per-series rows (the chip + name + value lines).
 *
 * Scoped to the tooltip itself, and throws without one. A bare
 * `div.flex.items-center` sweep over the card also matches `CardHeader`, whose
 * legend carries all four severity names — so a row test written that way
 * passes with no tooltip on screen at all.
 */
function tooltipRows(): HTMLElement[] {
  const tip = mounted.host.querySelector('div.pointer-events-none.absolute');
  if (!tip) throw new Error('no tooltip on screen');
  return [...tip.querySelectorAll<HTMLElement>('div.flex.items-center')];
}

/** The px offsets in a mask, which survive jsdom's rewrite of the colours. */
function maskOffsets(mask: string): string[] {
  return [...mask.matchAll(/(\d+(?:\.\d+)?)px/g)].map((m) => m[1] ?? '');
}

describe.each(Object.entries(CARDS))('the %s chart carries a non-colour channel', (_name, card) => {
  beforeEach(() => {
    globalThis.ResizeObserver = StubResizeObserver;
    mounted = mountRoot();
    renderRoot(mounted.root, card);
  });

  afterEach(() => {
    unmountMountedRoot(mounted);
  });

  it('every severity line has geometry', () => {
    // The control for the two cases below. A chart that measured no width emits
    // no <svg> at all, and one handed empty data emits a <path> with no `d` —
    // either way a missing dash would read as a passing one.
    for (const { stroke } of SEVERITIES) {
      expect(linePath(stroke).getAttribute('d') ?? '').not.toBe('');
    }
  });

  it.each(SEVERITIES)('dashes the $label line as the table says', ({ key, stroke }) => {
    const expected = SEVERITY_DASH[key];
    const actual = linePath(stroke).getAttribute('stroke-dasharray');
    // `critical` is the solid series, so the ABSENCE of the attribute is the
    // assertion there — not a value, and not an empty string, which would draw
    // a dashed line of zero-length dashes.
    expect(actual).toBe(expected ?? null);
  });

  it('names every series in the hover tooltip', () => {
    // The tooltip is the one surface where a reader is given NUMBERS, and it
    // used to render a chip and a value with no series name — leaving the hue,
    // 1.03:1 at its worst, as the only thing saying which number was critical.
    hover();
    const rows = tooltipRows();
    expect(rows.length).toBeGreaterThan(0);
    for (const { label } of SEVERITIES) {
      expect(rows.some((r) => r.textContent.includes(label))).toBe(true);
    }
  });

  it.each(SEVERITIES)('carries the $label pattern into the tooltip chip', ({ key, label }) => {
    hover();
    const row = tooltipRows().find((r) => r.textContent.includes(label));
    if (!row) throw new Error(`no tooltip row for ${label}`);
    const chip = row.querySelector('span');
    if (!chip) throw new Error(`no tooltip chip for ${label}`);
    const dash = SEVERITY_DASH[key];
    if (dash === undefined) {
      expect(chip.style.maskImage).toBe('');
      return;
    }
    const pattern = dashMask(dash);
    if (pattern === undefined) throw new Error(`${key} has an unparseable dash: ${dash}`);
    expect(maskOffsets(chip.style.maskImage)).toEqual(maskOffsets(pattern));
  });

  it.each(SEVERITIES)('gives the $label chip the same pattern as its line', ({ key, label }) => {
    const mask = swatch(label).style.maskImage;
    const dash = SEVERITY_DASH[key];
    if (dash === undefined) {
      // A solid series' chip is a plain filled rule: a mask here would punch
      // gaps the line does not have.
      expect(mask).toBe('');
      return;
    }
    const pattern = dashMask(dash);
    if (pattern === undefined) throw new Error(`${key} has an unparseable dash: ${dash}`);
    // Compared by offsets rather than by string: jsdom rewrites `#000` to
    // `rgb(0, 0, 0)`, so the two spellings never match literally.
    expect(maskOffsets(mask)).toEqual(maskOffsets(pattern));
    expect(maskOffsets(mask).length).toBeGreaterThan(0);
  });
});

/**
 * The legend's STATIC entries, which render while the chart is loading, errored
 * or empty. A card's header renders above all three, so these spans — not the
 * toggle buttons above — are what a reader sees for as long as there is no
 * chart, and they are a separate call site that the interactive cases cannot
 * reach.
 */
function staticChip(label: string): HTMLElement {
  const entry = [...mounted.host.querySelectorAll('span.inline-flex')].find((s) =>
    s.textContent.startsWith(label),
  );
  if (!entry) throw new Error(`no static legend entry for ${label}`);
  const el = entry.querySelector('span');
  if (!el) throw new Error(`no static chip for ${label}`);
  return el;
}

describe.each(Object.entries(STATIC_CARDS))(
  'the %s legend carries the channel with no chart on screen',
  (_name, card) => {
    beforeEach(() => {
      globalThis.ResizeObserver = StubResizeObserver;
      mounted = mountRoot();
      renderRoot(mounted.root, card);
    });

    afterEach(() => {
      unmountMountedRoot(mounted);
    });

    it('renders every severity as a static entry, not a toggle', () => {
      // The control: with a chart on screen the legend renders BUTTONS, and
      // `staticChip` would throw rather than read the wrong element — but a
      // legend that rendered nothing at all would make the cases below vacuous.
      expect(mounted.host.querySelectorAll('button')).toHaveLength(0);
      for (const { label } of SEVERITIES) expect(staticChip(label)).toBeTruthy();
    });

    it.each(SEVERITIES)('gives the static $label chip its pattern', ({ key, label }) => {
      const mask = staticChip(label).style.maskImage;
      const dash = SEVERITY_DASH[key];
      if (dash === undefined) {
        expect(mask).toBe('');
        return;
      }
      const pattern = dashMask(dash);
      if (pattern === undefined) throw new Error(`${key} has an unparseable dash: ${dash}`);
      expect(maskOffsets(mask)).toEqual(maskOffsets(pattern));
      expect(maskOffsets(mask).length).toBeGreaterThan(0);
    });
  },
);

describe('a server render carries the channel too', () => {
  // The Security page renders these cards on the server, so the dash has to be
  // in the first paint rather than arriving with hydration. This reads the
  // legend chip, which needs no measured width.
  it.each(Object.entries(CARDS))('%s', (_name, card) => {
    const html = renderToStaticMarkup(card);
    for (const { key } of SEVERITIES) {
      const dash = SEVERITY_DASH[key];
      if (dash === undefined) continue;
      const pattern = dashMask(dash);
      if (pattern === undefined) throw new Error(`${key} has an unparseable dash: ${dash}`);
      for (const offset of maskOffsets(pattern)) {
        expect(html).toContain(`${offset}px`);
      }
    }
  });
});

describe('dashMask', () => {
  it('turns a dasharray into the gaps it describes', () => {
    expect(dashMask('7 3')).toBe(
      'repeating-linear-gradient(90deg, #000 0px 7px, transparent 7px 10px)',
    );
  });

  it('repeats an odd-length array the way SVG does', () => {
    // SVG treats '5' as five on, five off. A mask built from the array as given
    // would be one stop long and paint the chip solid, losing the pattern that
    // identifies the series.
    expect(dashMask('5')).toBe(
      'repeating-linear-gradient(90deg, #000 0px 5px, transparent 5px 10px)',
    );
  });

  it('accepts the comma spelling of a dasharray', () => {
    expect(dashMask('7,3')).toBe(dashMask('7 3'));
  });

  it('falls back to a solid chip on a pattern it cannot read', () => {
    // An empty mask would hide the chip altogether, which is worse than losing
    // the pattern: the entry would lose its colour as well.
    expect(dashMask('')).toBeUndefined();
    expect(dashMask('fat thin')).toBeUndefined();
    expect(dashMask('-4 2')).toBeUndefined();
  });

  it('refuses an all-zero dasharray', () => {
    // CSS renders a repeating gradient whose stops are zero apart as a solid of
    // its LAST stop — `transparent` here — so this would hide the chip rather
    // than pattern it, while SVG ignores the dasharray and draws a solid line.
    expect(dashMask('0 0')).toBeUndefined();
    expect(dashMask('0')).toBeUndefined();
    expect(dashMask('0 0 0 0')).toBeUndefined();
    // A zero that is only PART of the cycle still draws, so the guard must not
    // reject any array merely containing a zero.
    expect(dashMask('0 4')).toBeDefined();
  });
});
