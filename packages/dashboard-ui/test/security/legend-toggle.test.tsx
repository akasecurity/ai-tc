// @vitest-environment jsdom
//
// The legend on the two Security-page trend charts toggles its series in the
// chart, so the property under test is what the CHART draws after a click —
// invisible to a server render, which dispatches no events.
//
// AreaChart gates its <svg> on a measured width from a ResizeObserver, which
// jsdom does not implement, so the observer is stubbed to report one. Without
// it the chart renders nothing at all and every assertion below about a
// plotted series would hold vacuously.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { COLORS } from '../../src/lib/colors.ts';
import {
  type FindingsChartPoint,
  FindingsOverTimeCardView,
} from '../../src/security/FindingsOverTimeCardView.tsx';
import { type MttrChartPoint, MttrTrendCardView } from '../../src/security/MttrTrendCardView.tsx';
import { SeriesLegend, useSeriesVisibility } from '../../src/shared/SeriesLegend.tsx';

const HOUR_MS = 60 * 60 * 1000;

// Every severity carries data in every bucket, so a series missing from the
// chart can only be one the legend hid — never one the data never had.
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

const SEVERITY_STROKES = {
  Critical: COLORS.sevCritical,
  High: COLORS.sevHigh,
  Medium: COLORS.sevMedium,
  Low: COLORS.sevLow,
} as const;

type SeverityLabel = keyof typeof SEVERITY_STROKES;
const ALL: SeverityLabel[] = ['Critical', 'High', 'Medium', 'Low'];

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

let host: HTMLDivElement;
let root: Root;

function mount(ui: React.ReactElement): void {
  act(() => {
    root.render(ui);
  });
}

/** The legend entry for one severity, found by the title the toggle writes. */
function legendButton(label: SeverityLabel): HTMLButtonElement {
  const match = [...host.querySelectorAll('button')].find((b) =>
    (b.getAttribute('title') ?? '').includes(label),
  );
  if (!match) throw new Error(`no legend entry for ${label}`);
  return match;
}

function click(label: SeverityLabel): void {
  const button = legendButton(label);
  act(() => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
}

/**
 * The severities the chart was HANDED, read off the line strokes.
 *
 * Not the same as what visibly draws: a series whose every value is null still
 * emits its <path>, with no `d` to render. That is the right reading for a
 * toggle (hiding removes the element outright) and the wrong one for asking
 * whether a line appears.
 */
function plotted(): SeverityLabel[] {
  return ALL.filter(
    (label) => host.querySelector(`svg path[stroke="${SEVERITY_STROKES[label]}"]`) !== null,
  );
}

/**
 * The severities whose line actually has geometry. `plotted()` says which
 * series the chart was handed; this says whether any of them received data,
 * which is the half an empty `data` array would otherwise satisfy silently.
 */
function drawn(): SeverityLabel[] {
  return ALL.filter((label) => {
    const path = host.querySelector(`svg path[stroke="${SEVERITY_STROKES[label]}"]`);
    return (path?.getAttribute('d') ?? '') !== '';
  });
}

/** The colour chip inside one legend entry (the first span; any value follows). */
function swatch(label: SeverityLabel): HTMLElement {
  const el = legendButton(label).querySelector('span');
  if (!el) throw new Error(`no swatch for ${label}`);
  return el;
}

describe('chart legend toggles', () => {
  beforeEach(() => {
    (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
      true;
    globalThis.ResizeObserver = StubResizeObserver;
    host = document.createElement('div');
    document.body.append(host);
    root = createRoot(host);
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    host.remove();
  });

  it('plots every severity before anything is clicked', () => {
    // The positive control for every assertion below: without it, a chart that
    // drew nothing (a ResizeObserver stub that stopped reporting a width, say)
    // would satisfy each "no longer plotted" case vacuously.
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    expect(plotted()).toEqual(ALL);
  });

  it('hands the chart the points it was given, not an empty series', () => {
    // `plotted()` alone is blind to this: a series with no data still emits its
    // <path>, so every toggle assertion here passes against an empty chart.
    mount(<MttrTrendCardView points={MTTR} isLoading={false} error={null} />);
    expect(drawn()).toEqual(ALL);

    click('Critical');
    expect(drawn()).toEqual(['High', 'Medium', 'Low']);
  });

  it('hollows out a hidden severity swatch', () => {
    // The chip keeps the series' colour as a ring rather than a fill, which is
    // what tells a reader WHICH series is hidden rather than merely that one is.
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    expect(swatch('Critical').style.boxShadow).toBe('');
    expect(swatch('Critical').style.background).not.toBe('transparent');

    click('Critical');

    expect(swatch('Critical').style.boxShadow).toContain('inset');
    expect(swatch('Critical').style.background).toBe('transparent');
    // A neighbour is untouched, so the case cannot pass on a legend that
    // hollowed every swatch at once.
    expect(swatch('High').style.boxShadow).toBe('');
  });

  it('never dims an operable entry with alpha', () => {
    // P1. `opacity` composites the text against the card, and no alpha
    // survives 4.5:1 here — even 0.95 lands at 4.49:1. WCAG 1.4.3's carve-out
    // is for an INACTIVE component; a hidden entry is the operable control
    // that brings its series back, which `puts a hidden severity back …`
    // proves. (Whether the TOKEN is dark enough is a separate guard, in
    // legend-contrast.test.ts — neither can see the other's failure.)
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    click('Critical');

    expect(legendButton('Critical').className).not.toMatch(/(^|[:\s])opacity-\d+/);
    // The de-emphasis is still THERE, just carried by a token — without this
    // the case passes on a legend that marks a hidden entry not at all.
    expect(legendButton('Critical').className).toContain('text-text-3');

    // And the entry that genuinely cannot be actioned is not the dimmed one.
    click('High');
    click('Medium');
    expect(legendButton('Low').className).not.toMatch(/(^|[:\s])opacity-\d+/);
  });

  it('names the locked entry with the reason it will not respond', () => {
    // P2. `title` is demoted to the accessible DESCRIPTION once `aria-label`
    // is set, and needs a pointer besides — so the reason has to ride the NAME.
    mount(<MttrTrendCardView points={MTTR} isLoading={false} error={null} />);
    click('Critical');
    click('High');
    click('Medium');

    expect(legendButton('Low').getAttribute('aria-label')).toBe('Low, 1d 1h, only series left');
    // An operable entry must NOT carry it, or the name says the opposite of
    // the truth on every other entry.
    click('Critical');
    expect(legendButton('Low').getAttribute('aria-label')).toBe('Low, 1d 1h');
  });

  it('removes a severity from the chart when its legend entry is clicked', () => {
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    click('Critical');

    expect(plotted()).toEqual(['High', 'Medium', 'Low']);
    expect(legendButton('Critical').getAttribute('aria-pressed')).toBe('false');
    // The entry stays in the legend, or a hidden series could never be restored.
    expect(legendButton('Critical').getAttribute('title')).toBe('Show Critical');
  });

  it('puts a hidden severity back when its legend entry is clicked again', () => {
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    click('Medium');
    expect(plotted()).not.toContain('Medium');

    click('Medium');
    expect(plotted()).toEqual(ALL);
    expect(legendButton('Medium').getAttribute('aria-pressed')).toBe('true');
  });

  it('refuses to hide the last visible severity', () => {
    // An empty chart is a view of nothing: the grid renders over a y-scale with
    // no data behind it and the tooltip degrades to a bare date.
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    click('Critical');
    click('High');
    click('Medium');
    expect(plotted()).toEqual(['Low']);

    click('Low');

    expect(plotted()).toEqual(['Low']);
    expect(legendButton('Low').getAttribute('aria-pressed')).toBe('true');
    // Marked with aria-disabled rather than `disabled`, so the entry keeps its
    // focus stop and can still explain itself.
    expect(legendButton('Low').getAttribute('aria-disabled')).toBe('true');
    expect(legendButton('Low').hasAttribute('disabled')).toBe(false);
  });

  it('leaves the range empty-state alone — hiding a series is not "no findings"', () => {
    // The empty state describes the RANGE, not the current filter.
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    click('Critical');
    expect(host.textContent).not.toContain('No findings in this range.');
  });

  // A card header renders above its loading, error and empty states, so the
  // legend outlives the chart. Offering a control there is offering one that
  // visibly does nothing. One case per state rather than one case driving all
  // three: sharing a body means the first failure hides the rest, and sharing
  // a root means React keeps the previous card's visibility state.
  const NO_CHART_STATES: { name: string; view: React.ReactElement }[] = [
    {
      name: 'loading',
      view: <FindingsOverTimeCardView points={FINDINGS} granularity="day" isLoading error={null} />,
    },
    {
      name: 'error',
      view: (
        <FindingsOverTimeCardView
          points={FINDINGS}
          granularity="day"
          isLoading={false}
          error="Store unreadable"
        />
      ),
    },
    {
      name: 'empty',
      view: (
        <MttrTrendCardView
          points={[{ label: 'Jul 1', critical: null, high: null, medium: null, low: null }]}
          isLoading={false}
          error={null}
        />
      ),
    },
  ];

  it.each(NO_CHART_STATES)('offers no toggles in the $name state', ({ view }) => {
    mount(view);

    expect(host.querySelectorAll('button')).toHaveLength(0);
    // The legend is still THERE — it just stops being interactive. Without
    // this the case would pass on a card that rendered no legend at all.
    expect(host.textContent).toContain('Critical');
  });

  it('still reports each severity latest value while no chart is on screen', () => {
    // The static branch renders the same trailing values the interactive one
    // does. Nothing else reaches that branch's `MetaText`, so without this the
    // line can be deleted with the whole suite staying green.
    mount(<MttrTrendCardView points={MTTR} isLoading error={null} />);

    expect(host.querySelectorAll('button')).toHaveLength(0);
    expect(host.textContent).toContain('1d 1h');
  });

  it('toggles the same way on the time-to-remediate chart', () => {
    mount(<MttrTrendCardView points={MTTR} isLoading={false} error={null} />);
    expect(plotted()).toEqual(ALL);

    click('High');

    expect(plotted()).toEqual(['Critical', 'Medium', 'Low']);
    expect(host.textContent).not.toContain('No resolved findings in this range.');
  });

  it('keeps each severity latest value in the legend while it is hidden', () => {
    // The legend's trailing value reads the latest bucket, which the toggle does
    // not filter — a hidden series still reports where it stands.
    mount(<MttrTrendCardView points={MTTR} isLoading={false} error={null} />);
    click('Low');

    expect(legendButton('Low').textContent).toContain('1d 1h');
  });

  it('plots a range whose only resolutions are low-severity', () => {
    // `isEmpty` is derived from MTTR_SERIES rather than hand-listing the four
    // severities. Drop one from that walk and a range carrying only that
    // severity renders the empty state over real data.
    mount(
      <MttrTrendCardView
        points={[{ label: 'Jul 1', critical: null, high: null, medium: null, low: 3 * HOUR_MS }]}
        isLoading={false}
        error={null}
      />,
    );

    expect(host.textContent).not.toContain('No resolved findings in this range.');
    expect(plotted()).toEqual(ALL);
  });

  it('names each entry so the label and its value are not run together', () => {
    // A button's accessible name is computed from its contents, and what
    // separates the label from the value visually is a flex `gap` rather than a
    // character — so the contents alone announce as "Low1d 1h".
    mount(<MttrTrendCardView points={MTTR} isLoading={false} error={null} />);

    // The defect, stated as the thing the name must NOT be. Without this the
    // case passes on any name at all, including the run-on one.
    expect(legendButton('Low').textContent).toBe('Low1d 1h');
    expect(legendButton('Low').getAttribute('aria-label')).toBe('Low, 1d 1h');

    // WCAG 2.5.3: the spoken name still contains the visible text, so a voice
    // user saying what they see reaches the same control.
    expect(legendButton('Low').getAttribute('aria-label')).toContain('Low');
  });

  it('names an entry by its label alone when the card has no trailing value', () => {
    // The findings chart passes no `metaLabel`, so a composed name would append
    // a stray separator to every entry.
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    expect(legendButton('Critical').getAttribute('aria-label')).toBe('Critical');
  });

  it('gives every legend entry a pointer cursor', () => {
    // Tailwind's preflight carries no button cursor rule, so a bare <button>
    // falls through to the UA's arrow. The class has to be spelled out, and
    // the locked entry's override has to survive the merge.
    //
    // This reads the CLASS, not the computed style: jsdom loads no stylesheet,
    // so it cannot tell a class that generates CSS from one that does not.
    // That half is only ever established by measuring `getComputedStyle` in a
    // real browser, which nothing here repeats — so a green run means the
    // class is present, never that the cursor is right.
    mount(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    expect(legendButton('Critical').className).toContain('cursor-pointer');
    expect(legendButton('Critical').className).not.toContain('cursor-default');

    click('Critical');
    click('High');
    click('Medium');

    // `cn` resolves the conflict last-wins, so the locked entry keeps only the
    // override — asserting its presence alone would pass on a class list
    // carrying both, where which one wins is whatever tailwind-merge decided.
    expect(legendButton('Low').className).toContain('cursor-default');
    expect(legendButton('Low').className).not.toContain('cursor-pointer');
    // The hover highlight is the other "a click does something" signal, so the
    // locked entry drops it too.
    expect(legendButton('Low').className).toContain('hover:bg-transparent');
    expect(legendButton('Low').className).not.toContain('hover:bg-surface-2');
  });
});

describe('chart legend trailing value', () => {
  const PROBE_SERIES = [
    { key: 'a', label: 'Alpha', color: 'var(--probe-a)' },
    { key: 'b', label: 'Beta', color: 'var(--probe-b)' },
  ];

  function LegendProbe({ metaLabel }: { metaLabel: (key: string) => string | null }) {
    const visibility = useSeriesVisibility(PROBE_SERIES);
    return (
      <SeriesLegend
        series={PROBE_SERIES}
        visibility={visibility}
        metaLabel={metaLabel}
        interactive
      />
    );
  }

  beforeEach(() => {
    (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
      true;
    host = document.createElement('div');
    document.body.append(host);
    root = createRoot(host);
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    host.remove();
  });

  it('treats an empty trailing value as nothing to report', () => {
    // `''` is the near-miss for a caller formatting an absent value. Left
    // unnormalized it composes an accessible name ending in a separator and
    // renders an empty styled span that still eats a flex `gap`.
    mount(<LegendProbe metaLabel={() => ''} />);

    const button = host.querySelector('button');
    expect(button?.getAttribute('aria-label')).toBe('Alpha');
    expect(host.querySelector('.text-text-3')).toBeNull();
  });

  it('composes the name from a trailing value that is present', () => {
    // The positive control: without it, a legend that dropped every trailing
    // value would satisfy the case above.
    mount(<LegendProbe metaLabel={() => '3h'} />);

    expect(host.querySelector('button')?.getAttribute('aria-label')).toBe('Alpha, 3h');
    expect(host.querySelector('.text-text-3')?.textContent).toBe('3h');
  });
});

describe('chart legend server render', () => {
  it('renders every severity pressed, so hydration reconciles against it', () => {
    // The first client render starts with nothing hidden; a server render that
    // disagreed would make React discard this markup on hydration.
    const html = renderToStaticMarkup(
      <FindingsOverTimeCardView
        points={FINDINGS}
        granularity="day"
        isLoading={false}
        error={null}
      />,
    );
    for (const label of ALL) {
      expect(html).toContain(`title="Hide ${label}"`);
    }
    expect(html).not.toContain('aria-pressed="false"');
    expect(html).not.toContain('aria-disabled');
  });
});
