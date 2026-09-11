import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import {
  type FindingsChartPoint,
  FindingsOverTimeCardView,
} from '../../src/security/FindingsOverTimeCardView.tsx';

// The chart plots all four severities. Low used to be excluded by contract while
// the MTTR trend directly beneath it plotted all four, so the same store read two
// different ways on one page.

function point(over: Partial<FindingsChartPoint> = {}): FindingsChartPoint {
  return { label: 'Jul 1', critical: 0, high: 0, medium: 0, low: 0, ...over };
}

function render(points: FindingsChartPoint[]) {
  return renderToStaticMarkup(
    <FindingsOverTimeCardView points={points} isLoading={false} error={null} />,
  );
}

describe('FindingsOverTimeCardView', () => {
  it('lists Low in the legend beside the other three', () => {
    const html = render([point({ critical: 1 })]);
    for (const label of ['Critical', 'High', 'Medium', 'Low']) {
      expect(html).toContain(label);
    }
  });

  it('plots a range holding only low-severity findings', () => {
    // The empty check used to sum critical+high+medium, so a range with nothing but
    // low-severity findings rendered "No findings" over real data.
    const html = render([point({ low: 3 })]);
    expect(html).not.toContain('No findings in this range.');
  });

  it('reports an empty range as empty when a producer omits `low` entirely', () => {
    // `low` is optional on the wire and this package ships to hosts whose types are
    // erased, so a three-series producer reaches this component. Adding an absent
    // `low` yields NaN, and `NaN === 0` is false — the range would render as
    // populated, with four flat zero lines where the empty state belongs.
    const threeSeries = [
      { label: 'Jul 1', critical: 0, high: 0, medium: 0 },
    ] as FindingsChartPoint[];
    expect(render(threeSeries)).toContain('No findings in this range.');
  });

  it('still reports a genuinely empty range as empty', () => {
    // The positive control for the case above: without it, a check that never
    // reports empty would satisfy that assertion too.
    expect(render([point()])).toContain('No findings in this range.');
  });
});
