import type { SeveritySummaryItem } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { SeverityCardView } from '../../src/security/SeverityCardView.tsx';

// The card reports ONE measure: findings by severity. The ring, the centre figure
// and the legend are three renderings of the same numbers.
//
// It used to carry a lifecycle cut too — a `caught` ring under a `caught` centre,
// above a "Needs remediation" row and a legend of TOTALS. Three populations in one
// card, and the row sat above the legend with a rule under it, so it read as a
// heading for rows that did not add up to it. These cases pin the collapse.

// Deliberately resolution-AWARE rows: `caught`/`openAtRest` are populated and must
// change nothing the card renders. With count-only fixtures every assertion below
// would hold whether or not the lifecycle branch came back.
const bySeverity: SeveritySummaryItem[] = [
  { severity: 'critical', count: 10, caught: 7, openAtRest: 3 },
  { severity: 'high', count: 20, caught: 20, openAtRest: 0 },
  { severity: 'medium', count: 0, caught: 0, openAtRest: 0 },
  { severity: 'low', count: 5, caught: 1, openAtRest: 4 },
];

function render(props: Partial<Parameters<typeof SeverityCardView>[0]> = {}) {
  return renderToStaticMarkup(
    <SeverityCardView
      bySeverity={bySeverity}
      total={35}
      isLoading={false}
      error={null}
      {...props}
    />,
  );
}

describe('SeverityCardView', () => {
  it('titles itself by severity, whatever lifecycle data the rows carry', () => {
    expect(render()).toContain('By severity');
  });

  it('shows no lifecycle framing at all', () => {
    const html = render();
    expect(html).not.toContain('Needs remediation');
    expect(html).not.toContain('caught');
    expect(html).not.toContain('Open by severity');
  });

  it('legends the per-severity totals, not the caught counts', () => {
    const html = render();
    // 7 / 20 / 1 are the `caught` values; 10 / 20 / 5 the totals. `high` is 20 in
    // BOTH, which is why the other two rows carry this assertion.
    expect(html).toContain('>10<');
    expect(html).toContain('>5<');
    expect(html).not.toContain('>7<');
  });

  it('centres the total, so the ring and the legend sum to the figure inside it', () => {
    // Deliberately past 999. The centre is COMPACT, and compactCount leaves anything
    // under 1,000 byte-identical to numberFormat — so against the shared 35-row
    // fixture this case reads the same whether the centre rounds or not, and a revert
    // to the unrounded figure passed the whole package suite. The legend moves in
    // step with the total, or the property this case is named for — ring, legend and
    // centre being one number — stops holding in its own fixture.
    const large: SeveritySummaryItem[] = [
      { severity: 'critical', count: 400, caught: 7, openAtRest: 393 },
      { severity: 'high', count: 600, caught: 600, openAtRest: 0 },
      { severity: 'medium', count: 0, caught: 0, openAtRest: 0 },
      { severity: 'low', count: 234, caught: 1, openAtRest: 233 },
    ];
    const html = render({ bySeverity: large, total: 1234 });
    expect(html).toContain('>1.2k<');
    // Both halves, because compactCount is LOSSY: asserting the ring alone lets the
    // exact figure go, and asserting the title alone lets the ring stop rounding.
    expect(html).toContain('title="1,234"');
  });

  it('centres a bare number, with no sub-label under the figure', () => {
    // Asserted STRUCTURALLY. Counting the word "findings" only catches a label that
    // happens to say "findings"; the label this replaced said "open" or "caught",
    // so that count stays at 1 and the regression it names sails through.
    //
    // The centre is the Donut's only child, so the figure element having no sibling
    // is the property — whatever a re-added label would say.
    const centre =
      /<div class="absolute inset-0 grid place-items-center text-center">(.*?)<\/div><\/div>/s.exec(
        render(),
      );
    expect(centre, 'the donut centre was not found — the markup shape changed').not.toBeNull();
    const inner = centre?.[1] ?? '';
    expect(inner).toContain('35');
    // One element in the centre, not two stacked.
    expect(inner.split('<div').length - 1).toBe(1);
  });

  it('sizes the ring by the totals, so changing only `caught` redraws nothing', () => {
    // The ring cannot be read by label: Donut emits `<path d= fill=>` inside an
    // aria-hidden wrapper and uses `label` solely as a React key, which is never
    // serialised. Asserting the four names would only re-read the LEGEND, and stays
    // green even against `segments={[]}`.
    //
    // So the property is asserted as invariance: hold `count` and move `caught`, and
    // every byte of the card must be identical. A ring fed from `caught` redraws its
    // arcs and fails here.
    const totals = render();
    const movedCaught = render({
      bySeverity: bySeverity.map((s) => ({ ...s, caught: 0, openAtRest: s.count })),
    });
    expect(movedCaught).toBe(totals);
    // The control: the ring IS sensitive to the numbers it is supposed to encode.
    const movedCounts = render({
      bySeverity: bySeverity.map((s) => ({ ...s, count: s.count + 1 })),
      total: 39,
    });
    expect(movedCounts).not.toBe(totals);
  });

  it('reports an empty store without a lifecycle qualifier', () => {
    const html = render({
      bySeverity: bySeverity.map((s) => ({ ...s, count: 0 })),
      total: 0,
    });
    expect(html).toContain('No findings.');
    expect(html).not.toContain('No open findings.');
  });
});
