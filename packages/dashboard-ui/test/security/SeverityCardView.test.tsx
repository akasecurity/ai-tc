import type { SeveritySummaryItem } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { SeverityCardView } from '../../src/security/SeverityCardView.tsx';
import { statusHrefKey } from '../../src/security/status-columns.ts';

// The card is a severity x status matrix. The status buckets are disjoint, so each
// row sums to its `count` and the grand total is the sum of the rows.
const bySeverity: SeveritySummaryItem[] = [
  {
    severity: 'critical',
    count: 10,
    openAtRest: 3,
    caught: 6,
    handled: 4,
    resolved: 2,
    dismissed: 1,
  },
  {
    severity: 'high',
    count: 20,
    openAtRest: 0,
    caught: 18,
    handled: 11,
    resolved: 7,
    dismissed: 2,
  },
  { severity: 'medium', count: 0, openAtRest: 0, caught: 0, handled: 0, resolved: 0, dismissed: 0 },
  { severity: 'low', count: 5, openAtRest: 4, caught: 1, handled: 0, resolved: 1, dismissed: 0 },
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

function cell(html: string, id: string): string {
  const m = new RegExp(`data-cell="${id}"[^>]*>(.*?)</td>`).exec(html);
  expect(m, `cell ${id} not found`).not.toBeNull();
  return [...(m?.[1] ?? '').matchAll(/>([^<]+)</g)].map((t) => t[1]).join('');
}

function cellHtml(html: string, id: string): string {
  return new RegExp(`data-cell="${id}"[^>]*>(.*?)</td>`).exec(html)?.[1] ?? '';
}

describe('SeverityCardView', () => {
  it('titles itself by both axes and states the exact total', () => {
    const html = render();
    expect(html).toContain('Findings by severity and status');
    expect(html).toContain('35 findings');
  });

  it('renders a status column per bucket, with an All column and row', () => {
    const html = render();
    for (const label of ['Open', 'Handled', 'Resolved', 'Dismissed', 'All']) {
      expect(html).toContain(`>${label}<`);
    }
  });

  it('places each bucket under its own column and severity', () => {
    const html = render();
    expect(cell(html, 'critical-open')).toBe('3');
    expect(cell(html, 'critical-handled')).toBe('4');
    expect(cell(html, 'critical-resolved')).toBe('2');
    expect(cell(html, 'critical-dismissed')).toBe('1');
    expect(cell(html, 'high-handled')).toBe('11');
    expect(cell(html, 'high-resolved')).toBe('7');
    expect(cell(html, 'low-open')).toBe('4');
  });

  it('sums the column totals from the rows', () => {
    // open 3+0+0+4=7, handled 4+11=15, resolved 2+7+1=10, dismissed 1+2=3
    const html = render();
    expect(html).toContain('>7<');
    expect(html).toContain('>15<');
    expect(html).toContain('>10<');
    expect(html).toContain('>3<');
  });

  it('shades a non-zero cell and leaves a zero cell unshaded', () => {
    const html = render();
    expect(html).toMatch(/data-cell="high-handled"[^>]*color-mix/);
    expect(html).not.toMatch(/data-cell="medium-open"[^>]*color-mix/);
  });

  it('omits the status columns on a count-only response', () => {
    const html = render({
      bySeverity: bySeverity.map(({ severity, count }) => ({ severity, count })),
    });
    expect(html).not.toContain('>Open<');
    expect(html).not.toContain('data-cell=');
    expect(html).toContain('>20<');
  });

  it('falls back to one Caught column when the response has no handled/resolved split', () => {
    const html = render({
      bySeverity: bySeverity.map(({ severity, count, caught, openAtRest, dismissed }) => ({
        severity,
        count,
        caught,
        openAtRest,
        dismissed,
      })),
    });
    expect(html).toContain('>Caught<');
    expect(html).not.toContain('>Handled<');
    expect(html).not.toContain('>Resolved<');
    expect(cell(html, 'critical-caught')).toBe('6');
  });

  it('has no count / percent toggle', () => {
    expect(render()).not.toContain('aria-pressed');
  });

  it('reports an empty store', () => {
    const html = render({ bySeverity: bySeverity.map((s) => ({ ...s, count: 0 })), total: 0 });
    expect(html).toContain('No findings.');
    expect(html).not.toContain('<table');
  });

  it('links a non-zero status cell to its href and leaves a zero cell as text', () => {
    const html = render({
      statusHrefs: {
        [statusHrefKey('critical', 'open')]: '/findings?status=open',
        [statusHrefKey('medium', 'open')]: '/findings?status=medium-open',
      },
    });
    expect(cellHtml(html, 'critical-open')).toContain('href="/findings?status=open"');
    // The host supplied a link for medium/open, but its count is 0.
    expect(cellHtml(html, 'medium-open')).not.toContain('<a ');
    expect(html).not.toContain('status=medium-open');
  });

  it('links nothing when the host supplies no status hrefs', () => {
    expect(cellHtml(render(), 'critical-open')).not.toContain('<a ');
  });

  it('links the footer and grand total from the same map, and the row total from severityHrefs', () => {
    const html = render({
      severityHrefs: { critical: '/findings?severity=critical' },
      statusHrefs: {
        [statusHrefKey('all', 'open')]: '/findings?status=open',
        [statusHrefKey('all', 'all')]: '/findings',
      },
    });
    expect(html).toContain('href="/findings?severity=critical"');
    expect(html).toContain('href="/findings?status=open"');
    expect(html).toContain('href="/findings"');
  });

  it('shows a five-digit count short with the exact figure on its title', () => {
    const big: SeveritySummaryItem[] = [
      {
        severity: 'critical',
        count: 12345,
        openAtRest: 12345,
        handled: 0,
        resolved: 0,
        dismissed: 0,
      },
      { severity: 'high', count: 9999, openAtRest: 9999, handled: 0, resolved: 0, dismissed: 0 },
      { severity: 'medium', count: 0, openAtRest: 0, handled: 0, resolved: 0, dismissed: 0 },
      { severity: 'low', count: 0, openAtRest: 0, handled: 0, resolved: 0, dismissed: 0 },
    ];
    const html = render({ bySeverity: big, total: 22344 });
    // Short for the eye, exact for assistive tech and on hover.
    expect(cellHtml(html, 'critical-open')).toContain('<span aria-hidden="true">12k</span>');
    expect(cellHtml(html, 'critical-open')).toContain('<span class="sr-only">12,345</span>');
    expect(cellHtml(html, 'critical-open')).toContain('title="12,345"');
    // Under the threshold stays exact, with no title.
    expect(cell(html, 'high-open')).toBe('9,999');
    expect(cellHtml(html, 'high-open')).not.toContain('title=');
    // The subtitle keeps the exact total.
    expect(html).toContain('22,344 findings');
  });

  it('never rounds a non-zero cell down to an invisible tint', () => {
    const skewed: SeveritySummaryItem[] = [
      { severity: 'critical', count: 1, openAtRest: 1, handled: 0, resolved: 0, dismissed: 0 },
      { severity: 'high', count: 5000, openAtRest: 0, handled: 5000, resolved: 0, dismissed: 0 },
      { severity: 'medium', count: 0, openAtRest: 0, handled: 0, resolved: 0, dismissed: 0 },
      { severity: 'low', count: 0, openAtRest: 0, handled: 0, resolved: 0, dismissed: 0 },
    ];
    const html = render({ bySeverity: skewed, total: 5001 });
    // 1 of 5000 is 0.01% of the maximum: it must still carry a tint above 0%.
    const m = /data-cell="critical-open"[^>]*color-mix\(in srgb, [^%]*? (\d+)%/.exec(html);
    expect(m, 'the tiny cell carries no tint').not.toBeNull();
    expect(Number(m?.[1])).toBeGreaterThan(0);
    // The control: a zero cell in the same table carries none.
    expect(html).not.toMatch(/data-cell="critical-handled"[^>]*color-mix/);
  });

  it('loads as a table-shaped skeleton: four severity rows, the status columns and a footer', () => {
    const html = render({ isLoading: true, bySeverity: [], total: 0 });
    expect(html).toContain('Loading…');
    expect(html).toContain('aria-busy="true"');
    // 5 header + (4 rows x (label + 4 cells + total)) + footer (label + 4 + total)
    expect(html.split('data-slot="skeleton"').length - 1).toBe(5 + 4 * 6 + 6);
    expect((html.match(/<tr/g) ?? []).length).toBe(1 + 4 + 1);
    // Nothing that looks like data.
    expect(html).not.toContain('data-cell=');
    expect(html).not.toContain('No findings.');
  });
});
