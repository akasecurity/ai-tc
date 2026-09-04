import type { ResolvedFeedItem } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { RecentlyResolvedCardView } from '../../src/security/RecentlyResolvedCardView.tsx';

// The resolved feed measures each row's age against the instant the card was
// handed, and the card reaches that row through a pass-down (`renderedAt` onto
// `ResolvedRow`) that nothing else covers — the security page composes this
// view, and the page's own suite asserts the prop reaches the view, not what
// the view does with it.
const RENDERED_AT = Date.parse('2026-07-05T12:00:00.000Z');

// Four hours before RENDERED_AT, and far enough from any real clock that a row
// falling back to `Date.now()` cannot coincidentally read the same label.
const RESOLVED_AT = '2026-07-05T08:00:00.000Z';

function item(over: Partial<ResolvedFeedItem> = {}): ResolvedFeedItem {
  return {
    findingKey: 'fk-1',
    ruleId: 'aws-key',
    severity: 'critical',
    path: 'src/db.ts',
    resolvedAt: RESOLVED_AT,
    detectedAt: '2026-07-01T00:00:00.000Z',
    ...over,
  };
}

function render(props: Partial<Parameters<typeof RecentlyResolvedCardView>[0]> = {}) {
  return renderToStaticMarkup(
    <RecentlyResolvedCardView
      renderedAt={RENDERED_AT}
      items={[item()]}
      isLoading={false}
      error={null}
      {...props}
    />,
  );
}

describe('RecentlyResolvedCardView', () => {
  it('measures a row against the instant the card was handed', () => {
    const html = render();

    expect(html).toContain('4 hours ago');
  });

  it('measures every row against that same instant', () => {
    const html = render({
      items: [item(), item({ findingKey: 'fk-2', resolvedAt: '2026-07-03T12:00:00.000Z' })],
    });

    expect(html).toContain('4 hours ago');
    expect(html).toContain('2 days ago');
  });

  it('is a fixture the ambient clock could not produce', () => {
    // The control: both cases above assert SHORT ages, which is exactly what a
    // row reading `Date.now()` stops producing once the fixtures age. Pin that
    // the fixture really is far from now, or a regression to the ambient clock
    // would pass on any machine whose date sat near it.
    expect(Math.abs(Date.now() - Date.parse(RESOLVED_AT))).toBeGreaterThan(
      30 * 24 * 60 * 60 * 1000,
    );
  });
});
