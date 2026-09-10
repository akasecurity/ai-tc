import type {
  EnforcementAction,
  ResolvedFeedItem,
  SeveritySummaryItem,
  TopSource,
} from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { EnforcementCardView } from '../../src/security/EnforcementCardView.tsx';
import { RecentlyResolvedCardView } from '../../src/security/RecentlyResolvedCardView.tsx';
import { RecommendedActionsCardView } from '../../src/security/RecommendedActionsCardView.tsx';
import { SeverityCardView } from '../../src/security/SeverityCardView.tsx';
import { TopSourcesCardView } from '../../src/security/TopSourcesCardView.tsx';

// The widget deep links. This package renders the anchors but knows no router: a
// host passes href STRINGS, and a row with no href renders exactly what it rendered
// before the feature existed.
//
// Every case below is paired. The absence half ("renders no anchor") is worth
// nothing on its own — it passes trivially against a view that renders no anchor
// EVER — so each is written beside the presence half that would catch that.

const RENDERED_AT = Date.parse('2026-07-05T12:00:00.000Z');

function anchors(html: string): number {
  return html.split('<a ').length - 1;
}

describe('EnforcementCardView', () => {
  const actions: EnforcementAction[] = [{ kind: 'blocked', count: 42, delta: 3 }];
  const render = (props: Partial<Parameters<typeof EnforcementCardView>[0]> = {}) =>
    renderToStaticMarkup(
      <EnforcementCardView
        total={42}
        actions={actions}
        isLoading={false}
        error={null}
        rangeLabel="Last 7 days"
        {...props}
      />,
    );

  it('links a tile when the host supplies an href for its kind', () => {
    const html = render({ actionHrefs: { blocked: '/findings?action=blocked' } });
    expect(html).toContain('href="/findings?action=blocked"');
    expect(anchors(html)).toBe(1);
  });

  it('renders no anchor at all when the prop is omitted', () => {
    expect(anchors(render())).toBe(0);
  });

  it('leaves a kind with no entry unlinked', () => {
    const html = render({
      actions: [
        { kind: 'blocked', count: 42, delta: 0 },
        { kind: 'warned', count: 7, delta: 0 },
      ],
      actionHrefs: { blocked: '/findings?action=blocked' },
    });
    expect(anchors(html)).toBe(1);
  });

  it('keeps the tile a block-level flex item so three tiles stay equal width', () => {
    // An anchor is inline by default and this one holds block children; without an
    // explicit display it collapses the row it sits in. The class is the assertion
    // because the layout it protects is not observable in a string of markup.
    expect(render({ actionHrefs: { blocked: '/x' } })).toContain('block min-w-0 flex-1');
  });
});

describe('SeverityCardView', () => {
  const bySeverity: SeveritySummaryItem[] = [
    { severity: 'critical', count: 12 },
    { severity: 'high', count: 4 },
  ];
  const render = (props: Partial<Parameters<typeof SeverityCardView>[0]> = {}) =>
    renderToStaticMarkup(
      <SeverityCardView
        bySeverity={bySeverity}
        total={16}
        isLoading={false}
        error={null}
        {...props}
      />,
    );

  it('links a legend row when the host supplies an href', () => {
    const html = render({ severityHrefs: { critical: '/findings?severity=critical' } });
    expect(html).toContain('href="/findings?severity=critical"');
    expect(anchors(html)).toBe(1);
  });

  it('renders no anchor at all when the prop is omitted', () => {
    expect(anchors(render())).toBe(0);
  });
});

describe('TopSourcesCardView', () => {
  const render = (props: Partial<Parameters<typeof TopSourcesCardView>[0]>) =>
    renderToStaticMarkup(
      <TopSourcesCardView items={[]} isLoading={false} error={null} {...props} />,
    );
  const repo: TopSource = { id: 'repo_api', name: 'acme/api', kind: 'repo', findingsCount: 9 };
  const user: TopSource = { id: 'user_a', name: 'a@example.com', kind: 'user', findingsCount: 5 };

  it('links a repo row when the host supplies an href', () => {
    const html = render({ items: [repo], sourceHrefs: { repo_api: '/findings?repo=acme%2Fapi' } });
    expect(html).toContain('href="/findings?repo=acme%2Fapi"');
    expect(anchors(html)).toBe(1);
  });

  it('leaves a user row unlinked while its repo neighbour links', () => {
    // The findings page has no author dimension, so the host emits no key for a
    // user source. This is the ONLY place that branch can be exercised: the local
    // store derives no user sources at all, so the page can never produce one.
    const html = render({
      items: [repo, user],
      sourceHrefs: { repo_api: '/findings?repo=acme%2Fapi' },
    });
    expect(anchors(html)).toBe(1);
    expect(html).not.toContain('user_a');
    expect(html).toContain('a@example.com');
  });

  it('renders no anchor at all when the prop is omitted', () => {
    expect(anchors(render({ items: [repo, user] }))).toBe(0);
  });
});

describe('RecentlyResolvedCardView', () => {
  const item: ResolvedFeedItem = {
    findingKey: 'fk-1',
    ruleId: 'aws-key',
    severity: 'critical',
    path: 'src/db.ts',
    resolvedAt: '2026-07-05T08:00:00.000Z',
    detectedAt: '2026-07-01T00:00:00.000Z',
  };
  const render = (props: Partial<Parameters<typeof RecentlyResolvedCardView>[0]> = {}) =>
    renderToStaticMarkup(
      <RecentlyResolvedCardView
        items={[item]}
        isLoading={false}
        error={null}
        renderedAt={RENDERED_AT}
        {...props}
      />,
    );

  it('links a row when the host supplies an href for its finding key', () => {
    const html = render({ itemHrefs: { 'fk-1': '/findings?type=aws-key&status=resolved' } });
    expect(html).toContain('href="/findings?type=aws-key&amp;status=resolved"');
    expect(anchors(html)).toBe(1);
  });

  it('renders no anchor at all when the prop is omitted', () => {
    expect(anchors(render())).toBe(0);
  });
});

describe('RecommendedActionsCardView', () => {
  const noop = (): void => undefined;
  const render = (props: Partial<Parameters<typeof RecommendedActionsCardView>[0]> = {}) =>
    renderToStaticMarkup(
      <RecommendedActionsCardView
        items={[]}
        isLoading={false}
        error={null}
        applyAction={noop}
        dismissAction={noop}
        isMutating={false}
        mutationError={null}
        {...props}
      />,
    );

  it('renders "View all" as a link when the host supplies one', () => {
    const html = render({ viewAllHref: '/findings?view=flat' });
    expect(html).toContain('href="/findings?view=flat"');
    expect(html).toContain('View all');
  });

  it('does not render "View all" at all without an href', () => {
    // It used to render as an enabled button with no handler — a control that looks
    // live and does nothing is worse than one that is absent.
    expect(render()).not.toContain('View all');
  });
});
