import { isValidElement, type ReactElement, type ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { DataSharesTableView } from '../../src/data-shares/DataSharesTableView.tsx';
import { destination, endpoint, group } from './fixtures.ts';

// A fixed render instant. These cases assert display contracts rather than
// ages, so the value only has to be the SAME one every run — but it has to be
// passed, because the views no longer have a clock of their own to fall back on.
const RENDERED_AT = Date.parse('2026-07-05T00:00:00.000Z');

function render(props: Partial<Parameters<typeof DataSharesTableView>[0]> = {}) {
  return renderToStaticMarkup(
    <DataSharesTableView
      renderedAt={RENDERED_AT}
      group={group()}
      expanded={{}}
      selection={null}
      drawerOpen={false}
      onToggle={vi.fn()}
      onOpenDest={vi.fn()}
      onOpenEndpoint={vi.fn()}
      {...props}
    />,
  );
}

/**
 * The one `<tr>` whose aria-label names `label`, sliced out of the markup —
 * so a class assertion lands on THAT row rather than anywhere in the table.
 * Asserting `html.toContain('bg-primary-tint')` over the whole string passes
 * just as well when every row is highlighted, or the wrong one is.
 */
function rowMarkup(html: string, label: string): string {
  const at = html.indexOf(`aria-label="${label}"`);
  if (at < 0) throw new Error(`no row found with aria-label "${label}"`);
  const start = html.lastIndexOf('<tr', at);
  const end = html.indexOf('</tr>', at);
  return html.slice(start, end);
}

const DEST_ROW = (name: string) => `View details for destination ${name}`;
const EP_ROW = (method: string, url: string) => `View details for endpoint ${method} ${url}`;

describe('DataSharesTableView', () => {
  it('renders one row per destination in the group', () => {
    const html = render({
      group: group({
        items: [destination({ id: 'a', name: 'Okta' }), destination({ id: 'b', name: 'SendGrid' })],
      }),
    });
    expect(html).toContain('Okta');
    expect(html).toContain('SendGrid');
  });

  it('renders endpoint rows only when the destination row is expanded (forceExpand)', () => {
    const withEndpoint = group({
      items: [
        destination({
          id: 'a',
          endpoints: [endpoint({ id: 'ep-1', url: 'https://api.example.com/v1/widgets' })],
        }),
      ],
    });
    const collapsed = render({ group: withEndpoint, expanded: {} });
    expect(collapsed).not.toContain('/v1/widgets');

    const expanded = render({ group: withEndpoint, forceExpand: true });
    expect(expanded).toContain('/v1/widgets');
  });

  it('renders endpoint rows when expanded by id, not just via forceExpand', () => {
    const withEndpoint = group({
      items: [
        destination({
          id: 'a',
          endpoints: [endpoint({ id: 'ep-1', url: 'https://api.example.com/v1/widgets' })],
        }),
      ],
    });
    const html = render({ group: withEndpoint, expanded: { a: true } });
    expect(html).toContain('/v1/widgets');
  });

  it('flags a destination that sends over plaintext HTTP', () => {
    const insecure = render({
      group: group({ items: [destination({ transports: ['http'] })] }),
    });
    expect(insecure).toContain('Sends over plaintext');

    const secure = render({
      group: group({ items: [destination({ transports: ['https'] })] }),
    });
    expect(secure).not.toContain('Sends over plaintext');
  });

  it('highlights the selected endpoint row and no other row', () => {
    const html = render({
      group: group({
        items: [
          destination({
            id: 'a',
            name: 'Selected',
            endpoints: [
              endpoint({ id: 'ep-1', url: 'https://api.example.com/one' }),
              endpoint({ id: 'ep-2', url: 'https://api.example.com/two' }),
            ],
          }),
          destination({ id: 'b', name: 'Other' }),
        ],
      }),
      forceExpand: true,
      drawerOpen: true,
      selection: { id: 'a', endpointId: 'ep-1' },
    });

    // The endpoint carrying the selection, and nothing else — not its sibling
    // endpoint, not its own parent destination, not the unrelated one.
    expect(rowMarkup(html, EP_ROW('GET', 'https://api.example.com/one'))).toContain(
      'bg-primary-tint',
    );
    expect(rowMarkup(html, EP_ROW('GET', 'https://api.example.com/two'))).not.toContain(
      'bg-primary-tint',
    );
    expect(rowMarkup(html, DEST_ROW('Selected'))).not.toContain('bg-primary-tint');
    expect(rowMarkup(html, DEST_ROW('Other'))).not.toContain('bg-primary-tint');
  });

  it('highlights the selected destination row itself when no endpoint is selected', () => {
    const html = render({
      group: group({
        items: [
          destination({ id: 'a', name: 'Selected' }),
          destination({ id: 'b', name: 'Other' }),
        ],
      }),
      drawerOpen: true,
      selection: { id: 'a' },
    });
    expect(rowMarkup(html, DEST_ROW('Selected'))).toContain('bg-primary-tint');
    expect(rowMarkup(html, DEST_ROW('Other'))).not.toContain('bg-primary-tint');
  });

  it('does not highlight anything while the drawer is closed, even with a selection id', () => {
    const html = render({
      group: group({ items: [destination({ id: 'a', name: 'Selected' })] }),
      drawerOpen: false,
      selection: { id: 'a' },
    });
    expect(rowMarkup(html, DEST_ROW('Selected'))).not.toContain('bg-primary-tint');
  });

  // The bug this column exists to close: a destination the operator had blocked
  // was byte-for-byte identical in the register to one nobody had touched, so
  // the only way to answer "which of these have we dealt with?" was to open
  // every drawer in turn.
  it('renders the egress decision, so a blocked destination is not identical to an untouched one', () => {
    const blocked = rowMarkup(
      render({
        group: group({
          items: [destination({ name: 'Blocked', status: 'blocked', isCustom: true })],
        }),
      }),
      DEST_ROW('Blocked'),
    );
    const untouched = rowMarkup(
      render({
        group: group({
          items: [destination({ name: 'Untouched', trust: 'unverified', status: 'review' })],
        }),
      }),
      DEST_ROW('Untouched'),
    );

    expect(blocked).toContain('Blocked');
    expect(untouched).toContain('Needs review');
    expect(untouched).not.toContain('Blocked');
  });

  it('distinguishes an operator decision from an inherited trust default, by tone and in text', () => {
    const decided = rowMarkup(
      render({
        group: group({
          items: [destination({ name: 'Decided', status: 'allowed', isCustom: true })],
        }),
      }),
      DEST_ROW('Decided'),
    );
    const inherited = rowMarkup(
      render({
        group: group({
          items: [destination({ name: 'Inherited', status: 'allowed', isCustom: false })],
        }),
      }),
      DEST_ROW('Inherited'),
    );

    // Both read "Allowed"; only the sr-only suffix and the badge tone separate
    // them, and the suffix is the half a screen reader can reach.
    expect(decided).toContain('set by an operator');
    expect(inherited).toContain('trust default');
    expect(decided).not.toEqual(inherited);
  });

  // The endpoint rows span Destination + Trust + Status. Getting that span
  // wrong shifts every endpoint cell one column left of its header, which
  // renders without error and silently mislabels the whole expanded row.
  it('keeps endpoint rows aligned with the header after the Status column', () => {
    const html = render({
      group: group({
        items: [
          destination({ endpoints: [endpoint({ id: 'ep-1', url: 'https://api.example.com/x' })] }),
        ],
      }),
      forceExpand: true,
    });
    // `<th[ >]`, not `<th` — the latter also matches the `<thead>` wrapping them.
    const headerCells = (html.match(/<th[ >]/g) ?? []).length;
    const epRow = rowMarkup(html, EP_ROW('GET', 'https://api.example.com/x'));
    const epCells = (epRow.match(/<td[ >]/g) ?? []).length;
    const spanned = [...epRow.matchAll(/colspan="(\d+)"/gi)].reduce(
      (n, m) => n + Number(m[1]) - 1,
      0,
    );
    expect(headerCells).toBe(8);
    expect(epCells + spanned).toBe(headerCells);
  });

  it('shows an overflow count once a destination carries more than 3 data classes', () => {
    const html = render({
      group: group({
        items: [
          destination({ dataClasses: ['secrets', 'pii', 'customer', 'source', 'telemetry'] }),
        ],
      }),
    });
    expect(html).toContain('+2');
  });

  describe('groupByProvider', () => {
    // Two hosts of the same provider — GitHub Raw is the more recently seen
    // one, so the provider row is named after it (grouping.ts folds the name
    // from the most recently seen host).
    const hostA = destination({
      id: 'gh-a',
      name: 'GitHub',
      host: 'api.github.com',
      providerId: 'github',
      category: 'Dev tools',
      trust: 'recognized',
      lastSeen: '2026-07-01T00:00:00.000Z',
    });
    const hostB = destination({
      id: 'gh-b',
      name: 'GitHub Raw',
      host: 'raw.githubusercontent.com',
      providerId: 'github',
      category: 'Dev tools',
      trust: 'recognized',
      lastSeen: '2026-07-05T00:00:00.000Z',
    });
    const twoHostGroup = group({ items: [hostA, hostB] });

    it('folds two hosts sharing a providerId into one provider row, collapsed by default', () => {
      const html = render({ group: twoHostGroup, groupByProvider: true, expanded: {} });
      expect(html).toContain('GitHub Raw');
      expect(html).toContain('2 hosts');
      expect(html).not.toContain('api.github.com');
      expect(html).not.toContain('raw.githubusercontent.com');
    });

    it('reveals both host rows once the provider row is expanded by id', () => {
      const html = render({
        group: twoHostGroup,
        groupByProvider: true,
        expanded: { 'provider:github': true },
      });
      expect(html).toContain('api.github.com');
      expect(html).toContain('raw.githubusercontent.com');
    });

    it('opens the provider row on its own while one of its hosts is the drawer selection', () => {
      const selected = render({
        group: twoHostGroup,
        groupByProvider: true,
        expanded: {},
        selection: { id: 'gh-b' },
        drawerOpen: true,
      });
      expect(selected).toContain('raw.githubusercontent.com');
      expect(rowMarkup(selected, DEST_ROW('GitHub Raw'))).toContain('bg-primary-tint');
      // The pinned row's toggle is disabled, so a click cannot flip an expansion
      // flag that nothing renders while the selection holds the row open.
      const providerRow = rowMarkup(selected, 'Collapse provider GitHub Raw');
      expect(providerRow).toContain('Kept open while a host is selected');
      expect(providerRow).toContain('disabled=""');

      // The same selection with the drawer closed leaves the row collapsed, so
      // the auto-open is tied to what is showing rather than to a stale id.
      const closed = render({
        group: twoHostGroup,
        groupByProvider: true,
        expanded: {},
        selection: { id: 'gh-b' },
        drawerOpen: false,
      });
      expect(closed).not.toContain('raw.githubusercontent.com');
    });

    it('forceExpand opens provider rows too', () => {
      const html = render({
        group: twoHostGroup,
        groupByProvider: true,
        expanded: {},
        forceExpand: true,
      });
      expect(html).toContain('api.github.com');
      expect(html).toContain('raw.githubusercontent.com');
    });

    // Positive control: the prop defaults to false, so an app that never
    // passes it keeps rendering exactly what it always has.
    it('renders two plain destination rows when the prop is omitted', () => {
      const html = render({ group: twoHostGroup });
      expect(html).toContain(DEST_ROW('GitHub'));
      expect(html).toContain(DEST_ROW('GitHub Raw'));
      expect(html).not.toContain('2 hosts');
    });

    it('shows Mixed for trust/status once the folded hosts disagree', () => {
      const mixed = group({
        items: [
          destination({ id: 'gh-a', providerId: 'github', trust: 'recognized' }),
          destination({ id: 'gh-b', providerId: 'github', trust: 'unverified' }),
        ],
      });
      const html = render({ group: mixed, groupByProvider: true });
      expect(html).toContain('Mixed');
    });

    // Handlers never reach the wire as markup, so the provider row's toggle is
    // exercised by calling the view as a plain function and walking the
    // element tree it returns for the row carrying the target aria-label —
    // the same technique this package's other row-handler tests use.
    it('binds the provider row toggle to the provider group id', () => {
      const onToggle = vi.fn();
      const tree = DataSharesTableView({
        renderedAt: RENDERED_AT,
        group: twoHostGroup,
        expanded: {},
        selection: null,
        drawerOpen: false,
        onToggle,
        onOpenDest: vi.fn(),
        onOpenEndpoint: vi.fn(),
        groupByProvider: true,
      });
      const row = findByAriaLabel(tree, 'Expand provider GitHub Raw');
      if (row === null)
        throw new Error('no row found with aria-label "Expand provider GitHub Raw"');
      (row.props as { onClick: () => void }).onClick();
      expect(onToggle).toHaveBeenCalledExactlyOnceWith('provider:github');
    });
  });
});

/**
 * Finds the element carrying `aria-label={label}` inside an UNRENDERED React
 * element tree, invoking any function component it walks through along the
 * way (none of this package's row components use hooks, so calling them
 * directly is safe) since a row's own aria-label is set inside its body, not
 * passed down from its caller.
 */
function findByAriaLabel(node: ReactNode, label: string): ReactElement | null {
  if (Array.isArray(node)) {
    for (const child of node as ReactNode[]) {
      const hit = findByAriaLabel(child, label);
      if (hit) return hit;
    }
    return null;
  }
  if (!isValidElement(node)) return null;
  const props = node.props as { 'aria-label'?: string; children?: ReactNode };
  if (props['aria-label'] === label) return node;
  if (typeof node.type === 'function') {
    const rendered = (node.type as (p: unknown) => ReactNode)(node.props);
    const hit = findByAriaLabel(rendered, label);
    if (hit) return hit;
  }
  return props.children === undefined ? null : findByAriaLabel(props.children, label);
}
