import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { DataSharesTableView } from '../../src/data-shares/DataSharesTableView.tsx';
import { destination, endpoint, group } from './fixtures.ts';

function render(props: Partial<Parameters<typeof DataSharesTableView>[0]> = {}) {
  return renderToStaticMarkup(
    <DataSharesTableView
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
});
