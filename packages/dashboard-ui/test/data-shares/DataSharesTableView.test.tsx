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

  it('highlights the selected destination and endpoint rows while the drawer is open', () => {
    const withEndpoint = group({
      items: [
        destination({ id: 'a', endpoints: [endpoint({ id: 'ep-1' })] }),
        destination({ id: 'b' }),
      ],
    });
    const html = render({
      group: withEndpoint,
      forceExpand: true,
      drawerOpen: true,
      selection: { id: 'a', endpointId: 'ep-1' },
    });
    expect(html).toContain('bg-primary-tint');
  });

  it('does not highlight anything while the drawer is closed, even with a selection id', () => {
    const html = render({
      group: group({ items: [destination({ id: 'a' })] }),
      drawerOpen: false,
      selection: { id: 'a' },
    });
    expect(html).not.toContain('bg-primary-tint');
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
