import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { DataShareDetailView } from '../../src/data-shares/DataShareDetailView.tsx';
import { destinationDetail } from './fixtures.ts';

const RENDERED_AT = Date.parse('2026-07-05T00:00:00.000Z');

function render(props: Partial<Parameters<typeof DataShareDetailView>[0]> = {}) {
  return renderToStaticMarkup(
    <DataShareDetailView
      destination={destinationDetail()}
      endpoint={null}
      onPick={vi.fn()}
      onBack={vi.fn()}
      onSetDecision={vi.fn()}
      isSettingDecision={false}
      renderedAt={RENDERED_AT}
      {...props}
    />,
  );
}

describe('DataShareDetailView', () => {
  it('shows the host under the name when they differ', () => {
    const html = render({
      destination: destinationDetail({ name: 'Okta', host: 'okta.com' }),
    });
    expect(html).toContain('Okta');
    expect(html).toContain('okta.com');
  });

  it('renders the host once, not twice, for a raw-IP destination whose name equals its host', () => {
    const html = render({
      destination: destinationDetail({
        kind: 'ip',
        name: '203.0.113.0',
        host: '203.0.113.0',
        trust: 'ip',
        providerId: null,
      }),
    });
    expect(html.match(/203\.0\.113\.0/g)).toHaveLength(1);
  });

  it('renders the host once, not twice, for an external destination whose name equals its host', () => {
    const html = render({
      destination: destinationDetail({
        kind: 'external',
        name: 'api.acme-partner.com',
        host: 'api.acme-partner.com',
        trust: 'unverified',
        providerId: null,
      }),
    });
    expect(html.match(/api\.acme-partner\.com/g)).toHaveLength(1);
  });
});
