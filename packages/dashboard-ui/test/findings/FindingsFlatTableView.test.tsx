import type { FindingInstanceDetail } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { FindingsFlatTableView } from '../../src/findings/FindingsFlatTableView.tsx';

// A fixed render instant. These cases assert display contracts rather than
// ages, so the value only has to be the SAME one every run — but it has to be
// passed, because the views no longer have a clock of their own to fall back on.
const RENDERED_AT = Date.parse('2026-07-05T00:00:00.000Z');

function instance(over: Partial<FindingInstanceDetail> = {}): FindingInstanceDetail {
  return {
    id: 'fnd-1',
    provider: 'claudecode',
    repo: 'acme/api',
    file: 'src/db.ts',
    action: 'blocked',
    detectedAt: '2026-01-01T00:00:00.000Z',
    confidence: 0.9,
    status: 'handled',
    groupId: 'aws-key',
    category: 'secret',
    subtype: 'aws-key',
    severity: 'critical',
    match: { maskedValue: 'AKIA****', contextPrefix: '' },
    detection: { id: 'aws-key', name: null },
    policy: { id: 'category:secret', name: 'secret' },
    ...over,
  };
}

function render(props: Partial<Parameters<typeof FindingsFlatTableView>[0]> = {}) {
  return renderToStaticMarkup(
    <FindingsFlatTableView
      renderedAt={RENDERED_AT}
      items={[instance()]}
      onSelect={vi.fn()}
      {...props}
    />,
  );
}

// `<th` alone would also match `<thead`; require the tag to end there.
const count = (html: string, tag: 'th' | 'td') =>
  (html.match(new RegExp(`<${tag}[\\s>]`, 'g')) ?? []).length;

describe('FindingsFlatTableView', () => {
  it('renders the same number of header and body cells with the User column off', () => {
    const html = render();
    expect(html).not.toContain('>User<');
    expect(count(html, 'th')).toBe(7);
    expect(count(html, 'td')).toBe(7);
  });

  // The header goes INSIDE this card. A caller that had to wrap this component
  // to get a title strip would draw a second border and a second corner radius
  // around the first — plainly visible where the two meet, which is how this
  // slot came to exist.
  it('renders a caller header inside its own single card', () => {
    const html = render({ header: <div>aws-key</div> });
    expect(html).toContain('<div>aws-key</div>');
    expect((html.match(/data-slot="card"/g) ?? []).length).toBe(1);
    // Above the table, not after it.
    expect(html.indexOf('<div>aws-key</div>')).toBeLessThan(html.indexOf('<table'));
  });

  // The master/detail panel pins one type, so two columns would repeat one value
  // down the table: severity is a property of the RULE, and the type name is
  // already on the row selected beside it. The Type column becomes the finding's
  // own masked value — the thing that actually differs between these rows.
  it('drops Severity and turns Type into Value when the type is pinned', () => {
    const html = render({ pinnedType: true });
    expect(html).not.toContain('>Severity<');
    expect(html).not.toContain('>Type<');
    expect(html).toContain('>Value<');
    // The value survives; the type name and its icon tile do not.
    expect(html).toContain('AKIA****');
    expect(html).not.toContain('>aws-key<');
    // One fewer column than the unpinned table, header and body alike.
    expect(count(html, 'th')).toBe(6);
    expect(count(html, 'td')).toBe(6);
  });

  it('renders the same number of header and body cells with the User column on', () => {
    const alice = { id: 'u-alice', name: 'alice@example.com' };
    const html = render({ showUserColumn: true, items: [instance({ user: alice })] });
    expect(html).toContain('>User<');
    expect(html).toContain('alice@example.com');
    expect(count(html, 'th')).toBe(8);
    expect(count(html, 'td')).toBe(8);
  });

  it('renders a dash in the User column for a row with no user', () => {
    const html = render({ showUserColumn: true });
    expect(count(html, 'td')).toBe(8);
    expect(html).toContain('<span class="text-text-3">—</span>');
  });
});
