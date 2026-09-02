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
