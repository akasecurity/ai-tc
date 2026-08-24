// Approvability is asked PER ROW, and the answer is the host's.
//
// A blocked row can only be matched under the fingerprint key it was recorded
// with, and that key lives on the machine that recorded it. That made a single
// `keyState` prop workable while every row in the list came from one store —
// and wrong the moment a host aggregates several, because rows recorded on
// different machines under different keys would all be judged against one
// value, and the remediation copy derived from it names a file (`~/.aka/data`)
// such a host does not have.
//
// So the view no longer derives approvability; it renders what the host
// answers. These cases pin that: two rows in one list, different answers, both
// respected. Without the per-row callback neither could be expressed.
import type { BlockedDetectionDescriptor } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { BlockedLedgerView } from '../../src/exceptions/BlockedLedgerView.tsx';

const row = (reference: string, keyVersion: number): BlockedDetectionDescriptor => ({
  reference,
  ruleId: 'aws-access-key',
  category: 'secret',
  keyVersion,
  maskedValue: 'AKIA••••',
  sessionId: null,
  repo: 'acme/api',
  blockedAt: '2026-08-01T00:00:00.000Z',
});

const render = (blockReason: (r: BlockedDetectionDescriptor) => string | null) =>
  renderToStaticMarkup(
    <BlockedLedgerView
      items={[row('aaa111', 1), row('bbb222', 7)]}
      onApprove={vi.fn()}
      blockedWindow="30m"
      onBlockedWindowChange={vi.fn()}
      blockReason={blockReason}
    />,
  );

describe('BlockedLedgerView approvability', () => {
  it('asks the host once per row, with the row', () => {
    const seen: string[] = [];
    render((r) => {
      seen.push(r.reference);
      return null;
    });
    expect(seen).toEqual(['aaa111', 'bbb222']);
  });

  it('lets one row be approvable while another is not, in the same list', () => {
    // The case a single key state cannot express: two machines, two keys.
    const markup = render((r) => (r.keyVersion === 7 ? 'Recorded on another machine.' : null));
    expect(markup).toContain('Recorded on another machine.');
    // Exactly one Approve carries the disabled ATTRIBUTE — matched as
    // `disabled=""` rather than the bare word, since Tailwind's `disabled:`
    // variants put that string in class names on every button.
    expect(markup.match(/disabled=""/g)).toHaveLength(1);
  });

  it('renders the host’s own words rather than any wording of its own', () => {
    // The view must not substitute machine-local remediation copy for a host
    // that has no such machine. Whatever the host says is what appears.
    const markup = render(() => 'This device has not reported since the key rotated.');
    expect(markup).toContain('This device has not reported since the key rotated.');
    expect(markup).not.toContain('~/.aka');
  });

  it('marks an unapprovable row as such next to its timestamp', () => {
    expect(render(() => 'nope')).toContain('not approvable');
    expect(render(() => null)).not.toContain('not approvable');
  });

  it('leaves every Approve live when the host blocks nothing', () => {
    expect(render(() => null)).not.toContain('disabled=""');
  });
});
