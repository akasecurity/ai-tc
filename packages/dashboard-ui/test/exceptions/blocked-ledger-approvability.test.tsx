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
//
// Every assertion below is scoped to ONE row's slice of the markup rather than
// the whole document. A whole-markup `toContain` cannot tell the right row
// being disabled from the wrong one, and the reason is the only channel the
// reader has — it is not also a tooltip, since a disabled button carries
// `disabled:pointer-events-none` and is never hit-tested — so deleting the
// element that renders it has to go red here or nowhere.
import type { BlockedDetectionDescriptor } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import {
  BLOCKED_REASON_UNSTATED,
  BlockedLedgerView,
} from '../../src/exceptions/BlockedLedgerView.tsx';

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

const REFERENCES = ['aaa111', 'bbb222'] as const;

const render = (blockReason: (r: BlockedDetectionDescriptor) => string | null) =>
  renderToStaticMarkup(
    <BlockedLedgerView
      items={[row(REFERENCES[0], 1), row(REFERENCES[1], 7)]}
      onApprove={vi.fn()}
      blockedWindow="30m"
      onBlockedWindowChange={vi.fn()}
      blockReason={blockReason}
    />,
  );

// One row's markup: from where its reference is printed to where the next row's
// is. Rows render in `items` order and each one's Approve sits after its own
// reference, so the slice holds exactly that row's content — including the
// button — and nothing of its neighbour's. Sliced on the references themselves
// rather than the wrapper's Tailwind classes, which are presentation and change
// without the structure changing.
function rowMarkup(markup: string, reference: string): string {
  const start = markup.indexOf(reference);
  expect(start, `row ${reference} is missing from the markup`).toBeGreaterThan(-1);
  const next = REFERENCES.map((r) => markup.indexOf(r)).filter((i) => i > start);
  return markup.slice(start, next.length > 0 ? Math.min(...next) : markup.length);
}

// The text of the element that carries this row's reason, or null when the row
// renders no such element. Read by id — the same id the row's Approve points at
// with `aria-describedby` — so the assertion fails if the element is deleted,
// and equality fails if the view decorates or substitutes the host's wording.
function reasonText(markup: string, reference: string): string | null {
  const found = new RegExp(`<[a-z]+[^>]*id="blocked-reason-${reference}"[^>]*>([^<]*)<`).exec(
    markup,
  );
  return found === null ? null : (found[1] ?? null);
}

// The disabled ATTRIBUTE on this row's Approve. Anchored on the leading
// whitespace so it cannot be satisfied by `aria-disabled=""` or
// `data-disabled=""` — neither is on the button today, but a ui-kit or Radix
// change could add one, and a substring match would then count it. Tailwind's
// `disabled:` class variants are unaffected: those appear inside `class="…"`
// without the `=""`.
const approveIsDisabled = (slice: string): boolean => /\sdisabled=""/.test(slice);

describe('BlockedLedgerView approvability', () => {
  it('asks the host once per row, with the row', () => {
    const seen: string[] = [];
    render((r) => {
      seen.push(r.reference);
      return null;
    });
    expect(seen).toEqual([...REFERENCES]);
  });

  it('lets one row be approvable while another is not, in the same list', () => {
    // The case a single key state cannot express: two machines, two keys.
    const markup = render((r) => (r.keyVersion === 7 ? 'Recorded on another machine.' : null));

    // The unapprovable row carries the reason and the disabled Approve...
    expect(reasonText(markup, 'bbb222')).toBe('Recorded on another machine.');
    expect(approveIsDisabled(rowMarkup(markup, 'bbb222'))).toBe(true);
    // ...and the two are tied together, which is the only thing that carries
    // the reason to a screen reader: the disabled button is out of the tab
    // order, and its `title` would never render as a tooltip.
    expect(rowMarkup(markup, 'bbb222')).toContain('aria-describedby="blocked-reason-bbb222"');
    // ...and the approvable one carries neither. Asserted on its own slice, so
    // disabling the WRONG row cannot satisfy this suite.
    expect(reasonText(markup, 'aaa111')).toBeNull();
    expect(approveIsDisabled(rowMarkup(markup, 'aaa111'))).toBe(false);
  });

  it('renders the host’s own words rather than any wording of its own', () => {
    // The view must not substitute machine-local remediation copy for a host
    // that has no such machine. Equality, not containment: a view that wrapped
    // the host string in wording of its own would still contain it.
    const markup = render(() => 'This device has not reported since the key rotated.');
    expect(reasonText(markup, 'aaa111')).toBe(
      'This device has not reported since the key rotated.',
    );
    expect(reasonText(markup, 'bbb222')).toBe(
      'This device has not reported since the key rotated.',
    );
  });

  it('marks an unapprovable row as such next to its timestamp', () => {
    expect(
      rowMarkup(
        render(() => 'nope'),
        'aaa111',
      ),
    ).toContain('not approvable');
    expect(
      rowMarkup(
        render(() => null),
        'aaa111',
      ),
    ).not.toContain('not approvable');
  });

  it('leaves every Approve live when the host blocks nothing', () => {
    const markup = render(() => null);
    for (const reference of REFERENCES) {
      expect(approveIsDisabled(rowMarkup(markup, reference))).toBe(false);
    }
  });

  it('keeps a row unapprovable when the host returns a blank reason', () => {
    // `string | null` admits `''`, which a template that rendered nothing or a
    // lookup that missed will produce. Blank is not consent: the row keeps its
    // disabled Approve, and the view supplies wording so the reader is not left
    // with a dead button and an empty line beside it.
    for (const blank of ['', '   ']) {
      const markup = render(() => blank);
      expect(reasonText(markup, 'aaa111')).toBe(BLOCKED_REASON_UNSTATED);
      expect(approveIsDisabled(rowMarkup(markup, 'aaa111'))).toBe(true);
    }
  });

  it('contains a throwing host callback to the row it happened on', () => {
    // The per-row lookup this prop exists for is exactly the kind that throws
    // on one machine missing from a map. Unguarded that unwinds to the nearest
    // error boundary and replaces the whole page, so one bad row would cost the
    // reader its nine siblings.
    const markup = render((r) => {
      if (r.keyVersion === 7) throw new Error('device not in map');
      return null;
    });

    expect(reasonText(markup, 'bbb222')).toBe(BLOCKED_REASON_UNSTATED);
    expect(approveIsDisabled(rowMarkup(markup, 'bbb222'))).toBe(true);
    // The sibling is untouched — still rendered, still approvable.
    expect(rowMarkup(markup, 'aaa111')).toContain('aaa111');
    expect(approveIsDisabled(rowMarkup(markup, 'aaa111'))).toBe(false);
  });
});
