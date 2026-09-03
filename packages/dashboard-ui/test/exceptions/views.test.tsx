import type { DetectionException, ExceptionDescriptor } from '@akasecurity/schema';
import { toExceptionDescriptor } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ExceptionDetailView } from '../../src/exceptions/ExceptionDetailView.tsx';
import { ExceptionsTableView } from '../../src/exceptions/ExceptionsTableView.tsx';

// A fixed render instant. These cases assert display contracts rather than
// ages, so the value only has to be the SAME one every run — but it has to be
// passed, because the views no longer have a clock of their own to fall back on.
const RENDERED_AT = Date.parse('2026-07-05T00:00:00.000Z');

// The capability presentation is asymmetric on purpose: a reveal-to-model
// grant is flagged with a badge on every surface (it lets the raw value reach
// the model), while suppression — the default — stays unlabelled. Rendered
// with react-dom's static renderer (this package's test environment is node,
// with no DOM).

const BADGE = 'Reveal to model';

// Built as a full store row and projected, exactly as a server boundary does:
// the views take the fingerprint-free descriptor, which excludes the field
// rather than merely omitting it, so an unprojected row would not typecheck
// here either.
function exception(overrides: Partial<DetectionException>): ExceptionDescriptor {
  return toExceptionDescriptor({
    id: '7d9f7a4e-1111-4222-8333-444455556666',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: 'a'.repeat(64),
    keyVersion: 1,
    maskedValue: 'A****Z',
    capability: 'suppress',
    scope: 'permanent',
    expiresAt: null,
    maxUses: null,
    useCount: 0,
    lastUsedAt: null,
    justification: 'test fixture',
    conditions: null,
    createdBy: 'tester',
    createdVia: 'web-add',
    createdAt: '2026-07-01T00:00:00.000Z',
    updatedAt: '2026-07-01T00:00:00.000Z',
    revokedAt: null,
    revokedBy: null,
    revokeReason: null,
    ...overrides,
  });
}

const noop = (): void => undefined;

describe('ExceptionsTableView capability badge', () => {
  it('flags a reveal-to-model row with the badge', () => {
    const html = renderToStaticMarkup(
      <ExceptionsTableView
        renderedAt={RENDERED_AT}
        items={[exception({ capability: 'reveal_to_model' })]}
        includeTerminal={false}
        onSelect={noop}
      />,
    );
    expect(html).toContain(BADGE);
  });

  it('leaves a suppress row unlabelled', () => {
    const html = renderToStaticMarkup(
      <ExceptionsTableView
        renderedAt={RENDERED_AT}
        items={[exception({})]}
        includeTerminal={false}
        onSelect={noop}
      />,
    );
    expect(html).not.toContain(BADGE);
  });
});

describe('ExceptionsTableView threads renderedAt, not the ambient clock', () => {
  // The ambient clock is set an hour past renderedAt, and past every fixture
  // instant below it, so a row that fell back to Date.now() would report a
  // different age AND a different lifecycle state than one that honors the SSR
  // instant — the same class of mismatch BlockedLedgerView.renderedAt exists to
  // prevent, one level over.
  const RENDERED_AT = Date.parse('2026-07-05T00:00:00.000Z');

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(RENDERED_AT + 60 * 60 * 1000);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('renders the expires and created columns against renderedAt', () => {
    const html = renderToStaticMarkup(
      <ExceptionsTableView
        items={[
          exception({
            scope: 'temporary',
            expiresAt: '2026-07-05T00:30:00.000Z',
            createdAt: '2026-07-04T23:30:00.000Z',
          }),
        ]}
        includeTerminal={false}
        onSelect={noop}
        renderedAt={RENDERED_AT}
      />,
    );
    expect(html).toContain('in 30 minutes');
    expect(html).toContain('30 minutes ago');
  });

  it('threads renderedAt into StateTagFor, so a row due to expire within the hour still reads active', () => {
    const html = renderToStaticMarkup(
      <ExceptionsTableView
        items={[exception({ scope: 'temporary', expiresAt: '2026-07-05T00:30:00.000Z' })]}
        includeTerminal={false}
        onSelect={noop}
        renderedAt={RENDERED_AT}
      />,
    );
    expect(html).toContain('>active<');
    expect(html).not.toContain('>expired<');
  });
});

describe('ExceptionDetailView threads renderedAt, not the ambient clock', () => {
  // Same shape as the table block above, but the stake is higher here: the
  // detail view derives `state` once and gates the whole revoke form on it, so
  // a fallback to Date.now() does not just relabel a cell — it renders a block
  // on the server that is not there on the client.
  const RENDERED_AT = Date.parse('2026-07-05T00:00:00.000Z');
  const REVOKE_FORM = 'Revoke this grant';

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(RENDERED_AT + 60 * 60 * 1000);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  // Expires half an hour AFTER the instant the server rendered at, and an hour
  // before the ambient clock — so the two clocks disagree about whether this
  // grant is still live, which is exactly the straddle the prop exists for.
  const expiringSoon = () =>
    exception({
      scope: 'temporary',
      expiresAt: '2026-07-05T00:30:00.000Z',
      createdAt: '2026-07-04T21:00:00.000Z',
    });

  it('measures the expires and created labels against renderedAt', () => {
    const html = renderToStaticMarkup(
      <ExceptionDetailView exception={expiringSoon()} renderedAt={RENDERED_AT} />,
    );

    // Each string belongs to exactly one field under BOTH clocks, so neither
    // assertion can be satisfied by the other's cell: falling back would read
    // "30 minutes ago" for expires and "4 hours ago" for created.
    expect(html).toContain('in 30 minutes');
    expect(html).toContain('3 hours ago');
  });

  it('keeps the grant active, and so keeps the revoke form, at the SSR instant', () => {
    const html = renderToStaticMarkup(
      <ExceptionDetailView exception={expiringSoon()} onRevoke={noop} renderedAt={RENDERED_AT} />,
    );

    expect(html).toContain('>active<');
    expect(html).not.toContain('>expired<');
    // The structural half: on the ambient clock this grant has expired and the
    // form is gone, which is a subtree appearing on one side of hydration only.
    expect(html).toContain(REVOKE_FORM);
  });

  it('still hides the revoke form for a grant already expired at that instant', () => {
    // The positive control for the case above: the form is gated on real
    // lifecycle state, not merely present whenever renderedAt is supplied.
    const html = renderToStaticMarkup(
      <ExceptionDetailView
        exception={exception({ scope: 'temporary', expiresAt: '2026-07-04T23:00:00.000Z' })}
        onRevoke={noop}
        renderedAt={RENDERED_AT}
      />,
    );

    expect(html).toContain('>expired<');
    expect(html).not.toContain(REVOKE_FORM);
  });
});

describe('ExceptionDetailView capability presentation', () => {
  it('shows the badge and the consequence callout for a reveal grant', () => {
    const html = renderToStaticMarkup(
      <ExceptionDetailView
        renderedAt={RENDERED_AT}
        exception={exception({ capability: 'reveal_to_model' })}
      />,
    );
    expect(html).toContain(BADGE);
    // The consequence must be stated, not implied.
    expect(html).toContain('raw form at tool boundaries');
    expect(html).toContain('audited');
  });

  it('renders a suppress grant without any capability labelling', () => {
    const html = renderToStaticMarkup(
      <ExceptionDetailView renderedAt={RENDERED_AT} exception={exception({})} />,
    );
    expect(html).not.toContain(BADGE);
    expect(html).not.toContain('raw form at tool boundaries');
  });
});

// The instant these views are given is not just a label input: `exceptionState`
// derives a grant's lifecycle from it, and ExceptionDetailView renders the
// revoke form ONLY while that reads `active`. So the two renders of a page —
// the server's and the browser's hydration of it — can disagree about whether a
// whole subtree exists, which React resolves by throwing the server's markup
// away. That is why the argument is required rather than defaulted, and these
// are what fail if a view goes back to picking its own instant.
//
// Each case drives two renders that differ ONLY in `renderedAt`, straddling the
// fixture's `expiresAt`. Two renders of one input, one boundary between them —
// which is exactly the shape of the defect.
describe('the exceptions views read the instant they are given', () => {
  const EXPIRES = '2026-07-05T00:30:00.000Z';
  const BEFORE = Date.parse('2026-07-05T00:00:00.000Z');
  const AFTER = Date.parse('2026-07-05T01:00:00.000Z');
  const expiring = () => exception({ scope: 'temporary', expiresAt: EXPIRES });

  it('labels the same grant differently on either side of its expiry', () => {
    const before = renderToStaticMarkup(
      <ExceptionsTableView
        items={[expiring()]}
        includeTerminal
        onSelect={noop}
        renderedAt={BEFORE}
      />,
    );
    const after = renderToStaticMarkup(
      <ExceptionsTableView
        items={[expiring()]}
        includeTerminal
        onSelect={noop}
        renderedAt={AFTER}
      />,
    );

    expect(before).toContain('in 30 minutes');
    expect(before).toContain('>active<');
    expect(after).toContain('30 minutes ago');
    expect(after).toContain('>expired<');
  });

  it('gates the revoke form on the instant, so the two renders differ in STRUCTURE', () => {
    // The severe case: not a differing label but a differing tree. The form is
    // present at BEFORE and absent at AFTER, from the same props.
    const before = renderToStaticMarkup(
      <ExceptionDetailView exception={expiring()} onRevoke={noop} renderedAt={BEFORE} />,
    );
    const after = renderToStaticMarkup(
      <ExceptionDetailView exception={expiring()} onRevoke={noop} renderedAt={AFTER} />,
    );

    expect(before).toContain('Revoke this grant');
    expect(after).not.toContain('Revoke this grant');
    // And the chip agrees with the form it gates, at both instants.
    expect(before).toContain('>active<');
    expect(after).toContain('>expired<');
  });

  it('threads the instant into the detail view own labels too', () => {
    const html = renderToStaticMarkup(
      <ExceptionDetailView
        exception={exception({ createdAt: '2026-07-04T23:30:00.000Z' })}
        renderedAt={BEFORE}
      />,
    );
    expect(html).toContain('30 minutes ago');
  });
});
