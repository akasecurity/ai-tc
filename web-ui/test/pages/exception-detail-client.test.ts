// The detail route's own wiring of `renderedAt`.
//
// dashboard-ui pins that ExceptionDetailView measures its labels — and gates
// the revoke form — against whatever instant it is handed. Neither that suite
// nor the view itself can see the two lines that supply one: the `renderedAt`
// [id]/page.tsx captures on the server, and the `renderedAt={now}` this client
// hands down. Drop either and the view falls back to the browser's clock,
// which is the mismatch the prop exists to prevent, and nothing else goes red.
//
// The stake here is higher than on the list route. `exceptionState` decides
// whether the revoke form renders at all, so a grant whose expiry falls
// between the server pass and hydration takes a whole subtree with it rather
// than relabelling a cell.
//
// Rendered statically, so `useRenderClock`'s effect never runs and what is
// asserted is the server pass — which is precisely the pass hydration has to
// reproduce.
import type { DetectionException, ExceptionDescriptor } from '@akasecurity/schema';
import { toExceptionDescriptor } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

const { ExceptionDetailClient } =
  await import('../../app/(app)/exceptions/[id]/ExceptionDetailClient.tsx');

const RENDERED_AT = Date.parse('2026-08-01T00:30:00.000Z');

function exceptionRow(overrides: Partial<DetectionException>): ExceptionDescriptor {
  return toExceptionDescriptor({
    id: '7d9f7a4e-1111-4222-8333-444455556666',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: 'a'.repeat(64),
    keyVersion: 4,
    maskedValue: 'A****Z',
    capability: 'suppress',
    scope: 'temporary',
    expiresAt: null,
    maxUses: null,
    useCount: 0,
    lastUsedAt: null,
    justification: 'test fixture',
    conditions: null,
    createdBy: 'tester',
    createdVia: 'web-add',
    createdAt: '2026-08-01T00:00:00.000Z',
    updatedAt: '2026-08-01T00:00:00.000Z',
    revokedAt: null,
    revokedBy: null,
    revokeReason: null,
    ...overrides,
  });
}

function render(exception: ExceptionDescriptor): string {
  return renderToStaticMarkup(
    createElement(ExceptionDetailClient, { exception, renderedAt: RENDERED_AT }),
  );
}

describe('the exception detail client threads renderedAt into the view', () => {
  it('measures the expiry label against the SSR instant, not the ambient clock', () => {
    // Expires an hour after the instant the page rendered at, and well over a
    // month before any clock this suite could actually run on — so the label
    // is "in 30 minutes" only if the server's instant reached the view.
    const markup = render(exceptionRow({ expiresAt: '2026-08-01T01:00:00.000Z' }));

    expect(markup).toContain('in 30 minutes');
  });

  it('keeps the revoke form for a grant still live at that instant', () => {
    // The structural half. On the ambient clock this grant expired long ago
    // and `exceptionState` would drop the form entirely.
    const markup = render(exceptionRow({ expiresAt: '2026-08-01T01:00:00.000Z' }));

    expect(markup).toContain('>active<');
    expect(markup).toContain('Revoke this grant');
  });

  it('still hides the form for a grant already expired at that instant', () => {
    // Positive control: the form follows real lifecycle state rather than
    // appearing whenever renderedAt happens to be supplied.
    const markup = render(exceptionRow({ expiresAt: '2026-08-01T00:15:00.000Z' }));

    expect(markup).toContain('>expired<');
    expect(markup).not.toContain('Revoke this grant');
  });
});
