import type { DetectionException, ExceptionDescriptor } from '@akasecurity/schema';
import { toExceptionDescriptor } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ExceptionDetailView } from '../../src/exceptions/ExceptionDetailView.tsx';
import { ExceptionsTableView } from '../../src/exceptions/ExceptionsTableView.tsx';

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
        items={[exception({ capability: 'reveal_to_model' })]}
        includeTerminal={false}
        onSelect={noop}
      />,
    );
    expect(html).toContain(BADGE);
  });

  it('leaves a suppress row unlabelled', () => {
    const html = renderToStaticMarkup(
      <ExceptionsTableView items={[exception({})]} includeTerminal={false} onSelect={noop} />,
    );
    expect(html).not.toContain(BADGE);
  });
});

describe('ExceptionDetailView capability presentation', () => {
  it('shows the badge and the consequence callout for a reveal grant', () => {
    const html = renderToStaticMarkup(
      <ExceptionDetailView exception={exception({ capability: 'reveal_to_model' })} />,
    );
    expect(html).toContain(BADGE);
    // The consequence must be stated, not implied.
    expect(html).toContain('raw form at tool boundaries');
    expect(html).toContain('audited');
  });

  it('renders a suppress grant without any capability labelling', () => {
    const html = renderToStaticMarkup(<ExceptionDetailView exception={exception({})} />);
    expect(html).not.toContain(BADGE);
    expect(html).not.toContain('raw form at tool boundaries');
  });
});
