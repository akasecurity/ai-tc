// The exceptions route's own wiring of `BlockedLedgerView.blockReason`.
//
// dashboard-ui pins that the view renders whatever the host answers, and
// meta.ts pins that `blockedRowBlockReason` is the right answer for a host
// serving one store. Neither can see the line that joins them, which lives
// here in a client component: `blockReason={(row) => blockedRowBlockReason(row,
// keyState)}`. exceptions-page.test.ts reads the props the page HANDS this
// component; it never renders it, so that line ran under no test at all.
//
// It was a pass-through before (`keyState={keyState}`) with no expression to
// get wrong. It is a derivation now, and getting it wrong is quiet: answer
// `null` for every row and each stale-key row gets its Approve back, offering
// a grant that can only fail server-side once the server re-reads the ledger.
//
// So this renders the component for real and asserts per row.
import type {
  BlockedDetectionDescriptor,
  DetectionException,
  ExceptionDescriptor,
  FingerprintKeyState,
} from '@akasecurity/schema';
import { toExceptionDescriptor } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

// ExceptionsClient reaches the router through the shared navigation hook, which
// throws outside a real Next app. Renders here are static — renderToStaticMarkup
// runs no effects — so a no-op router is enough: nothing calls it.
vi.mock('next/navigation', () => ({
  usePathname: () => '/exceptions',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { ExceptionsClient } = await import('../../app/(app)/exceptions/ExceptionsClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const CURRENT_VERSION = 4;
const FRESH = 'blk-fresh';
const STALE = 'blk-stale';
const REFERENCES = [FRESH, STALE] as const;

function exceptionRow(overrides: Partial<DetectionException>): ExceptionDescriptor {
  return toExceptionDescriptor({
    id: '7d9f7a4e-1111-4222-8333-444455556666',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: 'a'.repeat(64),
    keyVersion: CURRENT_VERSION,
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

function blockedRow(reference: string, keyVersion: number): BlockedDetectionDescriptor {
  return {
    reference,
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    keyVersion,
    maskedValue: 'AKIA****************',
    sessionId: null,
    repo: 'acme/api',
    blockedAt: '2026-08-01T00:00:00.000Z',
  };
}

// Two rows, one on each side of the current key version, so a single render
// covers both answers and neither case can pass by the derivation being
// constant.
function render(keyState: FingerprintKeyState): string {
  return renderToStaticMarkup(
    createElement(
      NavigationTransitionProvider,
      null,
      createElement(ExceptionsClient, {
        items: [],
        blocked: [blockedRow(FRESH, CURRENT_VERSION), blockedRow(STALE, CURRENT_VERSION - 1)],
        includeTerminal: false,
        blockedWindow: '30m' as const,
        keyState,
        activePermanent: [],
        approvableBlocked: 1,
        renderedAt: Date.parse('2026-08-01T00:30:00.000Z'),
      }),
    ),
  );
}

// One row's slice of the markup — from where its reference is printed to where
// the next row's is. A whole-document match cannot tell the right row being
// disabled from the wrong one, which is the mistake this suite exists to catch.
function rowMarkup(markup: string, reference: string): string {
  const start = markup.indexOf(reference);
  expect(start, `row ${reference} is missing from the markup`).toBeGreaterThan(-1);
  const next = REFERENCES.map((r) => markup.indexOf(r)).filter((i) => i > start);
  return markup.slice(start, next.length > 0 ? Math.min(...next) : markup.length);
}

// Anchored on the leading whitespace so `aria-disabled=""`/`data-disabled=""`
// cannot satisfy it, and so Tailwind's `disabled:` class variants — which sit
// inside `class="…"` with no `=""` — do not.
const approveIsDisabled = (slice: string): boolean => /\sdisabled=""/.test(slice);

describe('the exceptions client asks blockedRowBlockReason per row', () => {
  it('disables Approve on a row recorded under a superseded key, and only that row', () => {
    const markup = render({ status: 'present', version: CURRENT_VERSION });

    expect(approveIsDisabled(rowMarkup(markup, STALE))).toBe(true);
    expect(approveIsDisabled(rowMarkup(markup, FRESH))).toBe(false);
  });

  it('shows the stale row the reason meta.ts writes, naming both key versions', () => {
    // The words come from `blockedRowBlockReason`, not from the view — this is
    // the machine-local copy that only a host beside the store may show, and
    // the whole reason the prop became a callback.
    const markup = render({ status: 'present', version: CURRENT_VERSION });
    const stale = rowMarkup(markup, STALE);

    expect(stale).toContain(`Recorded under fingerprint key v${String(CURRENT_VERSION - 1)}`);
    expect(stale).toContain(`the key is now v${String(CURRENT_VERSION)}`);
    expect(stale).toContain('not approvable');
    expect(rowMarkup(markup, FRESH)).not.toContain('not approvable');
  });

  it('disables every row when the key file is missing', () => {
    // No key means no row can be matched, whatever version it carries.
    const markup = render({ status: 'absent' });

    for (const reference of REFERENCES) {
      expect(approveIsDisabled(rowMarkup(markup, reference))).toBe(true);
      expect(rowMarkup(markup, reference)).toContain('Trigger the detection again.');
    }
  });

  it('disables every row when the key file cannot be read, and says so', () => {
    // A different problem with a different remedy: the key is intact and the
    // grants survive, so the copy must not tell the reader to delete it.
    const markup = render({ status: 'unreadable' });

    for (const reference of REFERENCES) {
      expect(approveIsDisabled(rowMarkup(markup, reference))).toBe(true);
      expect(rowMarkup(markup, reference)).toContain('do not delete the key');
    }
  });
});

describe('the exceptions client threads renderedAt into the blocked ledger', () => {
  it('renders the blocked-at label against the SSR instant, not the ambient clock', () => {
    // Pins the one line this PR actually adds — `renderedAt={renderedAt}` on
    // BlockedLedgerView in ExceptionsClient.tsx. Delete it and relativeTime
    // falls back to Date.now(), which would not read "30 minutes ago" for a
    // fixture blocked at 2026-08-01T00:00 and rendered at 2026-08-01T00:30.
    const markup = render({ status: 'present', version: CURRENT_VERSION });
    expect(markup).toContain('30 minutes ago');
  });
});

describe('the exceptions client threads renderedAt into the exceptions table', () => {
  it('renders the expiry label against the SSR instant, not the ambient clock', () => {
    // Mirrors the ledger pin above, for the sibling this PR also wires:
    // `renderedAt={renderedAt}` on ExceptionsTableView in ExceptionsClient.tsx.
    // Delete it and relativeTime falls back to Date.now(), which would not
    // read "in 30 minutes" for a grant expiring 2026-08-01T01:00 when rendered
    // at 2026-08-01T00:30.
    const markup = renderToStaticMarkup(
      createElement(
        NavigationTransitionProvider,
        null,
        createElement(ExceptionsClient, {
          items: [exceptionRow({ expiresAt: '2026-08-01T01:00:00.000Z' })],
          blocked: [],
          includeTerminal: false,
          blockedWindow: '30m' as const,
          keyState: { status: 'present', version: CURRENT_VERSION },
          activePermanent: [],
          approvableBlocked: 0,
          renderedAt: Date.parse('2026-08-01T00:30:00.000Z'),
        }),
      ),
    );

    expect(markup).toContain('in 30 minutes');
  });
});
