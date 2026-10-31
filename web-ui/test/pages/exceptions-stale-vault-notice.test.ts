// The standing notice the Exceptions route shows when vault entries are off the
// current fingerprint key — a rotation whose per-row re-key did not reach them.
//
// Server-rendered off a store count rather than set from what `rotateKey`
// returned, and that is the property this suite exists for. A disclosure held in
// client state is gone the moment this route unmounts, which happens on the way
// into any grant detail page, while the rows it named stay stale for days; it
// also never fires at all for a rotation run from `aka exception rotate-key`,
// which no dashboard render saw. So the test renders statically: if the notice
// survives a render with no effects and no transition, it survives a reload.
//
// The sentence itself is pinned in @akasecurity/schema's own suite. What cannot
// be seen from there is the route's ARITHMETIC — the note takes (refreshed,
// skipped) and the store gives (stale, total), so the host has to pass
// `total - stale` as the first argument. Get that subtraction backwards and the
// page states a plausible, wrong fraction, which is why the cases below assert
// against the shared helper called with the numbers the store actually holds.
import type { BlockedDetectionDescriptor, FingerprintKeyState } from '@akasecurity/schema';
import { vaultRefreshShortfallNote } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

vi.mock('next/navigation', () => ({
  usePathname: () => '/exceptions',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { ExceptionsClient } = await import('../../app/(app)/exceptions/ExceptionsClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const KEY_STATE: FingerprintKeyState = { status: 'present', version: 4 };
const RENDERED_AT = Date.parse('2026-08-01T00:30:00.000Z');

function blockedRow(): BlockedDetectionDescriptor {
  return {
    reference: 'blk-1',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    keyVersion: 4,
    maskedValue: 'AKIA****************',
    sessionId: null,
    repo: 'acme/api',
    blockedAt: '2026-08-01T00:00:00.000Z',
  };
}

function render(vaultFingerprints: { stale: number; total: number }): string {
  return renderToStaticMarkup(
    createElement(
      NavigationTransitionProvider,
      null,
      createElement(ExceptionsClient, {
        items: [],
        blocked: [blockedRow()],
        includeTerminal: false,
        blockedWindow: '30m' as const,
        keyState: KEY_STATE,
        activePermanent: [],
        approvableBlocked: 1,
        vaultFingerprints,
        renderedAt: RENDERED_AT,
      }),
    ),
  );
}

/** The markup of every live region on the page, so an absence means something. */
function alertMarkup(markup: string): string {
  return [...markup.matchAll(/role="alert"[\s\S]*?<\/div>/g)].map((m) => m[0]).join('\n');
}

describe('the stale-vault notice on the Exceptions route', () => {
  it('states the shortfall as a live region when rows are off the current key', () => {
    const markup = render({ stale: 3, total: 10 });
    const expected = vaultRefreshShortfallNote(7, 3);

    // Non-null first: every assertion below reads this fixture, and a helper
    // that had started answering null would make the absence cases trivially
    // true with nothing naming the cause.
    expect(expected).not.toBeNull();
    expect(alertMarkup(markup)).toContain('3 of 10');
    expect(markup).toContain(expected ?? 'unreachable');
  });

  // The subtraction, pinned against the one arrangement that is right. Swap the
  // arguments in the component and the page renders "3 of 6" — a number a reader
  // cannot tell is wrong, which is why this is asserted rather than eyeballed.
  it('counts the shortfall against every row held, not against the fresh ones', () => {
    const markup = render({ stale: 3, total: 10 });
    expect(markup).not.toContain(vaultRefreshShortfallNote(3, 3) ?? 'unreachable');
    expect(markup).not.toContain('3 of 6');
  });

  // The positive control. Without it the two absence cases below would hold just
  // as well for a page that never renders the notice at all.
  it('says nothing when every row is on the current key', () => {
    const markup = render({ stale: 0, total: 10 });
    expect(alertMarkup(markup)).not.toContain('could not be re-keyed');
  });

  it('says nothing for an empty vault, which is not a shortfall', () => {
    const markup = render({ stale: 0, total: 0 });
    expect(alertMarkup(markup)).not.toContain('could not be re-keyed');
  });

  // A whole vault left behind is the case the one-shot count reported as "0
  // refreshed" and said nothing about. Here it is the loudest reading there is.
  it('states a whole vault left behind rather than reading as nothing happened', () => {
    const markup = render({ stale: 5, total: 5 });
    expect(alertMarkup(markup)).toContain('5 of 5');
  });

  // Not in place of the dialogs' error, and not an invitation to rotate again —
  // rotating again is the thing the sentence warns about, so the notice must not
  // be dressed as the failure that would prompt it.
  it('carries the cost of the only remedy there is', () => {
    const alerts = alertMarkup(render({ stale: 1, total: 4 }));
    expect(alerts).toContain('invalidates every exception grant a second time');
    expect(alerts).not.toContain('sev-critical');
  });
});
