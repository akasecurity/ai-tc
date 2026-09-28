// Refusal.tsx's refusedControlProps/RefusalReason are the shape every
// APP-LOCAL refused control spreads/renders (the enterprise dashboard's
// PERMISSION_REFUSAL buttons, per docs/superpowers/specs/2026-09-28-locked-
// write-controls-design.md) — so unlike this package's OWN views, which
// import shared/Refusal.tsx relatively, an outside app can only reach it
// through the package root. This is the one test that proves the barrel
// re-exports it, not merely that the module itself behaves.
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { RefusalReason, refusedControlProps } from '../../src/index.ts';

describe('the package root', () => {
  it('re-exports refusedControlProps', () => {
    const props = refusedControlProps(
      'reason-1',
      'You do not have enough permissions.',
      'hover:bg-surface',
    );

    expect(props).toEqual({
      'aria-disabled': true,
      'aria-describedby': 'reason-1',
      title: 'You do not have enough permissions.',
      className: 'cursor-not-allowed opacity-50 hover:bg-surface',
    });
  });

  it('re-exports RefusalReason', () => {
    const html = renderToStaticMarkup(
      <RefusalReason id="reason-1" dataSlot="test-reason">
        You do not have enough permissions.
      </RefusalReason>,
    );

    expect(html).toContain('id="reason-1"');
    expect(html).toContain('data-slot="test-reason"');
    expect(html).toContain('You do not have enough permissions.');
  });
});
