// Refusal.tsx's refusedControlProps/RefusalReason are the shape a host app's own
// refused controls spread/render, so unlike this package's OWN views, which import
// shared/Refusal.tsx relatively, an outside app can only reach them through the
// package root. This is the one test that proves the barrel re-exports them, not
// merely that the module itself behaves.
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { RefusalReason, refusedControlProps } from '../../src/index.ts';

describe('the package root', () => {
  it('re-exports refusedControlProps', () => {
    const props = refusedControlProps(
      'reason-1',
      'This control is not available here.',
      'hover:bg-surface',
    );

    expect(props).toEqual({
      'aria-disabled': true,
      'aria-describedby': 'reason-1',
      title: 'This control is not available here.',
      className: 'cursor-not-allowed opacity-50 hover:bg-surface',
    });
  });

  it('re-exports RefusalReason', () => {
    const html = renderToStaticMarkup(
      <RefusalReason id="reason-1" dataSlot="test-reason">
        This control is not available here.
      </RefusalReason>,
    );

    expect(html).toContain('id="reason-1"');
    expect(html).toContain('data-slot="test-reason"');
    expect(html).toContain('This control is not available here.');
  });
});
