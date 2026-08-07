import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ScrubbedValue } from '../../src/shared/ScrubbedValue.tsx';

// ScrubbedValue is the one presentational form for a resolved vault pointer.
// The load-bearing property is negative: in the masked and unavailable states
// the raw value must be absent from the produced markup entirely — not hidden,
// not truncated, absent. Rendered with react-dom's static renderer (this
// package's test environment is node, with no DOM).

const RAW = 'raw-vaulted-value-8829';
const DESCRIPTOR = {
  category: 'secret' as const,
  provider: 'aws',
  maskedMatch: 'raw-…9',
  occurrences: 3,
};

describe('ScrubbedValue', () => {
  it('renders the raw value when revealed', () => {
    const html = renderToStaticMarkup(<ScrubbedValue value={RAW} descriptor={DESCRIPTOR} />);
    expect(html).toContain(RAW);
    expect(html).toContain('data-slot="scrubbed-value"');
  });

  it('renders the raw value when the descriptor omits the provider segment', () => {
    const html = renderToStaticMarkup(
      <ScrubbedValue value={RAW} descriptor={{ category: 'secret', maskedMatch: 'raw-…9' }} />,
    );
    expect(html).toContain(RAW);
  });

  it('renders only the masked form when no raw value is available', () => {
    const html = renderToStaticMarkup(<ScrubbedValue value={null} descriptor={DESCRIPTOR} />);
    expect(html).toContain(DESCRIPTOR.maskedMatch);
    expect(html).not.toContain(RAW);
  });

  it('renders [unavailable] when there is neither value nor descriptor', () => {
    const html = renderToStaticMarkup(<ScrubbedValue value={null} descriptor={null} />);
    expect(html).toContain('[unavailable]');
    expect(html).not.toContain(RAW);
    expect(html).not.toContain(DESCRIPTOR.maskedMatch);
  });
});
