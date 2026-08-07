import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ShowMore } from '../../src/findings/ShowMore.tsx';

const TOGGLE = 'Show more';

describe('ShowMore', () => {
  it('renders a short value in full with no toggle', () => {
    const html = renderToStaticMarkup(<ShowMore value="A******Z" />);
    expect(html).toContain('A******Z');
    expect(html).not.toContain(TOGGLE);
  });

  it('renders a value at exactly the collapse length in full with no toggle', () => {
    const value = 'a'.repeat(80);
    const html = renderToStaticMarkup(<ShowMore value={value} />);
    expect(html).toContain(value);
    expect(html).not.toContain(TOGGLE);
  });

  it('truncates a value past the collapse length and shows the toggle', () => {
    const value = `${'a'.repeat(80)}TAILMARKER`;
    const html = renderToStaticMarkup(<ShowMore value={value} />);
    expect(html).toContain(`${'a'.repeat(80)}…`);
    expect(html).not.toContain('TAILMARKER');
    expect(html).toContain(TOGGLE);
  });
});
