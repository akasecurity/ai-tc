// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';

import { accessibleName, visibleText } from './accessible-name.ts';

function fragment(html: string): HTMLElement {
  const host = document.createElement('div');
  host.innerHTML = html;
  return host;
}

describe('accessibleName', () => {
  it('uses a label on a role that may be named', () => {
    expect(accessibleName(fragment('A<span role="img" aria-label="dot">x</span>'))).toBe('Adot');
  });

  // A label on any of these is ignored, so the element contributes its content.
  it.each([
    ['a bare span', '<span aria-label="L">c</span>'],
    ['a paragraph', '<p aria-label="L">c</p>'],
    ['role=definition', '<span role="definition" aria-label="L">c</span>'],
    ['role=mark', '<span role="mark" aria-label="L">c</span>'],
    ['role=suggestion', '<span role="suggestion" aria-label="L">c</span>'],
    ['role=term', '<span role="term" aria-label="L">c</span>'],
    ['role=time', '<span role="time" aria-label="L">c</span>'],
    ['role=tooltip', '<span role="tooltip" aria-label="L">c</span>'],
  ])('ignores a label on %s', (_, html) => {
    expect(accessibleName(fragment(html))).toBe('c');
  });

  it('skips an aria-hidden subtree and keeps sr-only text', () => {
    expect(
      accessibleName(
        fragment('A<span aria-hidden="true">x</span><span class="sr-only">, </span>2'),
      ),
    ).toBe('A, 2');
  });
});

describe('visibleText', () => {
  it('drops sr-only text and keeps the rest', () => {
    expect(visibleText(fragment('A<span class="sr-only">, </span>2'))).toBe('A2');
  });
});
