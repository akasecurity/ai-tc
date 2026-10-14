import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { TemplateUrl } from '../../src/data-shares/atoms.tsx';

function render(url: string): string {
  return renderToStaticMarkup(<TemplateUrl url={url} />);
}

// The markup TemplateUrl emits: one span per part, a template segment
// highlighted and a literal part plain, inside the mono wrapper.
function markup(...parts: { segment?: string; literal?: string }[]): string {
  const inner = parts
    .map(({ segment, literal }) =>
      segment === undefined
        ? `<span>${literal ?? ''}</span>`
        : `<span class="rounded bg-primary-tint px-1 font-semibold text-primary">${segment}</span>`,
    )
    .join('');
  return `<span class="break-all font-mono text-xs">${inner}</span>`;
}

describe('TemplateUrl', () => {
  it('highlights each ${…} segment between the literal parts', () => {
    expect(render('https://api.example.com/${id}/items')).toBe(
      markup({ literal: 'https://api.example.com/' }, { segment: '${id}' }, { literal: '/items' }),
    );
  });

  it('keeps the empty literal parts around a segment at either end', () => {
    expect(render('${base}/v1/${path}')).toBe(
      markup(
        { literal: '' },
        { segment: '${base}' },
        { literal: '/v1/' },
        { segment: '${path}' },
        { literal: '' },
      ),
    );
  });

  it('reads an empty ${} as literal text and keeps looking past it', () => {
    expect(render('/a/${}/${id}')).toBe(
      markup({ literal: '/a/${}/' }, { segment: '${id}' }, { literal: '' }),
    );
  });

  it('reads an unclosed ${ as literal text', () => {
    expect(render('/a/${id')).toBe(markup({ literal: '/a/${id' }));
  });

  it('runs a segment to the first } after its ${, across any ${ inside it', () => {
    expect(render('${a${b}c}')).toBe(
      markup({ literal: '' }, { segment: '${a${b}' }, { literal: 'c}' }),
    );
  });

  it('starts a segment at the $ right before the {', () => {
    expect(render('$${x}')).toBe(markup({ literal: '$' }, { segment: '${x}' }, { literal: '' }));
  });

  it('takes one pass over a long run of unclosed ${', { timeout: 5000 }, () => {
    // A segment pattern tried from every $ of a run with no closing } scans to
    // the end each time, which costs the square of the run's length.
    const url = `x${'${'.repeat(150_000)}`;
    expect(render(url)).toBe(markup({ literal: url }));
  });
});
