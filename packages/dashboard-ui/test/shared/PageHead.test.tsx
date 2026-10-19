import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { PageHead } from '../../src/shared/PageHead.tsx';

// The page head's height is declared in two places that cannot see each other:
// this component, and web-ui's PageHeadSkeleton, which draws two bars in its
// place on every one of the dashboard's routes. Nothing in either package can
// measure the other, so what is pinned here are the three tokens that height is
// the sum of.
//
// Summing to the same total is not sufficient and was not what broke: the
// skeleton's bars were `h-7` and `h-4` under a `gap-2` — 28 + 8 + 16 = 52
// against this component's 32 + 4 + 20 = 56 — so every page head moved 4px on
// reveal. The skeleton now mirrors the parts, and changing one here without
// changing it there puts the shift back.

function render(sub?: string): string {
  // `exactOptionalPropertyTypes` refuses an explicit `sub={undefined}`, and the
  // absent case is what the second test is about — so omit the prop entirely.
  return renderToStaticMarkup(
    sub === undefined ? <PageHead title="Policies" /> : <PageHead title="Policies" sub={sub} />,
  );
}

/** The whole opening tag carrying `attr`. */
function tagWithAttr(html: string, attr: string): string {
  const at = html.indexOf(attr);
  expect(at).toBeGreaterThan(-1);
  const open = html.lastIndexOf('<', at);
  return html.slice(open, html.indexOf('>', at) + 1);
}

describe('PageHead', () => {
  it('pins the three tokens web-ui reserves 80px from', () => {
    const html = render('Enforcement actions detections take when they match');

    // 24px of padding under the pair...
    expect(tagWithAttr(html, 'class="flex items-start')).toContain('pb-6');
    // ...a 32px title (text-2xl carries a 32px line box)...
    expect(html).toContain('text-2xl');
    // ...and a 20px sub 4px below it (text-sm carries a 20px line box).
    const sub = tagWithAttr(html, '<p');
    expect(sub).toContain('mt-1');
    expect(sub).toContain('text-sm');
  });

  it('drops the sub line entirely when there is none', () => {
    // The skeleton always draws two bars, so a head with no sub is 24px shorter
    // than what is reserved for it. No route pairs the two that way today.
    expect(render()).not.toContain('<p');
  });

  it('renders the title as an h1 by default', () => {
    expect(render()).toContain(
      '<h1 class="font-display font-semibold text-text text-2xl">Policies</h1>',
    );
  });

  it('renders a level-3 head as a smaller h3 whose actions wrap', () => {
    const html = renderToStaticMarkup(
      <PageHead title="API keys" sub="Scoped keys" actions={<button>New key</button>} level={3} />,
    );

    expect(html).toBe(
      '<div class="flex items-start justify-between gap-4 flex-wrap pb-5">' +
        '<div class="min-w-0">' +
        '<h3 class="font-display font-semibold text-text text-lg">API keys</h3>' +
        '<p class="mt-1 text-sm text-text-3">Scoped keys</p>' +
        '</div>' +
        '<div class="flex shrink-0 items-center gap-2"><button>New key</button></div>' +
        '</div>',
    );
  });
});
