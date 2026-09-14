import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

// The shell is a client component reading the router; neither is available under
// vitest, so both seams are stubbed and the markup is rendered statically.
vi.mock('next/navigation', () => ({
  usePathname: () => '/findings',
}));
vi.mock('../app/components/NavigationTransition', () => ({
  NavigationProgressBar: () => null,
  useNavigationTransition: () => ({ isPending: false, push: vi.fn(), replace: vi.fn() }),
}));

async function render(): Promise<string> {
  const { AppShell } = await import('../app/components/AppShell.tsx');
  return renderToStaticMarkup(createElement(AppShell, null, 'page'));
}

describe('the sidebar mark', () => {
  it('links to the security page', async () => {
    const html = await render();
    // Anchored on the mark's own wrapper rather than searching the whole shell:
    // every nav row is a link too, and one of them already points at /security, so
    // a bare `toContain('/security')` would pass with no link on the mark at all.
    const mark = /<a([^>]*)>\s*<svg[^>]*class="[^"]*h-8[^"]*"/.exec(html);
    expect(mark, 'the mark is not wrapped in a link').not.toBeNull();
    expect(mark?.[1]).toContain('href="/security"');
  });

  it('gives the link an accessible name and leaves the mark decorative', async () => {
    const html = await render();
    // The name belongs to the thing that is activated. Announcing the mark as well
    // would read it twice, so it becomes aria-hidden when it gains a link.
    expect(html).toContain('aria-label="AKA — go to Security"');
    expect(html).not.toContain('aria-label="AKA"');
  });
});
