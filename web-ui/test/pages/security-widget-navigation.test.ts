// @vitest-environment jsdom
//
// What the widget-navigation wrapper DOES. It is delegation over real anchors, so
// nothing about it is visible in static markup: every assertion here is a dispatched
// click, and each failure mode is silent — a wrapper that never intercepts still
// navigates (via a full page reload), and one that intercepts too much breaks
// open-in-new-tab without erroring.
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const push = vi.fn();
vi.mock('../../app/components/NavigationTransition', () => ({
  useNavigationTransition: () => ({ isPending: false, push, replace: vi.fn() }),
}));

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  push.mockClear();
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
});

/** Mount the wrapper around one anchor carrying `attrs`. */
async function mount(attrs: Record<string, string>): Promise<HTMLAnchorElement> {
  const { WidgetNavigation } = await import('../../app/(app)/security/WidgetNavigation.tsx');
  act(() => {
    root.render(createElement(WidgetNavigation, null, createElement('a', attrs, 'go')));
  });
  const anchor = container.querySelector('a');
  if (!anchor) throw new Error('no anchor rendered');
  return anchor;
}

/** Dispatch a click and report whether the default was prevented. */
function click(el: Element, init: MouseEventInit = {}): boolean {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true, button: 0, ...init });
  act(() => {
    el.dispatchEvent(event);
  });
  return event.defaultPrevented;
}

describe('WidgetNavigation', () => {
  it('routes a plain click through the shared transition', async () => {
    const anchor = await mount({ href: '/findings?action=blocked' });
    expect(click(anchor)).toBe(true);
    expect(push).toHaveBeenCalledWith('/findings?action=blocked');
  });

  it('reads the href ATTRIBUTE, not the absolutised property', async () => {
    // `anchor.href` returns `http://localhost/findings...`, which fails every
    // same-origin test written against it — the handler would no-op and every click
    // would silently fall back to a full document load with nothing failing.
    const anchor = await mount({ href: '/findings' });
    expect(anchor.href).toMatch(/^https?:\/\//);
    expect(anchor.getAttribute('href')).toBe('/findings');
    click(anchor);
    expect(push).toHaveBeenCalledWith('/findings');
  });

  it('routes a click that lands on a child of the anchor', async () => {
    // Rows are anchors wrapping spans, so the event target is nearly never the
    // anchor itself — without `closest`, real clicks would not be intercepted.
    const anchor = await mount({ href: '/findings' });
    const span = document.createElement('span');
    anchor.append(span);
    expect(click(span)).toBe(true);
    expect(push).toHaveBeenCalledWith('/findings');
  });

  it.each([
    ['meta', { metaKey: true }],
    ['ctrl', { ctrlKey: true }],
    ['shift', { shiftKey: true }],
    ['alt', { altKey: true }],
    ['middle button', { button: 1 }],
  ])('leaves a %s click to the browser', async (_label, init) => {
    // The href is real, so these still work — open-in-new-tab, open-in-new-window
    // and copy-link must not be swallowed by the interception.
    const anchor = await mount({ href: '/findings' });
    expect(click(anchor, init)).toBe(false);
    expect(push).not.toHaveBeenCalled();
  });

  it('leaves a protocol-relative href to the browser', async () => {
    // `//evil.example` starts with a slash and is cross-origin: a naive same-origin
    // test passes it straight to the router.
    const anchor = await mount({ href: '//evil.example/findings' });
    expect(click(anchor)).toBe(false);
    expect(push).not.toHaveBeenCalled();
  });

  it.each(['/\\evil.example', '/\\/evil.example'])(
    'leaves the backslash-escaped host %s to the browser',
    async (href) => {
      // The WHATWG URL parser treats a backslash as a second slash, so these resolve
      // to http://evil.example/ despite starting with a single slash — a prefix test
      // for `//` alone lets them through to the router.
      const anchor = await mount({ href });
      expect(new URL(href, 'http://localhost/').origin).toBe('http://evil.example');
      expect(click(anchor)).toBe(false);
      expect(push).not.toHaveBeenCalled();
    },
  );

  it('leaves an absolute external href to the browser', async () => {
    const anchor = await mount({ href: 'https://evil.example/findings' });
    expect(click(anchor)).toBe(false);
    expect(push).not.toHaveBeenCalled();
  });

  it('leaves a download and an explicit target to the browser', async () => {
    const download = await mount({ href: '/export.csv', download: '' });
    expect(click(download)).toBe(false);
    const blank = await mount({ href: '/findings', target: '_blank' });
    expect(click(blank)).toBe(false);
    expect(push).not.toHaveBeenCalled();
  });

  it('ignores a click that reaches no anchor at all', async () => {
    await mount({ href: '/findings' });
    expect(click(container.firstElementChild ?? container)).toBe(false);
    expect(push).not.toHaveBeenCalled();
  });
});
