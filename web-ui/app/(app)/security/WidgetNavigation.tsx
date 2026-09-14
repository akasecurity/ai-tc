'use client';

import type { MouseEvent, ReactNode } from 'react';

import { useNavigationTransition } from '../../components/NavigationTransition';

/**
 * Routes the widget deep links through the app's shared navigation transition.
 *
 * The links themselves are real `<a href>`s rendered by `@akasecurity/dashboard-ui`,
 * which takes no router dependency — that is what lets the same views run under a
 * different host. In the App Router a bare anchor is a FULL DOCUMENT navigation,
 * reloading the whole app; intercepting the plain left-click here turns it back
 * into a client transition with the shell's progress bar, without the views ever
 * learning which router they are under.
 *
 * Delegated from one element rather than wired per link so it covers every anchor
 * the region renders, including the Recommended Actions CTA the card already had.
 * No `role`/`tabIndex`/key handler belongs on this wrapper: the interactive things
 * are the anchors, which are natively focusable, and pressing Enter on one fires a
 * click that reaches this handler like any other.
 */
export function WidgetNavigation({ children }: { children: ReactNode }) {
  const { push } = useNavigationTransition();

  return (
    <div
      onClick={(event: MouseEvent<HTMLDivElement>) => {
        // Anything but an unmodified primary click keeps the browser's own
        // behaviour, so open-in-new-tab, open-in-new-window and copy-link all
        // still work — the href is real, and this only ever replaces the default
        // same-tab navigation.
        if (
          event.defaultPrevented ||
          event.button !== 0 ||
          event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.altKey
        ) {
          return;
        }
        // `Element`, not `HTMLElement`: every row here holds an inline SVG icon, so a
        // click frequently lands on an SVGElement. `closest` is inherited from
        // Element, which is what makes that work — asserting HTMLElement would be a
        // false claim about the common case.
        const clicked = event.target;
        const anchor = clicked instanceof Element ? clicked.closest('a') : null;
        if (!anchor) return;
        // `getAttribute`, never the `href` PROPERTY: the property is absolutised to
        // `http://host/...`, so a same-origin test against it never matches and every
        // click would silently fall through to a full reload with nothing failing.
        const href = anchor.getAttribute('href');
        // A same-origin path is the only thing the router may be handed. Several
        // shapes start with a slash and are NOT same-origin: `//host` is
        // protocol-relative, and the WHATWG URL parser treats a backslash as a
        // second slash, so `/\host` resolves to `http://host/` too. Resolve against
        // the current origin and compare, rather than pattern-matching the prefixes.
        if (!href?.startsWith('/')) return;
        const resolved = new URL(href, window.location.href);
        if (resolved.origin !== window.location.origin) return;
        // A download or an explicit target is asking for something this cannot do.
        if (anchor.hasAttribute('download')) return;
        const target = anchor.getAttribute('target');
        if (target && target !== '_self') return;

        event.preventDefault();
        push(href);
      }}
    >
      {children}
    </div>
  );
}
