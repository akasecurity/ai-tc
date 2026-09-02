// @vitest-environment jsdom
//
// The one hook in this package, and the only test here that needs a DOM — a
// server render never runs an effect, so the half of this hook that matters
// after hydration is invisible to `renderToStaticMarkup`. The environment is
// opted into per file rather than package-wide: every other suite covers pure
// helpers or static markup and gains nothing from jsdom but time.
//
// Two properties, and they pull in opposite directions, which is the whole
// reason the seam exists. The FIRST value has to be the instant the server
// rendered at, or hydration disagrees with the markup it is reconciling
// against. Every value after that has to come from the live clock, or a page
// left open freezes. A test that only checked one of them would pass on an
// implementation that reintroduces the bug this hook exists to fix.
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CLOCK_TICK_MS, useRenderClock } from '../../src/lib/useRenderClock.ts';

// The instant an SSR host captured, and a browser clock an hour ahead of it.
// That gap is the mismatch: it is what the label would move by if the first
// client render read the ambient clock instead of the prop.
const RENDERED_AT = Date.parse('2026-07-05T00:00:00.000Z');
const AMBIENT = RENDERED_AT + 60 * 60 * 1000;

// Records what the hook returned on each render, in order, so the first pass
// can be told apart from what the subscription does to it afterwards. Reading
// the DOM instead would only ever show the settled value — `act` flushes the
// subscribe-and-re-read before control comes back.
function Probe({ seen, tickMs = CLOCK_TICK_MS }: { seen: number[]; tickMs?: number }) {
  const now = useRenderClock(RENDERED_AT, tickMs);
  seen.push(now);
  return null;
}

describe('useRenderClock', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(AMBIENT);
    (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
      true;
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns the server instant on a server render, never the ambient clock', () => {
    const seen: number[] = [];
    renderToStaticMarkup(<Probe seen={seen} />);

    // No effect runs here, so this is the markup hydration will be handed.
    expect(seen).toEqual([RENDERED_AT]);
  });

  it('starts at the server instant, so the hydration render reproduces the markup', () => {
    const seen: number[] = [];
    const root = createRoot(document.createElement('div'));
    act(() => {
      root.render(<Probe seen={seen} />);
    });

    // Order is the assertion. Seeding the store from the live clock would make
    // the first value AMBIENT and every label on the page shift under
    // hydration — and the settled value below would be identical either way,
    // so only reading the FIRST render catches it.
    expect(seen[0]).toBe(RENDERED_AT);
    expect(seen.at(-1)).toBe(AMBIENT);
  });

  it('catches up on mount rather than waiting out a whole tick', () => {
    const seen: number[] = [];
    const root = createRoot(document.createElement('div'));
    act(() => {
      root.render(<Probe seen={seen} />);
    });

    // Hydration can land long after the server render. Without the immediate
    // read the page would keep showing the server's instant for a full tick,
    // which is the moment someone is most likely to be looking at it.
    expect(seen.at(-1)).toBe(AMBIENT);
    expect(vi.getTimerCount()).toBe(1);
  });

  it('keeps moving on the interval', () => {
    const seen: number[] = [];
    const root = createRoot(document.createElement('div'));
    act(() => {
      root.render(<Probe seen={seen} />);
    });
    act(() => {
      vi.advanceTimersByTime(CLOCK_TICK_MS);
    });

    expect(seen.at(-1)).toBe(AMBIENT + CLOCK_TICK_MS);
  });

  it('stops on unmount, so a torn-down page leaves no interval behind', () => {
    const seen: number[] = [];
    const root = createRoot(document.createElement('div'));
    act(() => {
      root.render(<Probe seen={seen} />);
    });
    act(() => {
      root.unmount();
    });
    const settled = seen.length;

    act(() => {
      vi.advanceTimersByTime(CLOCK_TICK_MS * 3);
    });

    expect(seen).toHaveLength(settled);
    expect(vi.getTimerCount()).toBe(0);
  });
});
