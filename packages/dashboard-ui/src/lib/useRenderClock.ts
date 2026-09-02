'use client';
import { useMemo, useSyncExternalStore } from 'react';

/**
 * How often the clock re-reads while the tab is in front.
 *
 * The smallest unit these labels render is a minute (`relativeTime` rounds
 * `deltaSec / 60`), so ticking faster than that only buys renders nobody can
 * see. Ticking AT a minute would leave a label up to a whole minute stale,
 * which is the unit itself; half of it bounds the visible lag at 30s for two
 * renders a minute.
 *
 * That bound holds only in front. A backgrounded tab has its timers clamped,
 * and a long-hidden one is throttled harder still — Chrome drops to roughly
 * once a minute after a few minutes out of view — so the interval alone stops
 * bounding anything for the tab someone left open, which is the case this hook
 * exists for. They can come back to a label, and on the detail route to a
 * revoke form gated on a stale `active`, from before they went away. The
 * visibility listener below is what bounds that at "as soon as you look at it".
 */
export const CLOCK_TICK_MS = 30_000;

interface ClockStore {
  subscribe: (onChange: () => void) => () => void;
  getSnapshot: () => number;
}

/**
 * The wall clock, as something React can subscribe to.
 *
 * `getSnapshot` has to return a CACHED value — React calls it repeatedly and
 * compares the results, so handing back a fresh `Date.now()` each time reads
 * as an endlessly-changing store and loops. Hence the held `now`, republished
 * on a tick rather than computed on read.
 */
function createClockStore(tickMs: number, serverInstant: number): ClockStore {
  // Seeded from the server's instant rather than read from the clock, because
  // this runs during a render, and a render may not read a moving source.
  let now = serverInstant;
  const listeners = new Set<() => void>();
  let timer: ReturnType<typeof setInterval> | undefined;

  const publish = (): void => {
    now = Date.now();
    for (const listener of listeners) listener();
  };

  // Only on the way back TO visible. Publishing as a tab is hidden would spend
  // a render nobody can see, which is what the throttle is for.
  const onVisibilityChange = (): void => {
    if (document.visibilityState === 'visible') publish();
  };

  return {
    subscribe(onChange: () => void): () => void {
      listeners.add(onChange);
      if (timer === undefined) {
        // React subscribes after the commit, so this is the first moment the
        // clock may be read — past hydration, where reading it is safe. It
        // catches up here rather than waiting out a tick: hydration can land
        // long after the server render on a slow connection, and a page that
        // waited 30s for its first correction would be showing a stale label
        // for exactly as long as anyone is most likely to be looking at it.
        // React re-reads the snapshot immediately after subscribing, which is
        // what turns this into a render.
        now = Date.now();
        timer = setInterval(publish, tickMs);
        // A backgrounded tab has its timers throttled, so the interval above
        // stops bounding anything the moment someone switches away. Catching
        // the return is what keeps the first thing they see current.
        document.addEventListener('visibilitychange', onVisibilityChange);
      }
      return () => {
        listeners.delete(onChange);
        if (listeners.size === 0 && timer !== undefined) {
          clearInterval(timer);
          timer = undefined;
          document.removeEventListener('visibilitychange', onVisibilityChange);
        }
      };
    },
    getSnapshot: () => now,
  };
}

/**
 * The instant relative labels should be measured against, starting from the
 * one an SSR host captured and moving on from there.
 *
 * A server render and the hydration render that follows it must agree, so a
 * label may not be measured against the browser's clock on the first pass:
 * `Date.now()` differs between the two by however long the payload took to
 * arrive, and a minute boundary crossed in that gap changes the text. Passing
 * the server's instant down fixes that, and freezing it there is what makes a
 * page left open go stale — the labels stop moving, and a lifecycle state
 * derived from `expiresAt` keeps reading `active` after the grant has expired.
 *
 * Both halves are load-bearing, and they are what the three arguments below
 * separate. `getServerSnapshot` — the third — is what the server render AND
 * the hydration render read, so it returns the instant the host passed in and
 * the two passes cannot disagree. `getSnapshot` is what every render after
 * that reads, so the clock starts moving again once hydration is done.
 *
 * The first half is the one that is easy to lose: serve the live clock to
 * both and the mismatch is back, invisibly, because a static render still
 * looks right.
 */
export function useRenderClock(renderedAt: number, tickMs: number = CLOCK_TICK_MS): number {
  const store = useMemo(() => createClockStore(tickMs, renderedAt), [tickMs, renderedAt]);
  return useSyncExternalStore(store.subscribe, store.getSnapshot, () => renderedAt);
}
