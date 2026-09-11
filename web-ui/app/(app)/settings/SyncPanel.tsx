'use client';

import { SyncPanelView, useRenderClock } from '@akasecurity/dashboard-ui';
import { useRouter } from 'next/navigation';
import { useEffect, useState, useTransition } from 'react';

import { syncNow } from './actions';
import type { SyncPanelData } from './sync-panel-data.ts';

/**
 * How often the panel re-asks the server while a pass is running.
 *
 * The bars come from a COUNT over the ledger, taken during the server render,
 * so "live" here means re-rendering rather than streaming: there is no channel
 * from a detached child back to this page, and inventing one for a progress bar
 * would be a daemon's worth of machinery for a number a re-read already has.
 *
 * Four seconds is chosen against what the reader is watching, not against the
 * cost: a drain sends in batches, so the bars move in steps, and a poll much
 * faster than a batch spends renders on identical numbers. The read it drives
 * is the one the store's per-kind partition was given an `INDEXED BY` for —
 * that index is what keeps this a walk in index order rather than a scan of the
 * largest table in the store, every four seconds.
 */
export const SYNC_POLL_MS = 4_000;

/**
 * How long the panel keeps polling after asking for a pass that has not yet
 * appeared.
 *
 * The action returns when the CHILD EXISTS, not when it has taken the claim, so
 * for a moment after a successful start there is nothing to see — `running` is
 * still false and the bars have not moved. Without this the panel would poll
 * once, find nothing, and go quiet for a pass that was seconds from starting.
 *
 * Bounded rather than open-ended because the other outcome is real: a child that
 * dies before claiming — an unreadable store, a refusal the drain records and
 * exits on — never appears at all, and a panel waiting on `running` alone would
 * poll for the life of the tab.
 */
export const SYNC_START_GRACE_MS = 20_000;

/**
 * The interactive half of the sync panel: the control, and keeping the numbers
 * beside it current.
 *
 * Separate from `SettingsClient` rather than folded into it, because the two
 * share nothing. That component owns a form whose every control is one write;
 * this owns a button that starts a process and then watches the store. Folding
 * them would put one `busy` flag across both, so asking for a pass would
 * disable the settings form.
 */
export function SyncPanel({ sync, renderedAt }: { sync: SyncPanelData; renderedAt: number }) {
  const router = useRouter();
  const [startError, setStartError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();
  const [awaitingStart, setAwaitingStart] = useState(false);

  // The server's instant, advanced after hydration so "3 minutes ago" keeps up
  // in a tab left open. The panel re-renders from the server only while a pass
  // is running; when nothing is, this is the only thing that moves the label.
  const now = useRenderClock(renderedAt);

  const polling = sync.running || awaitingStart;
  useEffect(() => {
    if (!polling) return undefined;
    const timer = setInterval(() => {
      // A hidden tab's timers are throttled but not stopped, and a render
      // nobody can see is a store read nobody asked for. The next visible tick
      // catches up, and so does any navigation back to this page.
      if (document.visibilityState === 'visible') router.refresh();
    }, SYNC_POLL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [polling, router]);

  // The wait always ends on the timer, never early on `running`. Ending it the
  // moment a claim appeared would be the obvious optimisation and would buy
  // nothing: polling continues on `running` either way, and the only way to
  // stop it early is to write state from inside an effect, which is a render
  // React is entitled to discard.
  useEffect(() => {
    if (!awaitingStart) return undefined;
    const timer = setTimeout(() => {
      setAwaitingStart(false);
    }, SYNC_START_GRACE_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [awaitingStart]);

  return (
    <SyncPanelView
      {...sync}
      renderedAt={now}
      busy={busy}
      startError={startError ?? undefined}
      onSyncNow={() => {
        startTransition(async () => {
          try {
            const result = await syncNow();
            setStartError(result.ok ? null : (result.error ?? 'No pass was started.'));
            setAwaitingStart(result.ok);
          } catch {
            // The action is written to RETURN a refusal rather than throw, but
            // that only covers what happens inside it. The call itself can
            // still reject — a dropped connection, a framework-level error —
            // and an unhandled rejection inside a transition takes the whole
            // page to the error boundary, losing the settings form's unsaved
            // answers for a fault a retry would clear.
            setStartError('The request could not be sent — check your connection and try again.');
            setAwaitingStart(false);
          }
        });
      }}
    />
  );
}
