// What the detached reconcile worker (src/reconcile.ts) runs for its argv:
//
//   <sessionId> <transcriptPath> [<dueAt>]
//
// With no due time it runs one pass at once. With one it is the follow-up of a
// held pass: it waits until that time, then runs the pass as that follow-up, which
// does nothing if the hold it was asked for has been released or replaced.
import { setTimeout as delay } from 'node:timers/promises';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { loadConfig } from '@akasecurity/plugin-sdk';

import { reconcileSessionTail } from './usage.ts';

export interface ReconcileWorkerDeps {
  readonly sleep?: ((ms: number) => Promise<void>) | undefined;
  readonly now?: (() => number) | undefined;
  readonly config?: (() => PluginConfig) | undefined;
}

const WHOLE_MILLISECONDS = /^\d{1,15}$/;

export async function runReconcileWorker(
  args: readonly string[],
  deps: ReconcileWorkerDeps = {},
): Promise<void> {
  const [sessionId, transcriptPath, due] = args;
  // Both are required: a missing one means the spawn was malformed, and a pass is
  // dropped rather than guessing a path.
  if (!sessionId || !transcriptPath) return;
  const now = deps.now ?? Date.now;
  if (due === undefined) {
    await reconcileSessionTail((deps.config ?? loadConfig)(), sessionId, transcriptPath, now);
    return;
  }
  if (!WHOLE_MILLISECONDS.test(due)) return;
  const dueAt = Number(due);
  await (deps.sleep ?? ((ms: number) => delay(ms)))(Math.max(0, dueAt - now()));
  await reconcileSessionTail((deps.config ?? loadConfig)(), sessionId, transcriptPath, now, dueAt);
}
