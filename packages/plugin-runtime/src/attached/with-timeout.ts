/**
 * 2s: the bound every network call and every posture fs op races against.
 * Async I/O only — the posture module's synchronous node:sqlite scan cannot
 * be preempted by this (see the non-preemptible note in posture-snapshot.ts).
 */
export const REQUEST_TIMEOUT_MS = 2000;

export function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error('attached gateway request timed out'));
    }, ms);
  });
  // If the request loses the race, swallow its eventual rejection so it never
  // surfaces as an unhandled rejection after the race has already settled.
  promise.catch(() => undefined);
  return Promise.race([promise, timeout]).finally(() => {
    clearTimeout(timer);
  });
}
