/**
 * Capture the error a thunk threw, outside its own catch.
 *
 * A `try { fn(); throw new Error('expected to throw') } catch` shape reads as
 * an error-capture but is really a passthrough of whatever `fn` threw — the
 * `throw` on the not-thrown path is caught by the SAME catch, which is easy to
 * get backwards once a case is copied a few times. Naming the capture once
 * here is what keeps every caller in this package pointed at the same shape.
 *
 * Synchronous only — `client.test.ts`'s async paths use
 * `.then(() => undefined, (e) => e as Error)` instead, which needs no thunk.
 */
export function thrownBy(fn: () => unknown): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err as Error;
  }
}
