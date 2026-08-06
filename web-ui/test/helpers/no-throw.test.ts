import { describe, expect, it } from 'vitest';

import { expectNoRejection } from './no-throw.ts';

// The helper a block of cases leans on gets its own suite, or it can be weakened
// back with nothing going red. `expectNoRejection` is the load-bearing assertion
// under every payload-validation case in `test/actions/exceptions.test.ts`, and
// the property it guards — the action RETURNED its refusal rather than rejecting
// — is one an ordinary `await` cannot state.
//
// One thing here is deliberately UNLIKE the sibling `no-echo.test.ts`, which
// carries a control showing the form it replaced stays green. No such control
// exists for this helper, because a plain `await` on a rejecting action is also
// red. What it buys is legibility rather than strength, and the third case pins
// that distinction rather than claiming the stronger one.

// The realistic failure: a field typed `string` arrives as a number, and the
// action rejects from deep inside instead of returning `{ ok: false, error }`.
const ACTION_ERROR = 'payload.reason.trim is not a function';
const rejecting = (): Promise<{ ok: boolean }> => Promise.reject(new TypeError(ACTION_ERROR));

// The error a thunk threw, captured OUTSIDE its own catch — a `try`/`catch`
// around the call asserts on the test's own guard error instead, which carries
// nothing from the helper and passes however the helper is weakened.
async function errorFrom(fn: () => Promise<unknown>): Promise<Error | undefined> {
  return fn().then(
    () => undefined,
    (err: unknown) => err as Error,
  );
}

describe('expectNoRejection', () => {
  it('hands back a resolved value unchanged', async () => {
    const value = { ok: false, error: "'reason' must be a string" } as const;
    // Identity, not equality: the caller asserts on this object afterwards, so
    // a helper that rebuilt it would be substituting its own shape for the
    // action's.
    expect(await expectNoRejection(() => Promise.resolve(value))).toBe(value);
  });

  it('fails on a rejection, and names the underlying error', async () => {
    const err = await errorFrom(() => expectNoRejection(rejecting));
    // Assert what it SAYS before what it carries: a helper that stopped failing
    // returns `undefined` here, and every assertion below would then throw on a
    // missing property rather than fail on the property being tested.
    expect(err).toBeDefined();
    expect(err?.message).toContain('rejected rather than returning');
    // The half that is the whole point when this fires, and the half that was
    // missing: the message has to carry the error WHOLE. Built as a comparison
    // whose actual side was the error, vitest elided it to
    // `rejected with TypeError: payload.reas…` — enough to see that something
    // rejected, never enough to see which field did it.
    expect(err?.message).toContain(ACTION_ERROR);
  });

  it('buys legibility, not redness — the plain await fails too', async () => {
    // A plain `await` on the rejecting action surfaces the action's OWN
    // TypeError: it names a line inside the action and says nothing about the
    // contract that broke.
    const plain = await errorFrom(async () => {
      const res = await rejecting();
      expect(res.ok).toBe(false);
    });
    expect(plain).toBeInstanceOf(TypeError);
    expect(plain?.message).toBe(ACTION_ERROR);

    // The helper's failure is an assertion about the property instead, and it
    // carries the TypeError above rather than discarding it. Both are red; only
    // this one is readable, which is the entire claim being made for it.
    const named = await errorFrom(() => expectNoRejection(rejecting));
    expect(named).not.toBeInstanceOf(TypeError);
    expect(named?.message).toContain('rejected rather than returning');
    expect(named?.message).toContain(ACTION_ERROR);
  });

  it('returns a resolved undefined rather than reading it as a rejection', async () => {
    // "Did it reject?" must not collapse into "did it return something truthy?"
    // — an action resolving `undefined` is a different defect, and catching it
    // here would make every caller's failure ambiguous between the two.
    await expect(expectNoRejection(() => Promise.resolve(undefined))).resolves.toBeUndefined();
  });
});
