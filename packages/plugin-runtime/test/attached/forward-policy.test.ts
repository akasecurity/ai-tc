import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  BREAKER_COOLDOWN_MS,
  BREAKER_FAILURE_THRESHOLD,
  createForwardPolicy,
  DECISION_PATH_BUDGET_MS,
  FORWARD_BUDGET_MS,
  type ForwardFailureReason,
  readForwardHealth,
} from '../../src/attached/forward-policy';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aka-forward-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  vi.useRealTimers();
});

const stateFile = (): string => join(dir, 'attached-state.json');

/** The success shape, so a value assertion stays readable. */
const ok = <T>(value: T): { ok: true; value: T } => ({ ok: true, value });
/** The failure shape. */
const failed = (reason: ForwardFailureReason): { ok: false; reason: ForwardFailureReason } => ({
  ok: false,
  reason,
});

/**
 * An error shaped the way the transport raises one for an answered non-2xx:
 * the STATUS as a structured field, no message parsing involved.
 */
function refusal(status: number): Error & { status: number } {
  return Object.assign(new Error(`backend request failed with status ${String(status)}`), {
    status,
  });
}

/**
 * An error shaped the way the transport raises one for a route a deployment
 * does not have. Matched by NAME, exactly as the policy matches it — this
 * module classifies whatever the injected client throws, and a fake is not
 * required to be an instance of anything.
 */
function routeAbsent(): Error {
  return Object.assign(new Error('control plane does not serve /v1/audit-events/batch'), {
    name: 'RemoteRouteAbsent',
  });
}

/**
 * An error shaped the way the transport raises one for an ANSWERED non-2xx —
 * a status field, structurally, exactly as `refusal` above does for 401/403.
 */
function serverRejection(status: number): Error & { status: number } {
  return Object.assign(new Error(`control-plane request failed with status ${String(status)}`), {
    status,
  });
}

/**
 * An error shaped the way the client raises one for a body it refused to
 * send. Matched by NAME, exactly as `isInvalidRequest` matches it.
 */
function invalidRequestError(): Error {
  return Object.assign(new Error('refusing to send a malformed body'), {
    name: 'RemoteRequestInvalid',
  });
}

/** Drive the breaker to open by failing it THRESHOLD times. */
async function tripOpen(
  policy: { run: (op: () => Promise<unknown>) => Promise<unknown> },
  err: () => Error = () => new Error('backend down'),
) {
  for (let i = 0; i < BREAKER_FAILURE_THRESHOLD; i++) {
    await policy.run(() => Promise.reject(err()));
  }
}

describe('createForwardPolicy', () => {
  it('returns the value on success and writes no state file on the happy path', async () => {
    const policy = createForwardPolicy({ dir });
    await expect(policy.run(() => Promise.resolve('ok'))).resolves.toEqual(ok('ok'));
    // No transition happened, so the hot path did no writing at all.
    await expect(readdir(dir)).resolves.toEqual([]);
  });

  it('resolves a failure instead of throwing when the forward rejects', async () => {
    const policy = createForwardPolicy({ dir });
    await expect(policy.run(() => Promise.reject(new Error('boom')))).resolves.toEqual(
      failed('unreachable'),
    );
  });

  it('resolves a failure instead of throwing when the op throws SYNCHRONOUSLY', async () => {
    const policy = createForwardPolicy({ dir });
    // The op is called inside the try; a sync throw must degrade, not reject.
    await expect(
      policy.run(() => {
        throw new Error('sync boom');
      }),
    ).resolves.toEqual(failed('unreachable'));
  });

  // Both budget tests pre-warm the policy with one real-timer call first. The
  // first run() of a process reads attached-state.json from disk, and that read
  // is real async I/O the fake clock cannot advance — so arming the fake timers
  // before it settled meant withTimeout's setTimeout was created AFTER the
  // clock had already been advanced past it, and the race never resolved.
  // Warming first caches the state, leaving only a microtask before the timer
  // is armed; the advanceTimersByTimeAsync(0) below flushes exactly that.
  it('bounds a hanging forward by the general budget', async () => {
    const policy = createForwardPolicy({ dir });
    await policy.run(() => Promise.resolve('warm'));

    vi.useFakeTimers();
    const pending = policy.run(() => new Promise<string>(() => undefined));
    await vi.advanceTimersByTimeAsync(0);
    // One tick short of the budget it must still be pending, or this would
    // pass for a bound that does not exist.
    await vi.advanceTimersByTimeAsync(FORWARD_BUDGET_MS - 1);
    let settled = false;
    void pending.then(() => (settled = true));
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(2);
    // A timeout is not a verdict about the credential — it is the bucket that
    // says "try again", and mislabelling it would send a user to an
    // administrator over a slow link.
    await expect(pending).resolves.toEqual(failed('unreachable'));
  });

  it('bounds a decision-path forward by the tighter budget', async () => {
    expect(DECISION_PATH_BUDGET_MS).toBeLessThan(FORWARD_BUDGET_MS);
    const policy = createForwardPolicy({ dir });
    await policy.run(() => Promise.resolve('warm'));

    vi.useFakeTimers();
    const pending = policy.run(() => new Promise<string>(() => undefined), { decisionPath: true });
    await vi.advanceTimersByTimeAsync(0);
    // Past the decision-path bound but strictly short of the general one:
    // only a genuinely tighter budget can settle here.
    await vi.advanceTimersByTimeAsync(DECISION_PATH_BUDGET_MS + 1);
    await expect(pending).resolves.toEqual(failed('unreachable'));
  });

  it('opens after the threshold and then skips the network entirely', async () => {
    const policy = createForwardPolicy({ dir });
    await tripOpen(policy);

    const op = vi.fn(() => Promise.resolve('should not run'));
    // `breaker-open`, not a backend verdict: NOTHING WAS ASKED. A caller that
    // treated this as a refusal would be reporting on a request that was never
    // made — the same mistake `runPolicySync` avoids by returning null for a
    // sync it never performed.
    await expect(policy.run(op)).resolves.toEqual(failed('breaker-open'));
    // The point of the breaker: no timeout is paid because no call is made.
    expect(op).not.toHaveBeenCalled();
  });

  it('does not open before the threshold is reached', async () => {
    const policy = createForwardPolicy({ dir });
    for (let i = 0; i < BREAKER_FAILURE_THRESHOLD - 1; i++) {
      await policy.run(() => Promise.reject(new Error('down')));
    }
    const op = vi.fn(() => Promise.resolve('ran'));
    await expect(policy.run(op)).resolves.toEqual(ok('ran'));
    expect(op).toHaveBeenCalledTimes(1);
  });

  it('a success closes the breaker and resets the failure count', async () => {
    let clock = 1_000;
    const policy = createForwardPolicy({ dir, now: () => clock });
    for (let i = 0; i < BREAKER_FAILURE_THRESHOLD - 1; i++) {
      await policy.run(() => Promise.reject(new Error('down')));
    }
    await expect(policy.run(() => Promise.resolve('recovered'))).resolves.toEqual(ok('recovered'));

    // The count is genuinely reset: another THRESHOLD-1 failures must still
    // not open it. (If the reset were missing, this would trip.)
    clock += 1;
    for (let i = 0; i < BREAKER_FAILURE_THRESHOLD - 1; i++) {
      await policy.run(() => Promise.reject(new Error('down')));
    }
    const op = vi.fn(() => Promise.resolve('still closed'));
    await expect(policy.run(op)).resolves.toEqual(ok('still closed'));
    expect(op).toHaveBeenCalledTimes(1);
  });

  describe('half-open probe', () => {
    it('lets exactly one probe through after the cooldown, and closes on success', async () => {
      let clock = 10_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy);

      clock += BREAKER_COOLDOWN_MS;
      const probe = vi.fn(() => Promise.resolve('up again'));
      await expect(policy.run(probe)).resolves.toEqual(ok('up again'));
      expect(probe).toHaveBeenCalledTimes(1);

      // Closed now: a subsequent call goes straight through.
      const next = vi.fn(() => Promise.resolve('flowing'));
      await expect(policy.run(next)).resolves.toEqual(ok('flowing'));
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('re-opens for another cooldown when the probe fails', async () => {
      let clock = 10_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy);

      clock += BREAKER_COOLDOWN_MS;
      await expect(policy.run(() => Promise.reject(new Error('still down')))).resolves.toEqual(
        failed('unreachable'),
      );

      // Immediately after the failed probe the breaker is open again, so the
      // next call must not reach the network.
      const op = vi.fn(() => Promise.resolve('nope'));
      await expect(policy.run(op)).resolves.toEqual(failed('breaker-open'));
      expect(op).not.toHaveBeenCalled();
    });
  });

  describe('cross-process breaker', () => {
    it('a FRESH policy honours an open breaker written by a previous process', async () => {
      const clock = 50_000;
      const first = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(first);

      // A new process: no in-process state, only the file on disk. This is the
      // case the file exists for — a hook is short-lived, so without it every
      // hook would re-pay the full budget against a backend already known down.
      const fresh = createForwardPolicy({ dir, now: () => clock });
      const op = vi.fn(() => Promise.resolve('should not run'));
      await expect(fresh.run(op)).resolves.toEqual(failed('breaker-open'));
      expect(op).not.toHaveBeenCalled();
    });

    it('a fresh policy probes once the persisted cooldown has elapsed', async () => {
      const clock = 50_000;
      const first = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(first);

      const later = clock + BREAKER_COOLDOWN_MS;
      const fresh = createForwardPolicy({ dir, now: () => later });
      const op = vi.fn(() => Promise.resolve('probe'));
      await expect(fresh.run(op)).resolves.toEqual(ok('probe'));
      expect(op).toHaveBeenCalledTimes(1);
    });

    it('never writes a payload or a credential into the state file (G8)', async () => {
      const policy = createForwardPolicy({ dir, now: () => 1_234 });
      await policy.run(() =>
        Promise.reject(new Error('carrying secret-token-abc and prompt text')),
      );
      const raw = await readFile(stateFile(), 'utf8');
      expect(raw).not.toContain('secret-token-abc');
      expect(raw).not.toContain('prompt text');
      // Exactly the three bookkeeping keys, nothing else. An ALLOW-list, so the
      // next field someone adds to the state has to be argued for here rather
      // than riding along — this file sits next to raw prompt and tool text.
      expect(Object.keys(JSON.parse(raw) as object).sort()).toEqual([
        'consecutiveFailures',
        'lastFailure',
        'openedAtMs',
      ]);
    });

    it('records the CLASSIFICATION of a refusal, never the refusal itself', async () => {
      // The 403 the backend actually sends is a JSON body, and a client that
      // stringified it into the error would put server-authored text one
      // JSON.stringify away from a file next to `Event.content`. Only the enum
      // is written, so there is nothing to redact.
      const policy = createForwardPolicy({ dir, now: () => 1_234 });
      await policy.run(() =>
        Promise.reject(
          Object.assign(new Error('403 for key aka_live_SECRET on /v1/events'), { status: 403 }),
        ),
      );
      const raw = await readFile(stateFile(), 'utf8');
      expect(raw).not.toContain('aka_live_SECRET');
      expect(raw).not.toContain('/v1/events');
      expect(JSON.parse(raw)).toEqual({
        consecutiveFailures: 1,
        openedAtMs: null,
        lastFailure: 'forbidden',
      });
    });

    it('leaves no temp file behind (the swap is atomic)', async () => {
      const policy = createForwardPolicy({ dir, now: () => 1 });
      await policy.run(() => Promise.reject(new Error('down')));
      const entries = await readdir(dir);
      expect(entries).toEqual(['attached-state.json']);
    });
  });

  describe('classifying the failure', () => {
    // The whole point of #167: `null` used to mean refused, timed out,
    // unreachable and never-attempted at once, so the one failure a human has
    // to act on was indistinguishable from the one they are meant to ignore.
    it.each([
      [401, 'unauthorized'],
      [403, 'forbidden'],
      // Answered, and not a verdict about this credential. Retrying is the
      // right response, so it belongs in the same bucket as a dead link.
      [500, 'unreachable'],
      [502, 'unreachable'],
    ])('a %d becomes %s', async (status, reason) => {
      const policy = createForwardPolicy({ dir, now: () => 7 });
      await expect(policy.run(() => Promise.reject(refusal(status)))).resolves.toEqual(
        failed(reason as ForwardFailureReason),
      );
      expect(readForwardHealth(dir, 7)?.lastFailure).toBe(reason);
    });

    it('a route the deployment does not serve becomes route-absent', async () => {
      const policy = createForwardPolicy({ dir, now: () => 7 });
      await expect(policy.run(() => Promise.reject(routeAbsent()))).resolves.toEqual(
        failed('route-absent'),
      );
    });

    it('a route-absent PROBE closes the breaker instead of spending the cooldown', async () => {
      // The half-open path re-stamps `openedAtMs` BEFORE issuing the probe, and
      // only the success arm clears it. Against a deployment that predates the
      // batch route the probe IS the batch call, and it 404s by definition — so
      // an early return here would leave the breaker open with a freshly reset
      // cooldown and answer every single-event retry the compatibility path
      // depends on with `breaker-open`: nothing delivered, and nothing counted
      // either, because the drop tally sits past the reason check.
      //
      // A 404 is an ANSWER. Reachability is the only thing the breaker measures,
      // and this arm has just proved it, so it closes exactly as a success does.
      let clock = 1_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy);
      clock += BREAKER_COOLDOWN_MS + 1;

      await expect(policy.run(() => Promise.reject(routeAbsent()))).resolves.toEqual(
        failed('route-absent'),
      );

      // The remedy must reach the network, not be suppressed by the call that
      // discovered it was needed.
      const op = vi.fn(() => Promise.resolve('ran'));
      await expect(policy.run(op)).resolves.toEqual(ok('ran'));
      expect(op).toHaveBeenCalledTimes(1);
    });

    it('an invalid-request PROBE does not consume the cooldown it was answered inside', async () => {
      // The same shape as the route-absent bug above, but the fix cannot be the
      // same fix: nothing reached the network here, so there is no evidence of
      // reachability to close the breaker on. The correct behaviour is to leave
      // the breaker exactly as it was found — undo the re-stamp `run()` made
      // before calling an op that turned out to refuse locally, rather than
      // either closing it or leaving the re-stamp in place.
      //
      // Leaving the re-stamp in place is the bug: `openedAtMs` moves forward to
      // the probe's own timestamp, so the NEXT probe is now measured from a
      // point in time nothing was ever learned at, and the caller waits a
      // second full cooldown for a chance the first one already earned.
      let clock = 1_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy);
      clock += BREAKER_COOLDOWN_MS + 1;

      // The half-open probe, answered locally before anything reached a socket.
      await expect(policy.run(() => Promise.reject(invalidRequestError()))).resolves.toEqual(
        failed('invalid-request'),
      );

      // One millisecond later — nowhere near a SECOND full cooldown — the
      // breaker must already be willing to probe again, because the original
      // cooldown had already elapsed and nothing legitimately reset it.
      clock += 1;
      const op = vi.fn(() => Promise.resolve('ran'));
      await expect(policy.run(op)).resolves.toEqual(ok('ran'));
      expect(op).toHaveBeenCalledTimes(1);
    });

    it('an invalid-request during the half-open window leaves consecutiveFailures and lastFailure untouched', async () => {
      // Restoring the pre-probe state has to restore ALL of it, not just
      // `openedAtMs` — a partial restore would silently change what the next
      // read of `/aka:status` reports, or how many failures the next real
      // outage needs to re-open the breaker.
      let clock = 1_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy, () => Object.assign(new Error('down'), { status: 403 }));
      const before = readForwardHealth(dir, clock);
      clock += BREAKER_COOLDOWN_MS + 1;

      await expect(policy.run(() => Promise.reject(invalidRequestError()))).resolves.toEqual(
        failed('invalid-request'),
      );

      const after = readForwardHealth(dir, clock);
      expect(after?.lastFailure).toBe(before?.lastFailure);
      expect(after?.consecutiveFailures).toBe(before?.consecutiveFailures);
    });

    it('route-absent does not erase a failure count a DIFFERENT route earned', async () => {
      // The property the shared breaker demands. `AttachedDataGateway` holds
      // ONE `ForwardPolicy` for every route it forwards through, so a 404 on
      // the batch route is evidence about THAT route only — it did not
      // disprove a failure `ingestEvents` (say) just recorded moments earlier.
      // Zeroing it here would let a permanently-dead batch route mask a
      // genuine, unrelated outage on every other route from the breaker
      // forever, since 404-then-fail-then-404-then-fail never reaches
      // BREAKER_FAILURE_THRESHOLD.
      const policy = createForwardPolicy({ dir });
      // Two failures on some OTHER route — short of the threshold, breaker
      // still closed.
      await policy.run(() => Promise.reject(new Error('ingestEvents down')));
      await policy.run(() => Promise.reject(new Error('ingestEvents down')));
      expect(readForwardHealth(dir)?.consecutiveFailures).toBe(2);

      // The batch route 404s. The breaker was closed, so no half-open re-stamp
      // exists to undo — nothing about the OTHER route's count may move.
      await expect(policy.run(() => Promise.reject(routeAbsent()))).resolves.toEqual(
        failed('route-absent'),
      );
      expect(readForwardHealth(dir)?.consecutiveFailures).toBe(2);

      // The THIRD real failure — on the original route again — must still be
      // the one that opens the breaker, exactly as it would have without the
      // 404 in between.
      await expect(
        policy.run(() => Promise.reject(new Error('ingestEvents still down'))),
      ).resolves.toEqual(failed('unreachable'));
      const op = vi.fn(() => Promise.resolve('should not run'));
      await expect(policy.run(op)).resolves.toEqual(failed('breaker-open'));
      expect(op).not.toHaveBeenCalled();
    });

    it('route-absent from a half-open probe restores the ORIGINAL cause, not a wiped one', async () => {
      // The other half: when there IS a re-stamp to undo (a probe fired because
      // the cooldown elapsed), the restore must bring back what caused the
      // breaker to open in the first place — not silence it. `lastFailure`
      // exists specifically for `/aka:status` to render a cause; a `{...CLOSED}`
      // write here would have it report a healthy device seconds after a 403.
      let clock = 1_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy, () => Object.assign(new Error('forbidden'), { status: 403 }));
      clock += BREAKER_COOLDOWN_MS + 1;

      await expect(policy.run(() => Promise.reject(routeAbsent()))).resolves.toEqual(
        failed('route-absent'),
      );

      const health = readForwardHealth(dir, clock);
      expect(health?.consecutiveFailures).toBe(BREAKER_FAILURE_THRESHOLD);
      expect(health?.lastFailure).toBe('forbidden');
    });

    it('a route the deployment does not serve never moves the breaker', async () => {
      // The property the reason exists for. An older deployment answers 404 on
      // EVERY chunk, so if this counted as a failure the third chunk would open
      // the breaker and suppress every unrelated forward for the cooldown —
      // against a deployment that is answering everything it understands. Past
      // the threshold deliberately: at the threshold alone this would pass on an
      // off-by-one that still opens on the next chunk.
      const policy = createForwardPolicy({ dir });
      for (let i = 0; i < BREAKER_FAILURE_THRESHOLD + 2; i++) {
        await expect(policy.run(() => Promise.reject(routeAbsent()))).resolves.toEqual(
          failed('route-absent'),
        );
      }
      const op = vi.fn(() => Promise.resolve('ran'));
      await expect(policy.run(op)).resolves.toEqual(ok('ran'));
      expect(op).toHaveBeenCalledTimes(1);
    });

    it.each([400, 413, 422])(
      'a %d body refusal classifies as rejected, and never moves the breaker',
      async (status) => {
        const policy = createForwardPolicy({ dir });
        for (let i = 0; i < BREAKER_FAILURE_THRESHOLD + 2; i++) {
          await expect(policy.run(() => Promise.reject(serverRejection(status)))).resolves.toEqual(
            failed('rejected'),
          );
        }
        const op = vi.fn(() => Promise.resolve('ran'));
        await expect(policy.run(op)).resolves.toEqual(ok('ran'));
        expect(op).toHaveBeenCalledTimes(1);
      },
    );

    it.each([401, 403, 404, 429, 500])(
      'a %d is NOT classified as rejected — it keeps its own existing meaning',
      async (status) => {
        // The boundary the range check draws. 401/403 already have their own
        // members; 404 on this route is `route-absent`, handled earlier and
        // never reaching `classifyFailure` at all; 429 and 500 are both
        // retriable rather than a body-shape refusal and must still count
        // toward the breaker like any other `unreachable`.
        const policy = createForwardPolicy({ dir });
        const result = await policy.run(() => Promise.reject(serverRejection(status)));
        expect(result).not.toEqual(failed('rejected'));
      },
    );

    it('a 429 counts toward the breaker — it is retriable, not a body-shape refusal', async () => {
      // The property `rejected`'s exclusion exists for. Left classified as
      // `rejected`, a sustained 429 could never trip the breaker (that reason
      // never touches consecutiveFailures) AND would trigger an unpaced
      // per-item retry storm at the deployment's own rate limiter through
      // `forwardBatch` — the exact burst its docblock says staying serial is
      // meant to avoid. Excluded, three 429s behave like three 500s: they
      // open the breaker and stop the storm.
      const policy = createForwardPolicy({ dir });
      for (let i = 0; i < BREAKER_FAILURE_THRESHOLD; i++) {
        await expect(policy.run(() => Promise.reject(serverRejection(429)))).resolves.toEqual(
          failed('unreachable'),
        );
      }
      const op = vi.fn(() => Promise.resolve('should not run'));
      await expect(policy.run(op)).resolves.toEqual(failed('breaker-open'));
      expect(op).not.toHaveBeenCalled();
    });

    it('rejected does not erase a failure count a DIFFERENT route earned', async () => {
      // Mirrors the equivalent route-absent test: the breaker is shared across
      // every route a gateway forwards through, so a 422 on THIS one must not
      // zero a count `ingestEvents` (say) already earned.
      const policy = createForwardPolicy({ dir });
      await policy.run(() => Promise.reject(new Error('ingestEvents down')));
      await policy.run(() => Promise.reject(new Error('ingestEvents down')));
      expect(readForwardHealth(dir)?.consecutiveFailures).toBe(2);

      await expect(policy.run(() => Promise.reject(serverRejection(422)))).resolves.toEqual(
        failed('rejected'),
      );
      expect(readForwardHealth(dir)?.consecutiveFailures).toBe(2);

      await expect(
        policy.run(() => Promise.reject(new Error('ingestEvents still down'))),
      ).resolves.toEqual(failed('unreachable'));
      const op = vi.fn(() => Promise.resolve('should not run'));
      await expect(policy.run(op)).resolves.toEqual(failed('breaker-open'));
      expect(op).not.toHaveBeenCalled();
    });

    it('a rejected PROBE closes the breaker instead of spending the cooldown', async () => {
      let clock = 1_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy);
      clock += BREAKER_COOLDOWN_MS + 1;

      await expect(policy.run(() => Promise.reject(serverRejection(422)))).resolves.toEqual(
        failed('rejected'),
      );

      const op = vi.fn(() => Promise.resolve('ran'));
      await expect(policy.run(op)).resolves.toEqual(ok('ran'));
      expect(op).toHaveBeenCalledTimes(1);
    });

    it('reads the STATUS, not the message — a 403 in the text is not a 403', async () => {
      // The sync path used to recover the status with a regex over the error
      // text. Nothing type-checked that, so a reword upstream degraded the
      // actionable outcome silently. This pins the replacement: text that
      // merely mentions a status is not evidence of one.
      const policy = createForwardPolicy({ dir, now: () => 7 });
      await expect(
        policy.run(() => Promise.reject(new Error('connect ECONNREFUSED — not a 403, honest'))),
      ).resolves.toEqual(failed('unreachable'));
      expect(readForwardHealth(dir, 7)?.lastFailure).toBe('unreachable');
    });

    it('a half-open probe re-stamps the breaker WITHOUT re-diagnosing it', async () => {
      // The probe writes `openedAtMs` again BEFORE it runs. Dropping
      // `lastFailure` in that write would erase the cause on the first probe —
      // roughly thirty seconds after the refusal, and permanently thereafter,
      // since every later probe would re-write the same empty cause. Status
      // would then show a wedged device with no reason, which is most of the
      // bug this issue is about.
      let clock = 10_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy, () => refusal(403));
      expect(readForwardHealth(dir, clock)?.lastFailure).toBe('forbidden');

      // The probe is GATED so the file can be read mid-flight. Awaiting it
      // instead would let it time out and re-diagnose the breaker itself, and
      // the assertion would then be about the probe's own failure rather than
      // about the re-stamp — passing whether or not the cause is carried.
      clock += BREAKER_COOLDOWN_MS;
      let probing = false;
      let release!: (value: string) => void;
      const pending = policy.run(() => {
        probing = true;
        return new Promise<string>((resolve) => (release = resolve));
      });
      // `persist` is awaited before the op is called, so an op that has started
      // proves the re-stamp already landed on disk.
      await vi.waitFor(() => {
        expect(probing).toBe(true);
      });
      expect(readForwardHealth(dir, clock)).toEqual({
        consecutiveFailures: BREAKER_FAILURE_THRESHOLD,
        openedAtMs: clock,
        lastFailure: 'forbidden',
      });

      release('probed');
      await expect(pending).resolves.toEqual(ok('probed'));
      // …and the success is what clears it, not the probe.
      expect(readForwardHealth(dir, clock)?.lastFailure).toBeNull();
    });

    it('a success clears the cause along with the count', async () => {
      // A forward has just landed, so the last thing the backend said about this
      // device is yes. Leaving the old cause behind would have status keep
      // naming a 403 a success has since disproved.
      const policy = createForwardPolicy({ dir, now: () => 7 });
      await policy.run(() => Promise.reject(refusal(401)));
      expect(readForwardHealth(dir, 7)?.lastFailure).toBe('unauthorized');

      await expect(policy.run(() => Promise.resolve('back'))).resolves.toEqual(ok('back'));
      expect(readForwardHealth(dir, 7)).toEqual({
        consecutiveFailures: 0,
        openedAtMs: null,
        lastFailure: null,
      });
    });

    it('a skipped forward records nothing at all', async () => {
      // The file says what the BACKEND did. A cooling breaker asked it nothing,
      // so re-stamping here would also destroy the count that measures the
      // outage: every skipped hook would look like another attempt.
      const clock = 10_000;
      const policy = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(policy, () => refusal(403));
      const before = await readFile(stateFile(), 'utf8');

      await expect(policy.run(() => Promise.resolve('nope'))).resolves.toEqual(
        failed('breaker-open'),
      );
      expect(await readFile(stateFile(), 'utf8')).toBe(before);
    });
  });

  describe('readForwardHealth', () => {
    it('reports the cause a previous process recorded', async () => {
      const policy = createForwardPolicy({ dir, now: () => 500 });
      await policy.run(() => Promise.reject(refusal(403)));
      expect(readForwardHealth(dir, 500)).toEqual({
        consecutiveFailures: 1,
        openedAtMs: null,
        lastFailure: 'forbidden',
      });
    });

    it.each([
      // Pre-#167 files, which is every already-deployed device: the field is
      // simply absent and the count beside it is still evidence.
      ['the field is absent', '{"consecutiveFailures":4,"openedAtMs":null}'],
      // Hand-edited or written by a build that knows a member this one does
      // not. Rendered values are validated against the enum, never trusted.
      ['an unknown member', '{"consecutiveFailures":4,"openedAtMs":null,"lastFailure":"teapot"}'],
      [
        'a non-string',
        '{"consecutiveFailures":4,"openedAtMs":null,"lastFailure":{"code":"forbidden"}}',
      ],
    ])('reads %s as NO cause, keeping the rest of the record', async (_label, contents) => {
      await writeFile(stateFile(), contents, 'utf8');
      expect(readForwardHealth(dir, 999_999)).toEqual({
        consecutiveFailures: 4,
        openedAtMs: null,
        lastFailure: null,
      });
    });

    it('says nothing at all when there is no file', () => {
      expect(readForwardHealth(dir, 1)).toBeNull();
    });
  });

  describe('a torn or hostile state file reads as CLOSED', () => {
    // An open breaker STOPS the tenant receiving its own telemetry. No corrupt
    // byte on disk gets to make that call, so every unreadable shape below must
    // forward normally rather than fail shut.
    it.each([
      ['truncated JSON', '{"consecutiveFailures":3,"opened'],
      ['garbage bytes', '  not json at all'],
      ['empty file', ''],
      ['a JSON array', '[]'],
      ['null', 'null'],
      ['openedAtMs as a string', '{"consecutiveFailures":9,"openedAtMs":"9999999999999"}'],
      ['openedAtMs NaN-ish', '{"consecutiveFailures":9,"openedAtMs":"NaN"}'],
      // NUMERIC and in the future — the shape the type guard alone admits. It
      // is the dangerous one precisely because it is well-formed: read as
      // open, the cooling branch never elapses and never rewrites the file, so
      // forwarding is off for good.
      ['openedAtMs in the future', '{"consecutiveFailures":9,"openedAtMs":9999999999999}'],
    ])('%s', async (_label, contents) => {
      await writeFile(stateFile(), contents, 'utf8');
      const policy = createForwardPolicy({ dir, now: () => 999_999 });
      const op = vi.fn(() => Promise.resolve('forwarded'));
      await expect(policy.run(op)).resolves.toEqual(ok('forwarded'));
      expect(op).toHaveBeenCalledTimes(1);
    });

    it('a future openedAtMs is CLEARED from the file, not merely ignored', async () => {
      // Reading it as closed is only half the fix: the stamp has to leave the
      // file, or every fresh process re-derives the same verdict from the same
      // bytes. The successful forward transitions from "failures recorded" to
      // CLOSED, which rewrites it.
      await writeFile(stateFile(), '{"consecutiveFailures":9,"openedAtMs":9999999999999}', 'utf8');
      const policy = createForwardPolicy({ dir, now: () => 999_999 });
      await expect(policy.run(() => Promise.resolve('forwarded'))).resolves.toEqual(
        ok('forwarded'),
      );

      expect(JSON.parse(await readFile(stateFile(), 'utf8'))).toEqual({
        consecutiveFailures: 0,
        openedAtMs: null,
        lastFailure: null,
      });
    });

    it('a clock that moves BACKWARDS does not wedge a legitimately open breaker', async () => {
      // The realistic producer: the breaker opens, then an NTP correction pulls
      // the clock back behind the stamp the same process wrote. The next
      // process must forward rather than sit on a cooldown that can never
      // elapse.
      let clock = 500_000;
      const first = createForwardPolicy({ dir, now: () => clock });
      await tripOpen(first);

      clock -= 60_000;
      const afterCorrection = createForwardPolicy({ dir, now: () => clock });
      const op = vi.fn(() => Promise.resolve('forwarded'));
      await expect(afterCorrection.run(op)).resolves.toEqual(ok('forwarded'));
      expect(op).toHaveBeenCalledTimes(1);
    });

    it('an absent file reads as closed', async () => {
      const policy = createForwardPolicy({ dir });
      const op = vi.fn(() => Promise.resolve('forwarded'));
      await expect(policy.run(op)).resolves.toEqual(ok('forwarded'));
      expect(op).toHaveBeenCalledTimes(1);
    });

    it('an unreadable state file reads as closed rather than disabling forwarding', async () => {
      // A DIRECTORY where the state file should be: readFile fails with EISDIR,
      // which is neither ENOENT nor parseable. Failing shut here would silently
      // disable forwarding forever on that machine.
      await rm(stateFile(), { force: true });
      const { mkdir } = await import('node:fs/promises');
      await mkdir(stateFile());
      const policy = createForwardPolicy({ dir });
      const op = vi.fn(() => Promise.resolve('forwarded'));
      await expect(policy.run(op)).resolves.toEqual(ok('forwarded'));
      expect(op).toHaveBeenCalledTimes(1);
    });
  });

  it('a failure to persist never propagates to the caller', async () => {
    // A file in the directory path makes mkdir -p fail with ENOTDIR, which
    // ensureDataDir cannot chmod its way around (see posture-store.test.ts).
    const blocked = join(dir, 'blocker');
    await writeFile(blocked, 'not a directory', 'utf8');
    const policy = createForwardPolicy({ dir: join(blocked, 'nested') });
    await expect(policy.run(() => Promise.reject(new Error('down')))).resolves.toEqual(
      failed('unreachable'),
    );
    await expect(policy.run(() => Promise.resolve('fine'))).resolves.toEqual(ok('fine'));
  });
});
