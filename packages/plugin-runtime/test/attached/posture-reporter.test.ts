import { StorePostureSnapshot } from '@akasecurity/schema';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { PostureReporter, PostureReporterDeps } from '../../src/attached/posture-reporter.ts';
import {
  createPostureReporter,
  POSTURE_REPORT_INTERVAL_MS,
} from '../../src/attached/posture-reporter.ts';
import { REQUEST_TIMEOUT_MS } from '../../src/attached/with-timeout.ts';

// Drive both phases the way the attached gateway does: prepare, then send
// whatever it produced. Most cases below care about the COMPOSED behaviour;
// the phase-split cases at the bottom pin the split itself.
async function run(reporter: PostureReporter): Promise<void> {
  const snapshot = await reporter.prepare();
  if (snapshot) await reporter.send(snapshot);
}
import type { StoreReadout } from '../../src/attached/posture-snapshot.ts';

const DEVICE_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

// A full, non-empty readout: storePresent true, 2 packs, non-zero counts.
function fixtureReadout(): StoreReadout {
  return {
    storePresent: true,
    schemaVersion: 14,
    findingsTotal: 5,
    findingsFirstAt: 1_700_000_000_000,
    findingsLastAt: 1_779_000_000_000,
    packs: [
      { packId: 'aka/secrets', version: '1.4.0', enabled: true, updatedAt: '1779000000000' },
      { packId: 'aka/pii', version: '0.9.0', enabled: false, updatedAt: null },
    ],
    policyCounts: {
      total: 3,
      disabled: 1,
      byAction: { warn: 2, redact: 0, block: 1, allow: 0, log: 0 },
    },
    readError: false,
  };
}

// The all-empty storePresent:false literal (mirrors Task 9's "missing db file" case).
function emptyReadoutFixture(): StoreReadout {
  return {
    storePresent: false,
    schemaVersion: null,
    findingsTotal: 0,
    findingsFirstAt: null,
    findingsLastAt: null,
    packs: [],
    policyCounts: {
      total: 0,
      disabled: 0,
      byAction: { warn: 0, redact: 0, block: 0, allow: 0, log: 0 },
    },
    readError: false,
  };
}

// The explicit generic keeps `.mock.calls[n][0]` typed as StorePostureSnapshot
// without declaring an unused parameter on the implementation itself.
function mockReport(impl: () => Promise<unknown> = () => Promise.resolve({ ok: true })) {
  return vi.fn<(snapshot: StorePostureSnapshot) => Promise<unknown>>(impl);
}

function mockMarkAttempted(onCall?: (atMs: number) => void) {
  return vi.fn<(deviceId: string, atMs: number) => Promise<void>>((_deviceId, atMs) => {
    onCall?.(atMs);
    return Promise.resolve();
  });
}

// Mutable so a test can drive several SessionStarts across a moving clock.
let nowMs = 1_780_000_000_000;

function makeDeps(overrides: Partial<PostureReporterDeps> = {}): PostureReporterDeps {
  const state = { deviceId: DEVICE_ID, lastAttemptedAtMs: 0 };
  const defaults: PostureReporterDeps = {
    report: mockReport(),
    store: {
      read: () => Promise.resolve(state),
      markAttempted: mockMarkAttempted((atMs) => {
        state.lastAttemptedAtMs = atMs;
      }),
      file: '/tmp/posture-state.json',
    },
    readStore: () => fixtureReadout(),
    hostname: () => 'DevMac-01',
    now: () => nowMs,
  };
  return Object.assign(defaults, overrides);
}

beforeEach(() => {
  nowMs = 1_780_000_000_000;
});

describe('createPostureReporter', () => {
  it('builds and sends a schema-valid snapshot, then advances the throttle', async () => {
    // Held locally (rather than read back off `deps.report`/`deps.store.markReported`)
    // so each stays a properly typed Mock with an inspectable `.mock`, and the
    // assertions below never touch an unbound method reference — same idiom as
    // attached-gateway.test.ts's held-locally client-method spies.
    const report = mockReport();
    const markAttempted = mockMarkAttempted();
    const deps = makeDeps({
      report,
      store: {
        read: () => Promise.resolve({ deviceId: DEVICE_ID, lastAttemptedAtMs: 0 }),
        markAttempted,
        file: '/tmp/posture-state.json',
      },
    });
    await run(createPostureReporter(deps));
    const sent = report.mock.calls[0]?.[0];
    if (!sent) throw new Error('expected a report');
    expect(() => StorePostureSnapshot.parse(sent)).not.toThrow();
    expect(sent).toMatchObject({
      deviceId: DEVICE_ID,
      hostname: 'DevMac-01',
      capturedAt: 1_780_000_000_000,
    });
    // The deviceId travels explicitly so the throttle can never be advanced
    // against a different device than the one just reported.
    expect(markAttempted).toHaveBeenCalledWith(DEVICE_ID, 1_780_000_000_000);
  });

  it('honors the throttle: a report inside the interval sends nothing', async () => {
    const report = mockReport();
    const deps = makeDeps({ report });
    deps.store.read = () =>
      Promise.resolve({
        deviceId: DEVICE_ID,
        lastAttemptedAtMs: 1_780_000_000_000 - POSTURE_REPORT_INTERVAL_MS + 1,
      });
    await run(createPostureReporter(deps));
    expect(report).not.toHaveBeenCalled();
  });

  it('a failed send stays silent, and still advances the throttle', async () => {
    // This previously asserted the opposite — that a failed send left the
    // throttle untouched so the next session could retry immediately. That
    // reads as the forgiving choice, but the stamp also gates the blocking
    // store read, so "never advance on failure" meant an unreachable backend
    // re-paid that read every SessionStart. Retrying a send the backend isn't
    // there to receive is worth less than bounding local work; the device is
    // still far inside the 72h freshness window an hour later.
    const markAttempted = mockMarkAttempted();
    const deps = makeDeps({
      report: mockReport(() => Promise.reject(new Error('down'))),
      store: {
        read: () => Promise.resolve({ deviceId: DEVICE_ID, lastAttemptedAtMs: 0 }),
        markAttempted,
        file: '/tmp/posture-state.json',
      },
    });
    await expect(run(createPostureReporter(deps))).resolves.toBeUndefined();
    expect(markAttempted).toHaveBeenCalledWith(DEVICE_ID, 1_780_000_000_000);
  });

  it('an absent store still reports (storePresent false is signal, not error)', async () => {
    const report = mockReport();
    const deps = makeDeps({ report, readStore: () => emptyReadoutFixture() });
    await run(createPostureReporter(deps));
    const sent = report.mock.calls[0]?.[0];
    expect(sent?.storePresent).toBe(false);
  });

  it('an UNREADABLE store reports nothing, and does not re-scan every session', async () => {
    // The counterpart to the case above: identical zeroed payload, but the
    // zeros were never measured. Sending it would tell the backend a healthy
    // device has no store — a false wipe alarm — and would overwrite the row's
    // packs/policyCounts with a fabricated "no coverage at all".
    //
    // The throttle still advances. A locked store was the worst case for the
    // old rule: unreadable meant no advance, so the blocking read that FAILED
    // was retried on every SessionStart. Sustained unreadability still reaches
    // the backend as `silent` on freshness, which is the honest signal and does
    // not depend on the retry cadence.
    const report = mockReport();
    const markAttempted = mockMarkAttempted();
    const deps = makeDeps({
      report,
      readStore: () => ({ ...emptyReadoutFixture(), readError: true }),
      store: {
        read: () => Promise.resolve({ deviceId: DEVICE_ID, lastAttemptedAtMs: 0 }),
        markAttempted,
        file: '/tmp/posture-state.json',
      },
    });
    await run(createPostureReporter(deps));
    expect(report).not.toHaveBeenCalled();
    expect(markAttempted).toHaveBeenCalledWith(DEVICE_ID, 1_780_000_000_000);
  });

  it('never sends readError on the wire — it is a local gate, not a snapshot field', async () => {
    const report = mockReport();
    const deps = makeDeps({ report });
    await run(createPostureReporter(deps));
    const sent = report.mock.calls[0]?.[0];
    if (!sent) throw new Error('expected a report');
    expect(sent).not.toHaveProperty('readError');
    expect(() => StorePostureSnapshot.parse(sent)).not.toThrow();
  });

  it('bounds a HANGING store.read() instead of leaving prepare() unresolved forever', async () => {
    // prepare()'s async fs I/O (store.read/markAttempted) is the one part of
    // this phase that CAN be preempted by withTimeout — unlike the synchronous
    // sqlite scan, it yields. A stalled NFS/FUSE mount or a permission prompt
    // hanging readFile/rename must not hang the caller past REQUEST_TIMEOUT_MS,
    // with only the harness's 10s SessionStart kill as a backstop.
    const deps = makeDeps({
      store: {
        read: () => new Promise<never>(() => undefined), // never resolves
        markAttempted: mockMarkAttempted(),
        file: '/tmp/posture-state.json',
      },
    });
    const startedAt = Date.now();
    const snapshot = await createPostureReporter(deps).prepare();
    expect(Date.now() - startedAt).toBeLessThan(REQUEST_TIMEOUT_MS + 1000);
    expect(snapshot).toBeNull();
  }, 10_000);

  it('bounds the blocking readStore() to once per interval even when every send fails', async () => {
    // The comments at attached-gateway.ts:205 and posture-snapshot.ts:94 justify
    // an un-preemptible, blocking SQLite read by saying it is paid "at most once
    // an hour". That reassurance is what this pins. It was false in exactly the
    // scenario those comments analyse: the throttle used to advance only after a
    // SUCCESSFUL send, so against an unreachable backend it never advanced and
    // the ~4s scan was re-paid on EVERY SessionStart (measured 5/5, not 1/5)
    // against a 10s hook kill.
    let readStoreCalls = 0;
    const state = { deviceId: DEVICE_ID, lastAttemptedAtMs: 0 };
    const deps = makeDeps({
      report: mockReport(() => Promise.reject(new Error('ECONNREFUSED'))),
      readStore: () => {
        readStoreCalls += 1;
        return fixtureReadout();
      },
      store: {
        read: () => Promise.resolve({ ...state }),
        markAttempted: mockMarkAttempted((atMs) => {
          state.lastAttemptedAtMs = atMs;
        }),
        file: '/tmp/posture-state.json',
      },
    });
    const reporter = createPostureReporter(deps);
    // Five SessionStarts one minute apart — all well inside the interval.
    for (let i = 0; i < 5; i++) {
      nowMs = 1_780_000_000_000 + i * 60_000;
      await run(reporter);
    }
    expect(readStoreCalls).toBe(1);
  });

  it('advances the throttle even when persisting it fails, so a read-only settings dir cannot silence the device', async () => {
    // The throttle now advances BEFORE the send, which puts a file write on the
    // path to reporting. If that write's failure propagated, an unwritable
    // ~/.aka/settings would suppress the report entirely — strictly worse than
    // the un-throttled reads it exists to prevent. Persisting is best-effort.
    const report = mockReport();
    const deps = makeDeps({
      report,
      store: {
        read: () => Promise.resolve({ deviceId: DEVICE_ID, lastAttemptedAtMs: 0 }),
        markAttempted: vi.fn<(deviceId: string, atMs: number) => Promise<void>>(() =>
          Promise.reject(new Error('EROFS')),
        ),
        file: '/tmp/posture-state.json',
      },
    });
    await run(createPostureReporter(deps));
    expect(report).toHaveBeenCalledTimes(1);
  });

  it('prepare() does all the local work but never touches the network', async () => {
    // The split is the point: prepare() contains the blocking store read, and
    // the gateway must be able to run it to completion before arming any
    // timers. A prepare() that sent would re-couple the blocking read to the
    // network race it was separated from.
    const report = mockReport();
    const deps = makeDeps({ report });
    const snapshot = await createPostureReporter(deps).prepare();
    expect(snapshot).toMatchObject({ deviceId: DEVICE_ID, hostname: 'DevMac-01' });
    expect(report).not.toHaveBeenCalled();
  });

  it('send() posts exactly the prepared snapshot and swallows a rejection', async () => {
    const report = mockReport(() => Promise.reject(new Error('ECONNREFUSED')));
    const deps = makeDeps({ report });
    const reporter = createPostureReporter(deps);
    const snapshot = await reporter.prepare();
    if (!snapshot) throw new Error('expected a snapshot');
    await expect(reporter.send(snapshot)).resolves.toBeUndefined();
    expect(report).toHaveBeenCalledWith(snapshot);
  });

  it('includes the plugin block the producer supplies, schema-valid on the wire', async () => {
    const report = mockReport();
    const deps = makeDeps({
      report,
      pluginBlock: () =>
        Promise.resolve({
          package: '@akasecurity/ai-tc-claude-code',
          version: '0.9.8',
          ossVersion: null,
          policyBundleVersion: 'sha256:abc123',
          policyFetchedAt: 1_779_500_000_000,
        }),
    });
    await run(createPostureReporter(deps));
    const sent = report.mock.calls[0]?.[0];
    if (!sent) throw new Error('expected a report');
    expect(() => StorePostureSnapshot.parse(sent)).not.toThrow();
    expect(sent.plugin).toMatchObject({
      package: '@akasecurity/ai-tc-claude-code',
      version: '0.9.8',
      policyBundleVersion: 'sha256:abc123',
    });
  });

  it('a throwing pluginBlock costs the block, never the snapshot', async () => {
    // The posture — storePresent above all — is worth strictly more than the
    // plugin metadata, so a broken producer must not silence the device.
    const report = mockReport();
    const deps = makeDeps({
      report,
      pluginBlock: () => Promise.reject(new Error('manifest unreadable')),
    });
    await run(createPostureReporter(deps));
    const sent = report.mock.calls[0]?.[0];
    if (!sent) throw new Error('expected a report');
    expect(sent).not.toHaveProperty('plugin');
    expect(() => StorePostureSnapshot.parse(sent)).not.toThrow();
  });

  it('bounds a HANGING pluginBlock — the snapshot still goes out without it', async () => {
    // The producer reads the policy cache from disk, so it gets the same
    // REQUEST_TIMEOUT_MS bound as the reporter's other fs ops: a stalled mount
    // must cost the block, never the snapshot, and never hang prepare() until
    // the harness's 10s kill.
    const report = mockReport();
    const deps = makeDeps({
      report,
      pluginBlock: () => new Promise<never>(() => undefined), // never resolves
    });
    const startedAt = Date.now();
    await run(createPostureReporter(deps));
    expect(Date.now() - startedAt).toBeLessThan(REQUEST_TIMEOUT_MS + 1000);
    const sent = report.mock.calls[0]?.[0];
    if (!sent) throw new Error('expected a report');
    expect(sent).not.toHaveProperty('plugin');
  }, 10_000);

  it('omits the plugin KEY without a producer — never an explicit undefined', async () => {
    // The wire shape is `.optional()`, and downstream bridges key on presence:
    // a spread `plugin: undefined` is a different object from an absent key
    // under exactOptionalPropertyTypes.
    const report = mockReport();
    await run(createPostureReporter(makeDeps({ report })));
    const sent = report.mock.calls[0]?.[0];
    if (!sent) throw new Error('expected a report');
    expect(sent).not.toHaveProperty('plugin');
  });

  it('a lastAttemptedAtMs in the FUTURE reports now instead of silencing the device', async () => {
    // A clock that jumps ahead and is then corrected backwards leaves a
    // negative delta, which is permanently < the interval. Without the guard
    // the device never reports again and the backend grades it `silent` — the
    // alarm state — with no local way to recover.
    const report = mockReport();
    const deps = makeDeps({ report });
    deps.store.read = () =>
      Promise.resolve({
        deviceId: DEVICE_ID,
        lastAttemptedAtMs: 1_780_000_000_000 + 30 * 24 * 60 * 60 * 1000,
      });
    await run(createPostureReporter(deps));
    expect(report).toHaveBeenCalledTimes(1);
  });
});
