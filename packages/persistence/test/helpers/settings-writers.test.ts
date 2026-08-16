/**
 * The concurrent-writer harness's own suite.
 *
 * Every no-loss assertion in concurrency/settings-race.test.ts rests on this
 * helper doing two things: actually running the writers, and actually releasing
 * them together. Both fail silently if left unguarded — a child that never ran
 * writes nothing to lose, and a barrier that serialised them removes the race
 * the assertions are about.
 */
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { readWorkspaceSettings } from '../../src/settings.ts';
import type { ConcurrentRun, WriterJob } from './settings-writers.ts';
import { BARRIER_HELD, barrierReport, runConcurrentSettingsWriters } from './settings-writers.ts';

const CHILD = fileURLToPath(new URL('./settings-writer-child.ts', import.meta.url));

/** Whether a pid is still live. Signal 0 delivers nothing and only asks. */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Poll until `predicate` holds, or give up after `timeoutMs` and say so.
 *
 * `what` may be a thunk so a caller can quote state that only exists once the
 * wait has already failed — reading it eagerly would capture an empty file.
 */
async function waitFor(
  predicate: () => boolean,
  timeoutMs: number,
  what: string | (() => string),
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      const detail = typeof what === 'string' ? what : what();
      throw new Error(`timed out after ${String(timeoutMs)}ms: ${detail}`);
    }
    await delay(20);
  }
}

/**
 * Whatever the orphaned child managed to write to fd 2.
 *
 * Absent is reported as such rather than as empty: a child that never spawned
 * leaves no file at all, and that is a different diagnosis from one that ran and
 * said nothing.
 */
function childStderr(file: string): string {
  try {
    return readFileSync(file, 'utf8').trim() || '(empty)';
  } catch {
    return '(no stderr file — the child never spawned)';
  }
}

/** Run one writer child directly, outside the harness, and collect its exit. */
async function runChildDirectly(args: string[]): Promise<{ code: number | null; stderr: string }> {
  const child = spawn(process.execPath, [CHILD, ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return await new Promise((resolve, reject) => {
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, stderr });
    });
  });
}

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-writers-helper-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

/**
 * One writer, as the PARENT saw it.
 *
 * `observedAt` is when the parent read this writer's ready token; omit it for a
 * writer it never saw park. `bootMs` is the writer's own boot duration, quoted
 * back in a fault message and read by nothing else.
 */
interface WriterTiming {
  observedAt?: number;
  bootMs?: number;
}

function run(releasedAt: number, writers: WriterTiming[]): ConcurrentRun {
  return {
    releasedAt,
    readyObservedAt: writers.map((w) => w.observedAt),
    outcomes: writers.map((w) => ({
      ok: true,
      bootMs: w.bootMs ?? 1,
      // Every writer starts after the release CAUSALLY — it is stamped by the
      // child once it observes the go file. These fixture numbers are not a
      // cross-process comparison and must not be read as licence for one: that
      // is the mistake this harness was last fixed for, and the barrier check
      // reads neither field.
      startedAt: releasedAt + 1,
      endedAt: releasedAt + 11,
      barrierTimeoutMs: 60_000,
    })),
  };
}

describe('runConcurrentSettingsWriters', () => {
  it('runs a writer, and it really writes', async () => {
    // Deliberately ONE writer: an outcome saying `ok` while the store stayed
    // empty would let every downstream assertion pass on nothing, and that is a
    // property of the harness. Asserting it across concurrent writers instead
    // would make this suite go red whenever the PRODUCT lost an update — a
    // harness failure reported for a defect somewhere else.
    const result = await runConcurrentSettingsWriters(base, [{ set: { policy: 'warn' } }]);
    expect(result.outcomes).toHaveLength(1);
    expect(result.outcomes[0]?.ok).toBe(true);
    expect(readWorkspaceSettings(base).policy).toBe('warn');
  });

  it('runs one writer per job and reports each one', async () => {
    const result = await runConcurrentSettingsWriters(base, [
      { set: { policy: 'warn' } },
      { set: { historicalAccess: 'full' } },
      { set: { dataSharesInPlace: false } },
    ]);
    expect(result.outcomes).toHaveLength(3);
    expect(result.outcomes.every((o) => o.ok)).toBe(true);
  });

  it('holds every writer at the line until all of them are ready', async () => {
    const result = await runConcurrentSettingsWriters(base, [
      { set: { policy: 'warn' } },
      { set: { historicalAccess: 'full' } },
      { set: { dataSharesInPlace: false } },
    ]);
    expect(barrierReport(result)).toBe(BARRIER_HELD);
  });

  it('carries a revoke across the process boundary', async () => {
    // JSON.stringify drops an undefined value, so a job that cleared a field by
    // setting it to undefined would cross as `{}` — the writer applies nothing
    // and still reports success, and a test asserting the revoke stuck fails
    // looking like a product defect. `clear` names the field instead.
    await runConcurrentSettingsWriters(base, [
      {
        set: {
          modelJudgeConsent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', payloadVersion: 1 },
        },
      },
    ]);
    expect(readWorkspaceSettings(base).modelJudgeConsent).toBeDefined();

    await runConcurrentSettingsWriters(base, [{ clear: ['modelJudgeConsent'] }]);
    expect(readWorkspaceSettings(base).modelJudgeConsent).toBeUndefined();
  });

  it('throws when a writer dies instead of folding it into a result', async () => {
    // A child that cannot even parse its arguments exits non-zero having written
    // nothing. Reported as a plain `ok: false` it would read as "this writer
    // lost the race", which is a legitimate outcome — so it has to be a failure
    // of the run instead.
    await expect(
      runConcurrentSettingsWriters(base, [undefined as unknown as WriterJob]),
    ).rejects.toThrow(/settings writer 0/);
  });

  it('runs its writers under its own barrier ceiling, not the child’s default', async () => {
    // The ceiling only bounds anything if it is actually sent. The child's
    // fallback is deliberately a different number, so this reads as 30s exactly
    // when the harness passed 30s — drop the argument and it reports the
    // fallback instead of quietly agreeing.
    //
    // Spelled out rather than imported: the harness derives it as
    // READY_TIMEOUT_MS * 2, and a test that recomputed the derivation would
    // agree with any value the harness chose, including none.
    const result = await runConcurrentSettingsWriters(base, [{ set: { policy: 'warn' } }]);
    expect(result.outcomes[0]?.barrierTimeoutMs).toBe(30_000);
  });
});

describe('a writer that is never released', () => {
  let sync: string;
  /** The orphaned writer, so a failed run cannot leave it behind. */
  let orphan: number | undefined;

  beforeEach(() => {
    sync = mkdtempSync(join(tmpdir(), 'aka-writer-abandon-'));
    orphan = undefined;
  });

  afterEach(() => {
    // `detached: true` buys the child the right to outlive its parent, which on
    // Windows also costs it the job object that used to kill it with the runner.
    // So if the liveness check ever fails to fire, this child now runs out its
    // ten-minute ceiling instead — a bounded version of the week-long leak this
    // suite exists to stop. Assert it exited on its own, then make sure of it.
    if (orphan !== undefined && alive(orphan)) {
      try {
        process.kill(orphan, 'SIGKILL');
      } catch {
        // Already gone between the check and the signal: nothing to clean up.
      }
    }
    rmSync(sync, { recursive: true, force: true });
  });

  it('abandons the barrier rather than polling for a release that never comes', async () => {
    // The leak this replaced: nothing ever created the release file, and the
    // child polled for it for a week. The park loop is synchronous, so this is
    // the only place such a child can be stopped from the inside.
    const result = await runChildDirectly([
      base,
      JSON.stringify({ set: { policy: 'warn' } }),
      join(sync, 'ready'),
      join(sync, 'go'),
      '300',
    ]);

    expect(result.code).toBe(3);
    expect(result.stderr).toMatch(/no release after 300ms/);
    // And it abandoned WITHOUT writing. A ceiling that let the writer proceed
    // would be the deadline-barrier the handshake exists to rule out: every
    // no-loss assertion downstream would hold for want of a race.
    expect(existsSync(join(base, 'settings'))).toBe(false);
  }, 20_000);

  it('exits when its parent goes, without waiting out the barrier ceiling', async () => {
    // A launcher that spawns one writer exactly as the harness does and then
    // exits, orphaning it at the barrier — the shape a suite timeout or a
    // killed runner leaves behind. Its ceiling is ten minutes, so nothing but
    // noticing the parent has gone can end it inside this window.
    const ready = join(sync, 'ready');
    const childErr = join(sync, 'launcher-child.err');
    const launcher = [
      "const { spawn } = require('node:child_process');",
      "const { openSync, writeSync } = require('node:fs');",
      // fd 2 goes to a file rather than being discarded. `stdio: 'ignore'` makes
      // a child that crashed on startup, one that was killed, and one that never
      // spawned all present identically as an absent ready file — and on a
      // platform nobody here can reproduce locally that costs a CI cycle per
      // hypothesis. A file rather than a pipe because the launcher exits
      // immediately: a pipe would have no reader.
      `const err = openSync(${JSON.stringify(childErr)}, 'a');`,
      // `detached: true` is what lets the child outlive the launcher on Windows,
      // where an ordinary spawn joins the parent's job object and is killed with
      // it. POSIX reparents either way, so this is a no-op there — which is why
      // the case passed everywhere else while Windows never reached the barrier.
      // `unref()` is a different question and does not substitute: it governs
      // whether the PARENT waits, not whether the child is allowed to survive.
      `const child = spawn(process.execPath, [${JSON.stringify(CHILD)}, ${JSON.stringify(base)}, ${JSON.stringify(JSON.stringify({ set: { policy: 'warn' } }))}, ${JSON.stringify(ready)}, ${JSON.stringify(join(sync, 'go'))}, '600000', String(process.pid)], { stdio: ['ignore', 'ignore', err], detached: true });`,
      // Report the pid and go, explicitly. `spawn` leaves a REFERENCED handle on
      // the event loop, so a launcher that merely ran off the end would outlive
      // the very child it exists to orphan — it waits for it, and the writer's
      // ten-minute ceiling becomes this test's runtime. `writeSync` for the
      // same reason the child uses it: stdout is a pipe here and `process.exit`
      // does not flush a pending pipe write.
      'writeSync(1, String(child.pid));',
      'child.unref();',
      'process.exit(0);',
    ].join('\n');

    // Bounded so a launcher that stops exiting fails in seconds instead of
    // hanging the file for the writer's whole ceiling. Node's own option, not
    // the `timeout` command, which macOS does not have.
    const pid = Number(
      execFileSync(process.execPath, ['-e', launcher], {
        encoding: 'utf8',
        timeout: 15_000,
      }).trim(),
    );
    expect(Number.isInteger(pid)).toBe(true);
    orphan = pid;

    // The ready file is written BEFORE the park loop, so its absence means the
    // child never got as far as the barrier — it never ran, or it died first —
    // rather than that it hung waiting for a release. Wording that as "never
    // parked" sent the last Windows failure looking at the wrong line, so the
    // message says which it is and quotes whatever the child managed to say.
    await waitFor(
      () => existsSync(ready),
      15_000,
      () => `writer never reached the barrier; child stderr: ${childStderr(childErr)}`,
    );
    await waitFor(
      () => !alive(pid),
      15_000,
      () =>
        `orphaned writer ${String(pid)} is still running; child stderr: ${childStderr(childErr)}`,
    );
    expect(alive(pid)).toBe(false);

    // WHY it exited, not merely that it is gone. `!alive(pid)` is also true of a
    // child the OS killed with its parent — which is exactly what Windows did
    // here before `detached: true` — so without this the case would go green on
    // a platform where the liveness check never ran at all.
    expect(childStderr(childErr)).toMatch(/parent exited before releasing the barrier/);
  }, 40_000);
});

describe('barrierReport', () => {
  it('holds when every writer was parked before the release', () => {
    expect(
      barrierReport(run(100, [{ observedAt: 20 }, { observedAt: 60 }, { observedAt: 100 }])),
    ).toBe(BARRIER_HELD);
  });

  // The two conjuncts, one case each. Each catches what the other cannot, and
  // the pair is what stops either being deleted with the suite green — which is
  // how the ordering half shipped unexercised: the gap case alone left
  // `at <= releasedAt` removable with all six cases passing.

  it('fails when a writer was never parked at all', () => {
    // A barrier that stopped holding lets the writers run as each finishes
    // booting, one after another — under which "no answer was lost" is
    // trivially true. The parent never saw that writer park, so the gap is what
    // reports it.
    expect(barrierReport(run(100, [{ observedAt: 20 }, { bootMs: 4_000 }]))).toBe(
      'writer 1 never parked (booted in 4000ms)',
    );
  });

  it('fails when a writer was not observed until AFTER the release', () => {
    // The ordering half, which no gap can reach: every writer parked and was
    // seen, but one of them only after the go file went out. That is what a
    // release reordered ahead of the handshake looks like from here — hoist
    // `releasedAt`/`writeFileSync(goFile)` above the wait and every observation
    // lands on this side of it.
    expect(barrierReport(run(100, [{ observedAt: 20 }, { observedAt: 140 }]))).toBe(
      'writer 1 was not observed until 40ms after the release (booted in 1ms)',
    );
  });

  it('names every writer at fault, not just the first', () => {
    // The whole reason this returns a sentence: a run with two bad writers has
    // to say so, or the second is found on the next CI cycle.
    expect(barrierReport(run(100, [{ observedAt: 20 }, {}, { observedAt: 150 }]))).toBe(
      'writer 1 never parked (booted in 1ms); writer 2 was not observed until 50ms after the release (booted in 1ms)',
    );
  });

  it('rejects a run carrying fewer observations than writers', () => {
    // An arity guard on an exported function, not a shape the helper can
    // return — `readyObservedAt` and `outcomes` both derive from the job list.
    // A caller assembling a ConcurrentRun by hand can still reach it.
    const partial = run(100, [{ observedAt: 20 }, { observedAt: 40 }]);
    expect(barrierReport({ ...partial, readyObservedAt: [20] })).toBe(
      'run is malformed: 1 observations for 2 writers',
    );
  });

  it('does not skip a hole in the observations', () => {
    // `Array.prototype.every` SKIPS holes, so a sparse array would never visit
    // the missing index and the run would report that the barrier held. No
    // production path builds one — both arrays are dense — so this pins the
    // trap rather than a live defect.
    const sparse = run(100, [{ observedAt: 20 }, { observedAt: 40 }, { observedAt: 60 }]);
    // eslint-disable-next-line no-sparse-arrays -- the hole IS the fixture
    expect(barrierReport({ ...sparse, readyObservedAt: [20, , 60] })).toBe(
      'writer 1 never parked (booted in 1ms)',
    );
  });

  it('reads no child stamp, however impossible that stamp looks', () => {
    // Two writers with child stamps that cannot both be true of a barrier that
    // held: one descheduled so long it started 9s late, and one reporting a
    // start BEFORE the release it was waiting on. Neither is a defect. The
    // first is ordinary runner load, and the second is the cross-process clock
    // disagreement this whole harness was rewritten for — startedAt is stamped
    // by the child, releasedAt by the parent, so their arithmetic means
    // nothing even though the causal order is certain.
    //
    // Both values are the point. A version of barrierReport that reached for
    // startedAt at all fails here whichever direction it compared: `>=
    // releasedAt` rejects writer 0, `<=` rejects writer 1. Without the early
    // stamp the case was a tautology — a late-only fixture satisfies a
    // `startedAt >= releasedAt` conjunct, so the conjunct could be added with
    // the suite green.
    const run_ = run(100, [{ observedAt: 20 }, { observedAt: 60 }]);
    const impossible = run_.outcomes.map((o, i) =>
      i === 0 ? { ...o, startedAt: 50, endedAt: 70 } : { ...o, startedAt: 9_000, endedAt: 9_010 },
    );
    expect(barrierReport({ ...run_, outcomes: impossible })).toBe(BARRIER_HELD);
  });

  it('fails for no writers at all', () => {
    expect(barrierReport(run(100, []))).toBe('no writers ran');
  });
});
