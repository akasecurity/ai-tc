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
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { readWorkspaceSettings } from '../../src/settings.ts';
import type { ConcurrentRun, WriterJob } from './settings-writers.ts';
import { allReleasedTogether, runConcurrentSettingsWriters } from './settings-writers.ts';

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

/** Poll until `predicate` holds, or give up after `timeoutMs` and say so. */
async function waitFor(predicate: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(`timed out after ${String(timeoutMs)}ms: ${what}`);
    await delay(20);
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

function run(releasedAt: number, readies: number[]): ConcurrentRun {
  return {
    releasedAt,
    outcomes: readies.map((readyAt) => ({
      ok: true,
      readyAt,
      // Every writer starts after the release; that is true by construction and
      // is precisely why the barrier check reads readyAt instead.
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
    expect(allReleasedTogether(result)).toBe(true);
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
    // fallback is deliberately a different number, so this reads as 60s exactly
    // when the harness passed 60s — drop the argument and it reports the
    // fallback instead of quietly agreeing.
    const result = await runConcurrentSettingsWriters(base, [{ set: { policy: 'warn' } }]);
    expect(result.outcomes[0]?.barrierTimeoutMs).toBe(60_000);
  });
});

describe('a writer that is never released', () => {
  let sync: string;

  beforeEach(() => {
    sync = mkdtempSync(join(tmpdir(), 'aka-writer-abandon-'));
  });

  afterEach(() => {
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
    const launcher = [
      "const { spawn } = require('node:child_process');",
      "const { writeSync } = require('node:fs');",
      `const child = spawn(process.execPath, [${JSON.stringify(CHILD)}, ${JSON.stringify(base)}, ${JSON.stringify(JSON.stringify({ set: { policy: 'warn' } }))}, ${JSON.stringify(ready)}, ${JSON.stringify(join(sync, 'go'))}, '600000', String(process.pid)], { stdio: 'ignore' });`,
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

    // Parked first, so the exit below is the barrier being abandoned rather
    // than a child that never got as far as waiting.
    await waitFor(() => existsSync(ready), 15_000, 'writer never parked at the barrier');
    await waitFor(() => !alive(pid), 15_000, `orphaned writer ${String(pid)} is still running`);
    expect(alive(pid)).toBe(false);
  }, 40_000);
});

describe('allReleasedTogether', () => {
  it('is true when every writer was parked before the release', () => {
    expect(allReleasedTogether(run(100, [20, 60, 100]))).toBe(true);
  });

  it('is false when a writer was still loading at the release', () => {
    // The failure mode it exists to catch: a barrier that stopped holding, so
    // the writers ran as each finished booting, one after another — under which
    // "no answer was lost" is trivially true.
    expect(allReleasedTogether(run(100, [20, 140]))).toBe(false);
  });

  it('tolerates a writer scheduled late AFTER the release, which is not a defect', () => {
    // A released child can sit unscheduled for longer than another writer's
    // whole call on a loaded runner. Only readiness is the barrier's business,
    // so that must not read as a broken barrier — otherwise the suite fails on
    // machine load rather than on the product.
    const late = run(100, [20, 60]);
    const scheduledLate = late.outcomes.map((o, i) =>
      i === 1 ? { ...o, startedAt: 9_000, endedAt: 9_010 } : o,
    );
    expect(allReleasedTogether({ ...late, outcomes: scheduledLate })).toBe(true);
  });

  it('is false for no writers at all', () => {
    expect(allReleasedTogether(run(100, []))).toBe(false);
  });
});
