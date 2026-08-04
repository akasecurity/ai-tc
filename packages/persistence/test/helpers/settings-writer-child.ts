/**
 * One settings writer, as a process of its own — the shape the product runs in.
 *
 * The wizard, `aka init` and the dashboard server are three separate processes
 * over one ~/.aka, and the race between them is a FILE race, so neither
 * `withTwoWriters` (independent handles on one store, in one thread) nor a
 * worker thread models it. A worker would in fact model the wrong thing: it
 * shares `process.pid`, and the tmp path the atomic write builds is per-process,
 * so two threads meet a collision that two processes never can.
 *
 * Reports on stdout as one JSON line rather than by exit code, because the
 * interesting failure is a writer that reported success and lost its answer
 * anyway. The timestamps bracket the applyOnboarding call so a test can show the
 * writers really did overlap — a barrier that quietly serialised them would make
 * every no-loss assertion pass for the wrong reason.
 *
 * Loaded by Node directly, outside the test runner's transform, so it stays on
 * node: builtins and plain erasable type annotations.
 */
import { existsSync, writeFileSync } from 'node:fs';

import { applyOnboarding } from '../../src/settings.ts';

const [base, jobJson, readyFile, goFile] = process.argv.slice(2);
if (
  base === undefined ||
  jobJson === undefined ||
  readyFile === undefined ||
  goFile === undefined
) {
  throw new Error('settings-writer-child: expected <base> <jobJson> <readyFile> <goFile>');
}

const job = JSON.parse(jobJson) as { set?: Record<string, unknown>; clear?: string[] };

// `clear` is a list of names rather than keys set to undefined, because
// JSON.stringify DROPS an undefined value: a revoke written the natural way
// crosses as `{}` and the child writes nothing at all. Silently — the writer
// still reports success, so a test asserting the revoke stuck fails looking like
// a product defect, and one asserting the grant survived passes for no reason.
const answers: Record<string, unknown> = { ...job.set };
for (const field of job.clear ?? []) answers[field] = undefined;

// A handshake, not a clock. Announce that this process is loaded and ready, then
// wait until the parent releases everyone. A deadline-based barrier instead ties
// the contention to how long Node takes to boot and load the schema — which
// under a full parallel suite can outlast the deadline, leaving the writers to
// run one after another and every no-loss assertion true for want of a race.
//
// Polled with a sleep rather than a bare spin: several of these run at once,
// and a hot loop each would take a core apiece off the rest of the suite —
// enough to push a timing-sensitive test elsewhere over its threshold. The
// extra millisecond of release latency costs nothing here, since the barrier's
// assertion tolerates a late start (see allReleasedTogether).
const PARK = new Int32Array(new SharedArrayBuffer(4));
const readyAt = Date.now();
writeFileSync(readyFile, '');
while (!existsSync(goFile)) {
  Atomics.wait(PARK, 0, 0, 1);
}

const startedAt = Date.now();
let ok = false;
let error: string | undefined;
try {
  applyOnboarding(answers, base);
  ok = true;
} catch (err) {
  error = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}
process.stdout.write(`${JSON.stringify({ ok, error, readyAt, startedAt, endedAt: Date.now() })}\n`);
