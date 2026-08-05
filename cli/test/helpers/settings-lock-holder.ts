/**
 * Holds the settings.json write lock from a process of its own, then writes the
 * file and releases — so `aka init` can meet a real, live lock rather than a
 * planted one.
 *
 * Ordering here is a guarantee, not a timing hope: the file is written BEFORE
 * the lock is released, and a waiter cannot enter the section until it is. So an
 * init that takes the lock always finds the file, however slow the runner. The
 * hold only has to outlast an init that DOESN'T take it, which is what makes the
 * difference observable.
 *
 * The lock protocol is the existence of `<file>.lock` (see
 * packages/persistence/src/file-lock.ts) — created exclusively, removed on
 * release — so this holds one by creating the file, with nothing imported.
 *
 * Loaded by Node directly, outside the test runner's transform, so it stays on
 * node: builtins and plain erasable type annotations.
 */
import { closeSync, openSync, rmSync, writeFileSync } from 'node:fs';

const [settingsFile, contents, holdMsRaw] = process.argv.slice(2);
if (settingsFile === undefined || contents === undefined || holdMsRaw === undefined) {
  throw new Error('settings-lock-holder: expected <settingsFile> <contents> <holdMs>');
}

// `Atomics.wait` reads a NaN timeout as Infinity, so a non-numeric hold would
// park here forever still holding the lock — the parent's init would time out,
// and its wait for this process to close would never settle. Refuse it loudly.
const holdMs = Number(holdMsRaw);
if (!Number.isFinite(holdMs) || holdMs < 0) {
  throw new Error(`settings-lock-holder: holdMs must be a non-negative number, got "${holdMsRaw}"`);
}

// The lock protocol is the existence of `<file>.lock` carrying the holder's pid,
// its own acquire clock and an ownership token (see
// packages/persistence/src/file-lock.ts). The body matters: a waiter reads the
// pid to check the holder is alive before ever considering the lock abandoned,
// so a body-less lock would exercise the truncated-lock fallback instead of the
// live-holder path this test is about.
const lock = `${settingsFile}.lock`;
const fd = openSync(lock, 'wx', 0o600);
writeFileSync(
  fd,
  `${JSON.stringify({ pid: process.pid, token: 'lock-holder', at: Date.now() })}\n`,
);
closeSync(fd);

// Tell the parent the lock is up, so it starts init knowing the section is
// already taken rather than guessing.
process.stdout.write('locked\n');

// Slept, not spun: a hot loop would hold a core for the whole hold and slow
// whatever else the suite is running in parallel.
const PARK = new Int32Array(new SharedArrayBuffer(4));
Atomics.wait(PARK, 0, 0, holdMs);

writeFileSync(settingsFile, contents, { mode: 0o600 });
rmSync(lock, { force: true });
process.stdout.write('released\n');
