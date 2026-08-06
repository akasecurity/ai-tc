/**
 * The exception fingerprint key's first mint, raced.
 *
 * `loadOrCreateFingerprintKey` reads the key file, and mints only when it is
 * ABSENT. Read and write are two syscalls, so on a fresh store every process
 * that gets through the read before anyone's write lands mints material of its
 * own. Publishing that with a REPLACE makes the last writer win and every other
 * process walk away holding material that is not the one on disk.
 *
 * That is not a lost preference. A grant is matched by an HMAC of the detected
 * value under this key, and the raw value is never stored, so a fingerprint
 * written under the losing material can never be recomputed: the grant is inert
 * from the moment it is created, and no surface reports it as anything but
 * approved. The module's own header says silently re-minting would orphan every
 * grant, which is exactly why a CORRUPT key throws instead of being replaced —
 * the race reached that forbidden state by accident.
 *
 * The fix is a CREATE rather than a replace, via `createOwnerOnlyFileSync`:
 * exactly one caller wins and the loser ADOPTS. Publishing goes through a link
 * rather than an exclusive open at the final path, because an exclusive open
 * publishes an EMPTY inode and fills it on the next syscall — a reader landing
 * in between, including the loser re-reading in order to adopt, would take a
 * live key for a corrupt one. Rotation keeps tmp + rename; replacing is what
 * rotation is for.
 *
 * Two tiers below, and both are load-bearing:
 *
 *   - The **thread race** proves the real property, that the kernel lets exactly
 *     one of several genuinely concurrent minters win. Nothing is stubbed. It
 *     asserts the race actually happened rather than assuming it: every thread
 *     was parked when the barrier lifted, no key existed yet, and at least two
 *     threads were inside the mint at the same moment.
 *   - The **simulated interleave** proves the branch, deterministically: one
 *     read reports absence while the winner's key is already on disk, which is
 *     the losing process's exact view of the world. A thread race cannot be
 *     made to land on that interleave on demand, and the adopt path is the one
 *     that has to be right.
 *
 * What the thread tier does NOT model is the pre-fix failure itself. These are
 * threads of one process, and the replacing write it used to take names its tmp
 * per PID, so reverting the fix reddens these on a tmp collision threads have
 * and processes do not. The interleave tier is what pins the adopt behaviour;
 * this tier pins that one winner emerges under real contention.
 *
 * Neither asserts an elapsed time. Convergence is a set of key materials, which
 * reads the same on a fast laptop and a loaded Windows runner.
 */
import type * as FsModule from 'node:fs';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  EXCEPTION_KEY_FILENAME,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from '../../src/fingerprint.ts';
import { VAULT_KEY_FILENAME } from '../../src/vault/key-provider.ts';
import { errorFrom } from '../helpers/errors.ts';
import type { MintFailure, MintOutcome } from '../helpers/mint-worker.ts';

// Puts the module on its mint path while a winner's key file already sits at
// the final path — the losing process's exact view. `Once` is the real race:
// the absence check misses, and the re-read after the failed publish sees the
// winner. `Always` is the narrower case where the file is gone by then too,
// which must fail secure rather than fall back to replacing it.
//
// `fired` is what stops these cases proving nothing. If the interceptor ever
// stops matching, every adopt case still passes — `loadOrCreateFingerprintKey`
// simply returns the winner off its ordinary read path, which is the same
// answer for the wrong reason.
const raceControl = vi.hoisted(() => ({
  keyFilename: 'exception.key',
  hideKeyFileOnce: false,
  hideKeyFileAlways: false,
  fired: 0,
}));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof FsModule>();
  const readFileSyncWithRace = ((...args: Parameters<typeof actual.readFileSync>) => {
    const hit = String(args[0]).endsWith(raceControl.keyFilename);
    if (hit && (raceControl.hideKeyFileAlways || raceControl.hideKeyFileOnce)) {
      raceControl.hideKeyFileOnce = false;
      raceControl.fired += 1;
      const err = new Error('ENOENT (simulated race)') as NodeJS.ErrnoException;
      err.code = 'ENOENT';
      throw err;
    }
    return actual.readFileSync(...args);
  }) as typeof actual.readFileSync;
  return { ...actual, readFileSync: readFileSyncWithRace };
});

// The hoisted factory cannot close over an import, so the filename it matches on
// is a literal. Pin it to the constant every other line uses: a rename that
// disarmed the interceptor would otherwise leave the adopt cases green.
it('the race interceptor matches the real key filename', () => {
  expect(raceControl.keyFilename).toBe(EXCEPTION_KEY_FILENAME);
});

const POSIX_MODES = process.platform !== 'win32';

// Enough threads to make simultaneous occupancy the norm rather than a fluke —
// the barrier releases them together, so they are all inside the absence-check
// window at once.
const RACERS = 6;

const ARRIVED = 0;
const RELEASE = 1;
const MAX_INSIDE = 3;
const SLOTS = 4;
const BARRIER_TIMEOUT_MS = 15_000;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-fp-race-'));
});

afterEach(() => {
  raceControl.hideKeyFileOnce = false;
  raceControl.hideKeyFileAlways = false;
  raceControl.fired = 0;
  rmSync(dir, { recursive: true, force: true });
});

// Defaulted to the per-test dir so every existing caller is unaffected. The
// shared race below owns a dir of its own and passes it, because its key must
// outlive the per-test lifecycle that both cases reading it run under.
const keyFile = (dataDir: string = dir): string => join(dataDir, EXCEPTION_KEY_FILENAME);

/** What one racing thread ended up holding. */
type Minted = Omit<MintOutcome, 'ok'>;

interface RaceResult {
  minted: Minted[];
  /**
   * How many threads had reached the barrier when it lifted, and whether a key
   * was already published at that instant.
   *
   * These are the race's positive controls, and without them convergence proves
   * nothing: threads that never overlap agree on one key trivially. A count
   * below the total means the starting thread released early; a key already on
   * disk means somebody was past the absence check before the others began.
   */
  arrivedAtRelease: number;
  keyPublishedAtBarrier: boolean;
  /**
   * The most threads that were inside the mint call at the same moment. The two
   * controls above bound what happened BEFORE the release; only this one says
   * the threads actually overlapped afterwards, which is the whole premise.
   */
  maxConcurrent: number;
}

/**
 * Block until every racing thread has reached the barrier. The starting thread
 * parks here rather than sleeping, so "they all raced" is an ordering guarantee
 * and not a hopeful timeout.
 *
 * A thread that failed to load never arrives, and this thread is parked and so
 * cannot receive its 'error' event — the two look identical from here, which is
 * why the timeout names both.
 */
function awaitBarrier(signal: Int32Array, count: number): void {
  const deadline = Date.now() + BARRIER_TIMEOUT_MS;
  let arrived = Atomics.load(signal, ARRIVED);
  while (arrived < count) {
    const left = deadline - Date.now();
    if (left <= 0) {
      throw new Error(
        `only ${String(arrived)} of ${String(count)} minters reached the barrier within ` +
          `${String(BARRIER_TIMEOUT_MS)}ms — a thread failed to start, or failed to load the module`,
      );
    }
    Atomics.wait(signal, ARRIVED, arrived, left);
    arrived = Atomics.load(signal, ARRIVED);
  }
}

// How many times to re-run the race looking for real overlap.
//
// The barrier guarantees the threads are all PARKED and released together, and
// `arrivedAtRelease` / `keyPublishedAtBarrier` pin that on every run. It cannot
// guarantee two of them are inside the mint at the same INSTANT, because that is
// a scheduling outcome: the mint is a handful of syscalls, and a runner with
// fewer free cores than racers can finish one thread before the next is
// scheduled and legitimately observe an occupancy of 1. CI runs the whole
// workspace under `turbo --force`, so the machine is oversubscribed and that is
// the normal case there, not a rare one.
//
// Retrying is what separates "this machine would not overlap" from "the code
// stopped overlapping": several independent attempts make a genuinely
// concurrent runner show it, while a saturated one is reported as unmeasurable
// instead of failing. The loser-adopts path itself is not left to this — the
// interceptor cases below force it deterministically on every run.
const OVERLAP_ATTEMPTS = 5;

interface OverlapRace {
  /**
   * The LAST attempt run, which is the only one a caller may compare against
   * the data dir: every attempt wipes and re-mints, so an earlier attempt's
   * key no longer exists anywhere.
   */
  race: RaceResult;
  /**
   * The highest occupancy seen across every attempt. Reported rather than
   * asserted — it exists so a skip can say what the runner actually managed,
   * and it can exceed `race.maxConcurrent` only when no attempt overlapped.
   */
  bestMaxConcurrent: number;
  attempts: number;
}

/**
 * Race repeatedly until two threads are actually observed inside the mint at
 * once, returning the LAST attempt and the best occupancy seen.
 *
 * Each attempt needs a FRESH data dir: a retry against a dir that already holds
 * the published key takes the load path and races nothing, so it would report a
 * tidy `maxConcurrent` of 0 forever.
 *
 * Returning the last attempt rather than the best-scoring one is load-bearing,
 * and returning the best is a bug this function shipped with. Each attempt wipes
 * the dir and mints a NEW random key, so the key on disk is always the last
 * attempt's. Handing back an earlier attempt's `minted` gives the caller two
 * unrelated keys to compare, and `agreedKey(...) === keyOnDisk()` then fails on
 * a mismatch that means nothing — on exactly the serialized runner the retry
 * loop exists to accommodate. When an attempt DOES overlap the loop stops on it,
 * so the last attempt is that attempt and the two readings coincide.
 */
async function raceUntilOverlap(dataDir: string, count: number): Promise<OverlapRace> {
  const attempt = async (): Promise<RaceResult> => {
    rmSync(dataDir, { recursive: true, force: true });
    mkdirSync(dataDir, { recursive: true });
    return raceToMint(dataDir, count);
  };

  // The first attempt runs unconditionally, so the caller never has to reason
  // about an empty run.
  let race = await attempt();
  let bestMaxConcurrent = race.maxConcurrent;
  let attempts = 1;
  while (attempts < OVERLAP_ATTEMPTS && race.maxConcurrent < 2) {
    race = await attempt();
    attempts += 1;
    bestMaxConcurrent = Math.max(bestMaxConcurrent, race.maxConcurrent);
  }
  return { race, bestMaxConcurrent, attempts };
}

/** Mint from `count` threads released at the same instant. */
async function raceToMint(
  dataDir: string,
  count: number,
  target: 'fingerprint' | 'vault' = 'fingerprint',
): Promise<RaceResult> {
  const shared = new SharedArrayBuffer(SLOTS * Int32Array.BYTES_PER_ELEMENT);
  const signal = new Int32Array(shared);
  const workers: Worker[] = [];
  const outcomes: Promise<Minted>[] = [];

  // Construction is inside the try so a thread that fails to spawn still takes
  // its already-parked siblings down with it — they wait on a release that
  // would otherwise never come, holding the temp dir and the run open.
  try {
    for (let i = 0; i < count; i += 1) {
      const worker = new Worker(new URL('../helpers/mint-worker.ts', import.meta.url), {
        workerData: { dataDir, target, shared },
      });
      // The racers must never be what keeps the run alive.
      worker.unref();
      workers.push(worker);
      const outcome = new Promise<Minted>((resolve, reject) => {
        worker.once('message', (msg: MintOutcome | MintFailure) => {
          if (msg.ok) resolve({ version: msg.version, material: msg.material });
          else reject(new Error(msg.message));
        });
        worker.once('error', reject);
      });
      // Settle the rejection now. Nothing awaits these until after the barrier,
      // so a thread that dies early would otherwise surface as an unhandled
      // rejection and bury the barrier's own diagnostic.
      outcome.catch(() => undefined);
      outcomes.push(outcome);
    }

    awaitBarrier(signal, count);
    // Read BEFORE the release: every thread is parked here, so nothing can
    // have minted yet unless the barrier failed to hold them.
    const arrivedAtRelease = Atomics.load(signal, ARRIVED);
    const keyPublishedAtBarrier = existsSync(
      join(dataDir, target === 'vault' ? VAULT_KEY_FILENAME : EXCEPTION_KEY_FILENAME),
    );
    Atomics.store(signal, RELEASE, 1);
    Atomics.notify(signal, RELEASE);
    const minted = await Promise.all(outcomes);
    return {
      minted,
      arrivedAtRelease,
      keyPublishedAtBarrier,
      maxConcurrent: Atomics.load(signal, MAX_INSIDE),
    };
  } finally {
    await Promise.all(workers.map((worker) => worker.terminate()));
  }
}

/** The key as it landed on disk. */
function keyOnDisk(dataDir: string = dir): Minted {
  const parsed = JSON.parse(readFileSync(keyFile(dataDir), 'utf8')) as {
    version: number;
    material: string;
  };
  return {
    version: parsed.version,
    material: Buffer.from(parsed.material, 'base64').toString('hex'),
  };
}

/** Every racer agreed, and on what. */
function agreedKey(minted: Minted[]): string {
  const distinct = new Set(minted.map((m) => `${String(m.version)}:${m.material}`));
  expect(distinct.size).toBe(1);
  return [...distinct][0] ?? '';
}

describe('concurrent first mints converge on one key', () => {
  // ONE race, read by the two cases below. They are two assertions about the
  // SAME run, and that is the point rather than an optimisation: the occupancy
  // case exists to say the convergence case was not trivial, which it can only
  // say about the run that produced it. Racing twice let one case overlap and
  // the other serialize, so the reassurance described a run nobody asserted on.
  //
  // It also halves what a starved runner pays here — the retry loop only
  // iterates when nothing overlaps, which is exactly the runner that can least
  // afford paying for it twice.
  //
  // The dir is owned here rather than taken from `beforeEach`, because both
  // cases read a key that has to outlive the per-test lifecycle.
  let shared: OverlapRace;
  let sharedDir: string;

  beforeAll(async () => {
    sharedDir = mkdtempSync(join(tmpdir(), 'aka-fp-race-shared-'));
    shared = await raceUntilOverlap(sharedDir, RACERS);
  });

  afterAll(() => {
    rmSync(sharedDir, { recursive: true, force: true });
  });

  it('leaves every racing thread holding the key that is on disk', () => {
    const { race } = shared;

    // Positive controls first: threads that did not overlap agree trivially.
    expect(race.arrivedAtRelease).toBe(RACERS);
    expect(race.keyPublishedAtBarrier).toBe(false);

    // Asserted unconditionally, including on a runner that serialized the
    // threads. Convergence without overlap is a WEAKER claim, not a vacuous one
    // — it still catches a mint that publishes one key and hands back another —
    // and gating it on the overlap measurement is worse than keeping it: a
    // ctx.skip() throws, so every assertion below it would go unrun and be
    // reported as a skip rather than a gap. The overlap PREMISE is the only part
    // a scheduler can genuinely deny, so that is the part with its own case.
    expect(race.minted).toHaveLength(RACERS);
    // Read from the shared dir, and it must be the LAST attempt's key — every
    // attempt wipes and re-mints, so an earlier one's key is gone.
    const published = keyOnDisk(sharedDir);
    // The whole property: one key, and it is the one that was published.
    expect(agreedKey(race.minted)).toBe(`${String(published.version)}:${published.material}`);
    expect(published.version).toBe(1);
  });

  it('gets two threads inside the mint at once, so the case above is not trivial', (ctx) => {
    // The premise the convergence case rests on, measured on THAT run rather
    // than assumed or re-raced. It is a separate case because it is the one
    // claim here whose failure says nothing about the code: on a saturated
    // runner the threads genuinely do not overlap, so this is reported rather
    // than failed. Asserting it would blame the mint for the scheduler; folding
    // it back into the case above would take that case's real assertions down
    // with it, which is what a skip did before it was split out.
    if (shared.race.maxConcurrent < 2) {
      ctx.skip(
        `no attempt got two of ${String(RACERS)} threads inside the mint at once ` +
          `(best ${String(shared.bestMaxConcurrent)} over ${String(shared.attempts)} attempts) — ` +
          `this runner serialized them, so convergence was proven only trivially`,
      );
    }

    expect(shared.race.maxConcurrent).toBeGreaterThanOrEqual(2);
  });

  it('is stable afterwards — a later reader sees what the racers agreed on', async () => {
    const race = await raceToMint(dir, RACERS);

    expect(race.arrivedAtRelease).toBe(RACERS);
    expect(race.keyPublishedAtBarrier).toBe(false);
    const later = loadOrCreateFingerprintKey(dir);
    expect(agreedKey(race.minted)).toBe(
      `${String(later.version)}:${later.material.toString('hex')}`,
    );
  });
});

describe('the vault keyring does not share the defect', () => {
  // The store keeps two machine-local keys behind the same read-then-mint
  // shape, and the vault's blast radius is the larger one: a lost epoch does
  // not orphan a grant, it leaves ciphertext nothing can open. Both now publish
  // through the same primitive, so this pins the claim under real concurrency —
  // beside the defect it does not have, so a later change that regresses it
  // fails next to the reason.
  it('leaves every racing thread holding one keyring', async () => {
    const race = await raceToMint(dir, RACERS, 'vault');

    expect(race.arrivedAtRelease).toBe(RACERS);
    expect(race.keyPublishedAtBarrier).toBe(false);
    expect(race.minted).toHaveLength(RACERS);
    expect(agreedKey(race.minted)).toBe(`1:${race.minted[0]?.material ?? ''}`);
  });
});

describe('a mint that loses the race adopts the winner', () => {
  it('does not replace a key that appeared after its absence check', () => {
    const winner = loadOrCreateFingerprintKey(dir);
    const published = readFileSync(keyFile());

    // The loser's read reports absence, so it takes the mint path with the
    // winner's key already at the final path.
    raceControl.hideKeyFileOnce = true;
    const loser = loadOrCreateFingerprintKey(dir);

    expect(raceControl.fired).toBe(1);
    expect(loser.version).toBe(winner.version);
    expect(loser.material.equals(winner.material)).toBe(true);
    expect(readFileSync(keyFile()).equals(published)).toBe(true);
  });

  it('leaves the loser able to match grants the winner wrote', () => {
    // The harm the convergence exists to prevent, stated as the harm: a
    // fingerprint is an HMAC under this key and the raw value is never stored,
    // so material that differs by one byte produces a grant that can never be
    // matched again — approved, recorded, and inert.
    const winner = loadOrCreateFingerprintKey(dir);
    const grant = fingerprintValue(winner, 'AKIAIOSFODNN7EXAMPLE');

    raceControl.hideKeyFileOnce = true;
    const loser = loadOrCreateFingerprintKey(dir);

    expect(raceControl.fired).toBe(1);
    expect(fingerprintValue(loser, 'AKIAIOSFODNN7EXAMPLE')).toBe(grant);
  });

  it('adopts the stored version rather than the one it computed', () => {
    // Rotated TWICE so the winner sits at version 2 while the loser, whose
    // store reports no key version at all, computes 1 for itself. Without that
    // gap both numbers are 1 and the assertion cannot tell adopting from
    // keeping — which is the defect it exists to catch: a key file saying 2
    // while the holder believes 1 writes rows under a version no reader will
    // look for.
    rotateFingerprintKey(dir);
    const winner = rotateFingerprintKey(dir);
    expect(winner.version).toBe(2);

    raceControl.hideKeyFileOnce = true;
    const loser = loadOrCreateFingerprintKey(dir);

    expect(raceControl.fired).toBe(1);
    expect(loser.version).toBe(2);
    expect(loser.material.equals(winner.material)).toBe(true);
  });

  it.skipIf(!POSIX_MODES)('re-tightens a loosened key it adopted', () => {
    // The adopt path returns a file this process did not write, so it carries
    // whatever mode its writer left. Every other path that returns a stored key
    // re-tightens; this one has to as well.
    loadOrCreateFingerprintKey(dir);
    chmodLoose(keyFile());

    raceControl.hideKeyFileOnce = true;
    loadOrCreateFingerprintKey(dir);

    expect(raceControl.fired).toBe(1);
    expect(statSync(keyFile()).mode & 0o777).toBe(0o600);
  });

  it.skipIf(!POSIX_MODES)('keeps a freshly minted key owner-only', () => {
    loadOrCreateFingerprintKey(dir);

    expect(statSync(keyFile()).mode & 0o777).toBe(0o600);
  });

  it('leaves no publishing tmp behind', () => {
    loadOrCreateFingerprintKey(dir);

    expect(siblingsOf(keyFile())).toEqual([EXCEPTION_KEY_FILENAME]);
  });
});

describe('a lost race that cannot be resolved fails secure', () => {
  it('throws rather than replacing a winner it cannot read back', () => {
    loadOrCreateFingerprintKey(dir);
    const published = readFileSync(keyFile());

    // Every read reports absence: the mint path is taken, the publish still
    // loses to the real file, and the re-read cannot say who won. The one thing
    // that must not happen is falling back to a replacing write.
    raceControl.hideKeyFileAlways = true;
    const err = errorFrom(() => loadOrCreateFingerprintKey(dir));
    raceControl.hideKeyFileAlways = false;

    expect(err).toBeDefined();
    // Names the branch, not just the module: every corrupt-key message also
    // contains "exception key file", and the case two describes down is exactly
    // the one this must not be confused with.
    expect(err?.message).toMatch(/removed while it was being created/);
    // Codeless errors are rendered as "the key is corrupt, delete it", whose
    // remedy would orphan every grant under the healthy key still on disk.
    expect((err as { code?: string } | undefined)?.code).toBe('key-unclaimable');
    expect(readFileSync(keyFile()).equals(published)).toBe(true);
  });

  it('throws on a corrupt winner instead of minting over it', () => {
    // A corrupt key already throws on the read path. It must also throw on the
    // MINT path, which is the one place the module has material in hand and
    // could be tempted to publish it.
    loadOrCreateFingerprintKey(dir);
    // Parseable JSON of the wrong shape, so /corrupt/ below is the module's own
    // refusal and not a JSON.parse SyntaxError that would say the same thing
    // about any garbage at all.
    const corrupt = JSON.stringify({ version: 1, material: 'short' });
    writeRaw(keyFile(), corrupt);

    raceControl.hideKeyFileOnce = true;
    const err = errorFrom(() => loadOrCreateFingerprintKey(dir));

    expect(raceControl.fired).toBe(1);
    expect(err).toBeDefined();
    expect(err?.message).toMatch(/corrupt/);
    expect(readFileSync(keyFile(), 'utf8')).toBe(corrupt);
  });

  it.skipIf(!POSIX_MODES)('refuses to mint through a symlink at the key path', () => {
    // A link is refused whether or not its target exists, so a planted one is
    // never written through and never has its target created. The refusal has
    // to NAME the symlink: the remedy is removing it, and the message this
    // branch would otherwise share says the file was removed instead.
    const target = join(dir, 'elsewhere.key');
    symlinkSync(target, keyFile());

    const err = errorFrom(() => loadOrCreateFingerprintKey(dir));

    expect(err).toBeDefined();
    expect(err?.message).toMatch(/symlink/);
    expect((err as { code?: string } | undefined)?.code).toBe('key-unclaimable');
    expect(existsSync(target)).toBe(false);
  });
});

describe('the fixed mint preserves the behaviour around it', () => {
  // The neighbouring `fingerprint.test.ts` owns these contracts against the real
  // fs; this file runs under a mocked `readFileSync`, so one case re-checks that
  // the mint still behaves when the interceptor is dormant. The rest are not
  // duplicated here.
  it('still mints on a genuinely absent key, with the interceptor dormant', () => {
    expect(readFingerprintKey(dir)).toBeNull();

    const key = loadOrCreateFingerprintKey(dir);

    expect(raceControl.fired).toBe(0);
    expect(key.version).toBe(1);
    expect(key.material).toHaveLength(32);
    expect(readFingerprintKey(dir)?.material.equals(key.material)).toBe(true);
  });
});

// Plants bytes the module would never produce. The race mock patches reads
// only, so this reaches the real file.
function writeRaw(file: string, body: string): void {
  writeFileSync(file, body);
}

// A mode no writer in this package produces, so re-tightening to 0600 is
// observable rather than already true.
function chmodLoose(file: string): void {
  chmodSync(file, 0o644);
}

/** Every entry beside the key, so a leftover tmp is visible. */
function siblingsOf(file: string): string[] {
  return readdirSync(join(file, '..')).sort();
}
