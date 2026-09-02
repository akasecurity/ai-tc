import { randomUUID } from 'node:crypto';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { createOwnerOnlyFileSync } from '@akasecurity/persistence';
import { DATA_FILE_MODE, ensureDataDir, settingsDir } from '@akasecurity/plugin-sdk';

import { publishByRename } from './atomic-publish.ts';

export interface PostureState {
  deviceId: string;
  /**
   * When the last report was ATTEMPTED, not when one last succeeded. The
   * distinction is load-bearing: this stamp gates a blocking, un-preemptible
   * SQLite read (see readStorePosture), so tying it to success meant an
   * unreachable control plane re-paid that read on every SessionStart — the exact
   * scenario the "at most once an hour" reassurance was defending.
   */
  lastAttemptedAtMs: number;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Device identity + report throttle.
 *
 * `dir` defaults to ~/.aka/settings, NOT ~/.aka/data — deliberately OUTSIDE the
 * directory this feature measures. The adversary the regression detector exists
 * to catch removes ~/.aka/data to destroy local findings; with the identity
 * stored in there, that same removal took the key continuity is judged by. The
 * next report arrived under a fresh deviceId, `getByDeviceId` returned null, and
 * `isRegression(null, …)` scored the wipe as a first-ever report — so the one
 * event the channel is built to detect was the one event it could not see.
 * settings/ is a sibling of data/, so it survives the wipe and the new report
 * lands on the existing row with its preserved baseline.
 *
 * `legacyDir` is the pre-move location, and is OPT-IN rather than defaulted:
 * only a caller that knows the real on-disk layout (the factory, which has
 * config.dataDir) should reach outside `dir` at all. Defaulting it to dataDir()
 * would make a single-argument call — every test, every embedder passing a temp
 * dir — silently read the developer's real ~/.aka/data.
 *
 * When supplied it is consulted only if no current file exists, so a device
 * enrolled before this change keeps its deviceId and its server-side history
 * instead of silently re-enrolling as new (which would look exactly like the
 * wipe above). The old file is left in place rather than deleted: adoption is a
 * read, and a failed unlink must not be able to break the fail-open path.
 */
export function createPostureStore(dir: string = settingsDir(), legacyDir?: string) {
  const file = join(dir, 'posture-state.json');
  const legacyFile = legacyDir === undefined ? null : join(legacyDir, 'posture-state.json');

  async function persist(state: PostureState): Promise<void> {
    await ensureDataDir(dir);
    // Per-write suffix, not a fixed `${file}.tmp`. Two SessionStart hooks can
    // run concurrently; with one shared temp name both write it and the second
    // rename hits ENOENT because the first already moved it away. Fail-open
    // swallows that, but it silently loses a throttle advance — and the throttle
    // now gates the blocking store read, so losing it costs a re-scan.
    const tmp = `${file}.${randomUUID()}.tmp`;
    try {
      await writeFile(tmp, JSON.stringify(state), { encoding: 'utf8', mode: DATA_FILE_MODE });
      // Atomic swap so a concurrent hook never sees a torn file. Same Windows
      // caveat as the policy cache: a rename whose destination another handle
      // has open is refused there, transiently, so it goes through the shared
      // retry.
      await publishByRename(tmp, file);
    } catch (err) {
      // Never leave the temp behind, the same guarantee `policy-store.ts` makes
      // about the identical pair. The suffix is a fresh uuid per write, so a
      // leaked temp is not overwritten by the next attempt — they accumulate in
      // the settings dir without bound, and nothing surfaces it: every caller of
      // `persist` swallows, so the machine reports normally while the directory
      // fills.
      //
      // Reachable rather than theoretical since the retry landed. POSIX rename
      // does not fail here, which is why this was survivable before; Windows
      // refuses a contended destination, and `publishByRename` rethrows once its
      // attempts are spent — so a destination held past the budget leaks one
      // file per publish, on exactly the platform the retry exists for.
      await rm(tmp, { force: true }).catch(() => undefined);
      throw err;
    }
  }

  async function readFrom(path: string): Promise<PostureState | null> {
    // Split the read from the parse, the same way readStorePosture splits
    // "could not measure" from "not there": ENOENT/ENOTDIR are the only
    // errors that mean this file genuinely doesn't exist. Any other error —
    // EACCES, EMFILE, EIO, a transient lock — means the identity might well
    // still be sitting there, so it must NOT be treated as "no identity yet".
    // Collapsing both into null used to make a one-off permission hiccup mint
    // a fresh deviceId and overwrite the intact file, destroying the very
    // continuity this store exists to preserve. Thrown here, it propagates out
    // of read() untouched and prepare()'s fail-open catch turns it into "no
    // report this attempt" — the file is never touched.
    let raw: string;
    try {
      raw = await readFile(path, 'utf8');
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT' || code === 'ENOTDIR') return null;
      throw err;
    }
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed === 'object' && parsed !== null) {
        const record = parsed as {
          deviceId?: unknown;
          lastAttemptedAtMs?: unknown;
          lastReportedAtMs?: unknown;
        };
        if (typeof record.deviceId === 'string' && UUID_RE.test(record.deviceId)) {
          // `lastReportedAtMs` is the pre-rename spelling. Read it as a fallback
          // so an upgrading fleet doesn't all reset to 0 and report at once; the
          // two mean close enough for a throttle stamp that carrying it over is
          // better than a synchronized burst.
          const stamp =
            typeof record.lastAttemptedAtMs === 'number'
              ? record.lastAttemptedAtMs
              : typeof record.lastReportedAtMs === 'number'
                ? record.lastReportedAtMs
                : 0;
          return { deviceId: record.deviceId, lastAttemptedAtMs: stamp };
        }
      }
    } catch {
      // Fail-open: content that READ fine but is corrupt/malformed (truncated
      // write, garbage bytes) behaves like a fresh install — unlike an I/O
      // error, there is no intact identity here to protect.
    }
    return null;
  }

  async function read(): Promise<PostureState | null> {
    const current = await readFrom(file);
    if (current) return current;
    // One-time adoption of the pre-move identity (see the legacyDir note above).
    // Skipped when unsupplied, or when it resolves to the file just read.
    //
    // readFrom's non-ENOENT throw is right for `file` above — that's the
    // identity worth protecting from a silent overwrite. It is wrong here:
    // an EACCES/EIO on the LEGACY location (e.g. a root-owned pre-move
    // ~/.aka/data on a machine that never re-owned it) would otherwise
    // propagate out of read() on every single call, permanently — never
    // reaching the fresh-mint path below even once, for as long as that
    // legacy path stays unreadable. Adoption is opt-in and best-effort by
    // design (see the class doc: "adoption is a read … must not break the
    // fail-open path"); a legacy read failure is just "nothing to adopt".
    const legacy =
      legacyFile === null || legacyFile === file
        ? null
        : await readFrom(legacyFile).catch(() => null);
    if (legacy) {
      // Persisting is best-effort here: the legacy identity was just
      // successfully READ, so failing the rewrite must not discard it. An
      // unpersisted adoption still reports this session under the RIGHT id;
      // the cost is a re-adoption next session while the legacy file survives
      // (it is deliberately left in place — see the class doc).
      try {
        await persist(legacy);
      } catch {
        // fail-open: an unpersisted adoption still reports this session
      }
      return legacy;
    }
    // Fresh mint is NOT best-effort the same way. There is no prior identity
    // to fall back to here — if persist() fails, this id is unrecoverable, and
    // returning it anyway means every SessionStart mints ANOTHER fresh id
    // (nothing was ever saved to find next time): one orphan remote row per
    // session, isRegression permanently blind on this host (previous is
    // always null), and the throttled scan re-paid every session (the
    // throttle for this id was never persisted either). Refusing to mint and
    // returning null instead costs one skipped report — fail-open the same
    // way an unwritable settings dir fails open everywhere else in this
    // reporter, rather than manufacturing fleet noise.
    //
    // PUBLISHED WITH AN EXCLUSIVE CREATE, not the tmp+rename `persist` uses, and
    // that difference is the whole point. Two SessionStart hooks reaching this
    // line together each mint their own uuid; with a rename the last writer wins
    // the FILE while the loser still returns the id it minted — an id nothing
    // ever persisted, so that session reports under an identity the control
    // plane sees exactly once and never again. One orphan device per race, from
    // ordinary hook concurrency, with none of the wipe the class doc blames for
    // the same symptom.
    //
    // An exclusive create answers who won. The loser re-reads and ADOPTS, which
    // is sound here for the reason the fingerprint's first mint is: a fresh
    // identity has nothing to preserve, so taking the winner's is not a loss.
    // `persist`'s rename stays right everywhere else in this file, where there
    // IS a prior value and overwriting is the intent.
    const fresh: PostureState = { deviceId: randomUUID(), lastAttemptedAtMs: 0 };
    try {
      await ensureDataDir(dir);
      if (createOwnerOnlyFileSync(file, JSON.stringify(fresh))) return fresh;
    } catch {
      return null;
    }
    // The create was refused, which means the path is occupied — but by which of
    // two very different things. A concurrent hook that won the race left a
    // VALID state, and its id is the machine's id. A corrupt or truncated file
    // left by an earlier crash is also "occupied", and adopting nothing from it
    // would strand the machine with no identity for as long as those bytes sit
    // there — the exact fresh-install case the corrupt-file path exists to
    // recover, which is why this cannot simply return null.
    const winner = await readFrom(file).catch(() => null);
    if (winner) return winner;
    // Nothing adoptable there: overwrite it, which is what the tmp+rename
    // publish is for. Single-writer in practice, since a concurrent mint would
    // have left a readable file above.
    try {
      await persist(fresh);
    } catch {
      return null;
    }
    return fresh;
  }

  /**
   * Advances the throttle for the device the caller is about to report on.
   * `deviceId` is passed in rather than re-read: read() mints a FRESH deviceId
   * whenever the state file is missing or unparseable, so re-reading here would
   * advance the throttle for a device that never reported and strand the row the
   * control plane actually holds — it would age into a permanent silent/unmanaged
   * entry while the new id sits throttled for a full interval.
   *
   * Called BEFORE the send, not after: the throttle's job is to bound the
   * blocking store read, and a stamp that only moves on success does not bound
   * it against an unreachable control plane.
   */
  async function markAttempted(deviceId: string, atMs: number): Promise<void> {
    await persist({ deviceId, lastAttemptedAtMs: atMs });
  }

  return { read, markAttempted, file };
}

export type PostureStore = ReturnType<typeof createPostureStore>;

/**
 * This machine's device identity, minting and persisting one if it has none.
 *
 * A NARROW DOOR onto the store above, exported so `aka attach` can tell a
 * deployment which machine is asking WITHOUT this package handing out its whole
 * posture surface. The CLI needs exactly one string and no ability to stamp
 * attempt timestamps or reach the file path.
 *
 * Sharing the store matters more than the convenience. If the CLI minted its own
 * id, a machine would present one identity when attaching and a different one
 * when reporting posture, so the deployment would see two devices for one
 * laptop — and a later re-attach would create a second machine record instead of
 * rotating the first. Reading through the same store is what keeps those the
 * same machine.
 *
 * Answers `null` when the identity could not be read OR minted — a permissions
 * problem on `~/.aka/settings`, most often. The caller decides what to do about
 * it; there is deliberately no fallback id here, because a fabricated one would
 * reintroduce exactly the split this function exists to prevent.
 */
export async function readDeviceIdentity(dir?: string): Promise<string | null> {
  const state = await createPostureStore(dir).read();
  return state?.deviceId ?? null;
}
