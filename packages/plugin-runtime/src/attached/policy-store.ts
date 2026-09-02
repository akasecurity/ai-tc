import { randomUUID } from 'node:crypto';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { DATA_FILE_MODE, dataDir, ensureDataDir } from '@akasecurity/plugin-sdk';
import { POLICY_BUNDLE_SHAPE_ID, PolicyBundle } from '@akasecurity/schema';

import { publishByRename } from './atomic-publish.ts';

// The cached policy bundle, the epoch-ms it was last CONFIRMED FRESH (drives
// sync throttling and staleness reporting), and the ETag that confirmed it.
// Owned here alongside the store that reads/writes it.
export interface StoredPolicyBundle {
  bundle: PolicyBundle;
  /**
   * Advances on a 304 as well as a 200 — it records when the bundle was last
   * known current, not when its bytes last changed. Staleness in
   * `renderAttachedStatus` is measured off this, so treating a 304 as "no
   * update" here would make a perfectly fresh device look stale.
   */
  fetchedAtMs: number;
  /**
   * Last ETag the control plane gave for this bundle, replayed as `If-None-Match`.
   * Optional because a cache written before B3 shipped ETags has none — `read`
   * stays tolerant of that two-member shape rather than failing closed on it.
   */
  etag?: string;
  /**
   * Which bundle fields the build that wrote this record understood, as
   * `POLICY_BUNDLE_SHAPE_ID` reported them.
   *
   * Optional because a record written before this was stamped carries none —
   * which reads as a mismatch, so every cache already on disk gives up its
   * validator once and is refilled in full. That is the repair, not a
   * concession to it.
   */
  shapeId?: string;
}

/**
 * Disk-backed policy bundle cache.
 *
 * Hooks are short-lived processes (one per event), so an in-memory cache is
 * always cold. The hook path reads this file and never touches the network;
 * `runPolicySync` (policy-sync.ts), running in a detached child, writes it
 * out-of-band.
 */
export function createPolicyStore(dir: string = dataDir()) {
  const file = join(dir, 'policy-cache.json');

  async function read(): Promise<StoredPolicyBundle | null> {
    try {
      const raw = await readFile(file, 'utf8');
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed !== 'object' || parsed === null) return null;
      const record = parsed as {
        bundle?: unknown;
        fetchedAtMs?: unknown;
        etag?: unknown;
        shapeId?: unknown;
      };
      const bundle = PolicyBundle.parse(record.bundle);
      const fetchedAtMs = typeof record.fetchedAtMs === 'number' ? record.fetchedAtMs : 0;
      // Tolerant, not strict: a pre-B3 cache has no etag and must still be
      // usable. Omitting the key rather than storing `undefined` is what
      // exactOptionalPropertyTypes wants.
      const stored = typeof record.etag === 'string' ? record.etag : undefined;
      // The VALIDATOR is dropped — and only the validator — when this record was
      // written by a build that understood a different set of bundle fields.
      //
      // `PolicyBundle.parse` above strips any key this build does not declare,
      // so a record an older build wrote is missing whatever that build had
      // never heard of, while still carrying the `version` of a representation
      // that carried it. Replaying that etag earns a 304, and the sync's
      // not-modified arm rewrites the same narrowed body with a fresh validator
      // — so the absent field can never arrive, and upgrading the plugin does
      // not help, because the etag still matches. Handing the puller no
      // validator makes the next request unconditional, and the control plane
      // answers it with the whole bundle, which this build parses with the
      // fields it does know about.
      //
      // The BUNDLE itself is kept. Returning null here instead would drop the
      // organization's raise-only floor until a sync lands — enforcement lost in
      // order to repair enforcement — and a body missing a field this build
      // understands is still every rule and policy the device had a moment ago.
      //
      // A stamp naming MORE than this build is replayable, not a mismatch. Such
      // a record was written by a wider build and already carries everything
      // this one declares, so its validator describes a representation this
      // build has no reason to refetch — and treating it as a mismatch would
      // make the narrower build pull the whole bundle unconditionally every
      // window for the life of the install, which is the cheap-poll-into-full-
      // transfer cost the transport refuses at length.
      const replayable =
        record.shapeId === POLICY_BUNDLE_SHAPE_ID || knowsMoreThanThisBuild(record.shapeId);
      const etag = replayable ? stored : undefined;
      return { bundle, fetchedAtMs, ...(etag === undefined ? {} : { etag }) };
    } catch {
      // Fail-open: an unreadable or corrupt cache behaves like no cache
      return null;
    }
  }

  /**
   * Whether `shapeId` names strictly MORE bundle fields than this build has.
   *
   * `POLICY_BUNDLE_SHAPE_ID` is a sorted comma-joined key list, so this is a set
   * comparison. An absent, empty or unrecognisable stamp is deliberately NOT a
   * superset: those are the records the shape check exists to replace, and
   * treating them as wider would freeze every cache written before stamping.
   */
  function knowsMoreThanThisBuild(shapeId: unknown): boolean {
    if (typeof shapeId !== 'string' || shapeId === '') return false;
    const theirs = new Set(shapeId.split(','));
    const ours = POLICY_BUNDLE_SHAPE_ID.split(',');
    return theirs.size > ours.length && ours.every((key) => theirs.has(key));
  }

  /** The record currently on disk, unvalidated, or null when there is none. */
  async function priorRecord(): Promise<Record<string, unknown> | null> {
    try {
      const parsed: unknown = JSON.parse(await readFile(file, 'utf8'));
      return typeof parsed === 'object' && parsed !== null
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      return null;
    }
  }

  /**
   * Publish one record atomically.
   *
   * Shared by both arms of `write` so the tmp-and-rename reasoning below is
   * stated once and neither arm can drift into a plain overwrite.
   */
  async function publishRecord(record: StoredPolicyBundle): Promise<void> {
    // Per-write suffix, not a fixed `${file}.tmp` — the same reasoning as
    // posture-store.ts and forward-policy.ts, which this file was the last in
    // the package not to follow. Two sync children can overlap (the throttle
    // bounds the common case, not concurrent sessions or a manual `aka sync`),
    // and with one shared temp name they interleave into it: the loser's rename
    // hits ENOENT, or worse, one writes while the other renames and the cache
    // lands torn. `read()` then fails its `PolicyBundle.parse` and returns null,
    // which is fail-open by design — so the organization's raise-only floor silently
    // disappears until the next successful sync. That is enforcement, lost
    // quietly, which is exactly what this cache must not do.
    //
    // `wx` refuses to follow a symlink planted at the tmp path and refuses to
    // reuse a stale one, so the write cannot be redirected onto another file.
    const tmp = `${file}.${randomUUID()}.tmp`;
    try {
      // 0600: the policy bundle can carry org-specific rules and custom keywords
      await writeFile(tmp, JSON.stringify(record), {
        encoding: 'utf8',
        mode: DATA_FILE_MODE,
        flag: 'wx',
      });
      // Atomic swap so a hook reading concurrently never sees a torn file.
      // Through `publishByRename` because Windows refuses a rename whose
      // destination another handle has open — a concurrent reader is enough —
      // and raises the same EPERM when two publishes race. Both are transient
      // and neither means the bytes are wrong.
      await publishByRename(tmp, file);
    } catch (err) {
      // Never leave the temp behind to accumulate in ~/.aka; the write itself
      // still fails loudly to `runPolicySync`, which records the outcome.
      await rm(tmp, { force: true }).catch(() => undefined);
      throw err;
    }
  }

  /**
   * Persist the bundle and the validator that confirmed it.
   *
   * `etag` is a second parameter rather than the caller handing over a whole
   * `StoredPolicyBundle` so that `fetchedAtMs` keeps a single writer here —
   * every caller stamping its own clock is how two cache entries end up
   * disagreeing about what "fresh" means. The 304 arm expresses itself by
   * passing the bundle it already holds back in with the new etag.
   */
  async function write(bundle: PolicyBundle, etag?: string): Promise<void> {
    await ensureDataDir(dir);

    // A build that understands FEWER fields does not get to flatten a record a
    // wider one wrote.
    //
    // One `~/.aka` serves every host plugin on the machine — the data dir has no
    // per-host segment — and they are separately published packages that upgrade
    // on their own schedules, so a narrower build sharing this cache is the
    // ordinary state of a machine during a rollout, not an edge case. Its pull
    // parses the full body with its own schema, drops what it has never heard
    // of, and would write that back; the wider build would then have to spend
    // another pull recovering a field it does understand, which the shared sync
    // throttle can hold off for a whole window. Two builds would take turns
    // narrowing and repairing one file.
    //
    // Two overlapping children can still interleave this read and the publish.
    // That race is benign and is not worth a lock. What can slip through is a
    // LOST UPDATE rather than a narrowing — the branch below republishes a
    // record read a moment earlier, so a wider build's newer record can be
    // clobbered by an older one CARRYING THE WIDER STAMP, which `read` will
    // therefore not withhold a validator for. It still converges: the pair it
    // republishes is internally consistent, so the wider build's next
    // conditional pull answers 200 and rewrites it.
    const prior = await priorRecord();
    const priorVersion = (prior?.bundle as { version?: unknown } | undefined)?.version;
    if (
      prior !== null &&
      knowsMoreThanThisBuild(prior.shapeId) &&
      priorVersion === bundle.version
    ) {
      // SAME VERSION, wider body: flattening it would destroy fields this build
      // cannot even name, to land bytes the device already has. So the body and
      // the stamp both stay, and only freshness moves.
      //
      // Freshness has to move, because `fetchedAtMs` advances nowhere else. Left
      // frozen, status renders an ever-growing "fetched N ago" and the posture
      // report tells the control plane the device stopped syncing while it is in
      // fact syncing successfully every window.
      //
      // The VALIDATOR is deliberately not adopted. Pairing bytes with an etag
      // this build never held for them would rest on the control plane bumping
      // `version` for every representation it serves — true of the deployment
      // this ships against, and not a property this package owns or can check.
      // Keeping the etag already on disk costs at most one conditional round
      // trip and assumes nothing.
      await publishRecord({
        ...(prior as unknown as StoredPolicyBundle),
        fetchedAtMs: Date.now(),
      });
      return;
    }

    // A DIFFERENT version falls through and is written, narrowed. That is the
    // whole point of scoping the guard to an equal version: the organization has
    // published a new policy, and a device that refuses to adopt it because it
    // cannot represent one field of the old one is worse off than one that adopts
    // it narrowed. Declining here instead would deadlock — `read` hands the wider
    // record's validator back on the next pass, the pull returns the same 200,
    // and the write declines again, every window, forever, while `pullPolicyBundle`
    // reports `ok`. Writing it stamps THIS build's narrower shape, which is
    // exactly what makes the wider build's next read withhold its validator and
    // restore the fields in one unconditional pull.

    await publishRecord({
      bundle,
      fetchedAtMs: Date.now(),
      // Stamped on EVERY write, the 304 arm's included: that arm hands back the
      // bundle it already holds, and the point of the stamp is to describe the
      // build that last narrowed those bytes, which is this one.
      shapeId: POLICY_BUNDLE_SHAPE_ID,
      ...(etag === undefined ? {} : { etag }),
    });
  }

  return { read, write, file };
}

export type PolicyStore = ReturnType<typeof createPolicyStore>;
