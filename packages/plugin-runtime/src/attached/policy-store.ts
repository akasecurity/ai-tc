import { randomUUID } from 'node:crypto';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { POLICY_CACHE_FILENAME } from '@akasecurity/persistence';
import { DATA_FILE_MODE, dataDir, ensureDataDir } from '@akasecurity/plugin-sdk';
import { PolicyBundle } from '@akasecurity/schema';

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
  // The name comes from the detach list rather than from a literal, so a rename
  // moves the writer with it. This is the file that list singles out as the most
  // consequential to leave behind, and it was the one writer not reading it —
  // which made a rename typecheck clean while detach quietly stopped clearing
  // the cache and this kept writing it under the old name.
  const file = join(dir, POLICY_CACHE_FILENAME);

  async function read(): Promise<StoredPolicyBundle | null> {
    try {
      const raw = await readFile(file, 'utf8');
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed !== 'object' || parsed === null) return null;
      const record = parsed as { bundle?: unknown; fetchedAtMs?: unknown; etag?: unknown };
      const bundle = PolicyBundle.parse(record.bundle);
      const fetchedAtMs = typeof record.fetchedAtMs === 'number' ? record.fetchedAtMs : 0;
      // Tolerant, not strict: a pre-B3 cache has no etag and must still be
      // usable. Omitting the key rather than storing `undefined` is what
      // exactOptionalPropertyTypes wants.
      const etag = typeof record.etag === 'string' ? record.etag : undefined;
      return { bundle, fetchedAtMs, ...(etag === undefined ? {} : { etag }) };
    } catch {
      // Fail-open: an unreadable or corrupt cache behaves like no cache
      return null;
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
    const stored: StoredPolicyBundle = {
      bundle,
      fetchedAtMs: Date.now(),
      ...(etag === undefined ? {} : { etag }),
    };
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
      await writeFile(tmp, JSON.stringify(stored), {
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

  return { read, write, file };
}

export type PolicyStore = ReturnType<typeof createPolicyStore>;
