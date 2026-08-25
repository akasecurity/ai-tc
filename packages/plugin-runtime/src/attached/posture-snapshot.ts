// Read-only posture readout of a local ~/.aka/data/aka.db.
//
// Deliberately NOT openLocalDatabase(): that opener creates the file if absent,
// applies migrations, and seeds defaults — a posture reader must report the
// store AS FOUND (including its absence) and must never mutate what it
// measures. The findings join below mirrors the canonical read in OSS
// persistence (repositories/findings.ts, CAPTURE_EVENT_TYPES) — keep in sync.
//
// What creates the store this reads: the OSS surfaces — standalone plugin
// sessions (StandaloneDataGateway's openLocalDatabase), the aka CLI, and the
// OSS web-ui. The ATTACHED gateway never opens or creates it; attached
// sessions ingest events straight to the control plane. On a machine that has only
// ever run attached, no ~/.aka/data/aka.db exists and every snapshot honestly
// reports storePresent:false — a measurement, not a defect (see the factory
// for the deployment consequences).
import { statSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

import type { StorePosturePack, StorePosturePolicyCounts } from '@akasecurity/schema';

import { emptyActionCounts, isActionTaken } from './action-counts.ts';

const CAPTURE_EVENT_TYPES_SQL = `('prompt','response','code_change','tool_use')`;

export interface StoreReadout {
  storePresent: boolean;
  schemaVersion: number | null;
  findingsTotal: number;
  findingsFirstAt: number | null;
  findingsLastAt: number | null;
  packs: StorePosturePack[];
  policyCounts: StorePosturePolicyCounts;
  /**
   * True when the store could not be MEASURED — locked by a concurrent writer,
   * permission-denied (on the file, or on any parent directory, which makes
   * even "does it exist" unanswerable), corrupt, or WAL/-shm unavailable (the
   * OSS store runs `PRAGMA journal_mode = WAL`, and SQLite cannot open a WAL
   * database read-only when the -shm can't be attached).
   *
   * Every other field is then the absent-store LITERAL below — fabricated, not
   * measured — so this flag is the caller's signal to report nothing at all.
   * Reporting the literal instead would tell the control plane a healthy device has
   * no store, no packs and no policies; the plugin cannot tell "gone" from
   * "unreadable", so it declines to assert either.
   *
   * NOT set for two states that ARE measurements:
   *  - a genuinely missing file — the event this feature exists to catch;
   *  - a valid store carrying no aka schema (pre-migration, or a wiped data dir
   *    recreated empty). That reports storePresent with zero coverage, which is
   *    what was actually observed. Folding it in here suppressed the report and
   *    turned wipe-then-recreate into silence until the 72h freshness grader.
   */
  readError: boolean;
}

/**
 * Distinguishes "this store has no aka schema" from "this store is unreadable".
 *
 * Deliberately keyed on the error rather than on which phase threw. SQLite opens
 * LAZILY: a file of shredded bytes passes `new DatabaseSync(...)` and only fails
 * on the first statement, exactly as a missing table does. Splitting on open-vs-
 * query would therefore classify a corrupt store as empty-but-healthy and report
 * a fabricated storePresent:true — the same false measurement in the opposite
 * direction. Only "no such table" means the file is a sound database that simply
 * has not been migrated; SQLITE_BUSY, "file is not a database", and I/O errors
 * all stay read failures.
 */
function isSchemaAbsent(err: unknown): boolean {
  return err instanceof Error && /no such table/i.test(err.message);
}

function emptyReadout(readError = false): StoreReadout {
  const byAction = emptyActionCounts();
  return {
    storePresent: false,
    schemaVersion: null,
    findingsTotal: 0,
    findingsFirstAt: null,
    findingsLastAt: null,
    packs: [],
    policyCounts: { total: 0, disabled: 0, byAction },
    readError,
  };
}

export function readStorePosture(dbPath: string): StoreReadout {
  // statSync, NOT existsSync. existsSync answers false for ANY failure to look,
  // not just absence — a permission-denied parent directory, an unmounted or
  // still-locked encrypted home, macOS full-disk-access blocking the path. All
  // of those are "could not measure", and reporting them as a genuinely absent
  // store fed the control plane the absent-store literal with readError unset: two
  // such reports spanning the absence grace window stamped a sticky false
  // regression on a machine whose store is intact. Only ENOENT (no such file)
  // and ENOTDIR (a path component is not a directory — the data dir itself was
  // replaced by a file, so no store can exist at this path) are measurements of
  // absence; every other failure to stat is a readError.
  try {
    statSync(dbPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return emptyReadout();
    return emptyReadout(true);
  }
  let db: DatabaseSync | null = null;
  // Hoisted — along with packs/policyCounts/findings* below — so the
  // schema-absent branch can still report what it managed to measure BEFORE
  // the throw, instead of discarding it. Each SQL statement below can
  // independently hit "no such table" for its OWN missing table (a store can
  // be mid-migration with some tables present and others not), and only ONE
  // shared try/catch wraps all of them — without hoisting, a device with 12
  // packs and 40 policies but a not-yet-created inspection_findings table
  // reported 0 packs / 0 policies (both already measured, both discarded),
  // and a device with a 500-finding baseline losing only its policies table
  // reported findingsTotal: 0, tripping isRegression's wipe alarm on a store
  // that was never touched past that one table. PRAGMA user_version answers
  // on any sound SQLite file, migrated or not, so a pre-migration store
  // reports its real (low) version rather than a null that reads like "we
  // learned nothing".
  let version: number | null = null;
  let packs: StorePosturePack[] = [];
  let policyCounts: StorePosturePolicyCounts = {
    total: 0,
    disabled: 0,
    byAction: emptyActionCounts(),
  };
  let findingsTotal = 0;
  let findingsFirstAt: number | null = null;
  let findingsLastAt: number | null = null;
  // Shared by the success path and the schema-absent catch branch below —
  // both report exactly what the hoisted variables hold at that point.
  const currentReadout = (): StoreReadout => ({
    storePresent: true,
    schemaVersion: version,
    findingsTotal,
    findingsFirstAt,
    findingsLastAt,
    packs,
    policyCounts,
    readError: false,
  });
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
    // readOnly blocks a journal_mode change, but busy_timeout is
    // connection-local state and settable here. Without it the default is 0,
    // and a concurrent writer holding the file — another hook mid-write, the
    // aka CLI, the web-ui — fails the first statement below with SQLITE_BUSY
    // instead of waiting out a brief write, turning a healthy store into a
    // readError suppression (and, on pre-gate builds, a false absent-store
    // report). Match the canonical opener's 2000ms
    // (oss/packages/persistence/src/database.ts, openWithPragmas). The wait is
    // part of the same non-preemptible blocking-read budget the aggregate-scan
    // note below describes. This narrows the failure to genuinely
    // longer-lived contention (and to WAL -shm attachment failures, which no
    // timeout fixes) — it does not eliminate it.
    db.exec('PRAGMA busy_timeout = 2000');
    version = (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
    // Each section below is independently guarded against "no such table" —
    // NOT one shared try around all three. A store can be mid-migration with
    // some tables present and others not (an attached-only machine never
    // migrates its store at all), and the three queries have a fixed order
    // (packs, then policies, then findings): a bare shared try/catch meant
    // ONE missing table — wherever it fell in that order — discarded every
    // section after it, including ones that would have succeeded. Hoisting
    // the variables alone does not fix this: it only preserves what ran
    // BEFORE the throw, not what would have run after it. A missing
    // policies table, for instance, must not block the findings query from
    // ever executing.
    try {
      const packRows = db
        .prepare(
          `SELECT namespace, pack_id, version, enabled, updated_at FROM installed_packs ORDER BY namespace, pack_id`,
        )
        .all() as {
        namespace: string;
        pack_id: string;
        version: string;
        enabled: number;
        updated_at: number | string | null;
      }[];
      packs = packRows.map((r) => ({
        packId: `${r.namespace}/${r.pack_id}`,
        version: r.version,
        enabled: r.enabled !== 0,
        updatedAt: r.updated_at == null ? null : String(r.updated_at),
      }));
    } catch (err) {
      if (!isSchemaAbsent(err)) throw err;
      // packs stays [] — the table genuinely doesn't exist yet, a measurement.
    }
    try {
      const policyRows = db.prepare(`SELECT action, enabled FROM policies`).all() as {
        action: string;
        enabled: number;
      }[];
      const byAction = emptyActionCounts();
      let disabled = 0;
      for (const row of policyRows) {
        if (row.enabled === 0) disabled += 1;
        // A row carrying an action this build does not know (an older or
        // newer store) still counts toward `total`, just not toward any bucket.
        if (isActionTaken(row.action)) byAction[row.action] += 1;
      }
      policyCounts = { total: policyRows.length, disabled, byAction };
    } catch (err) {
      if (!isSchemaAbsent(err)) throw err;
      // policyCounts stays the all-zero default — genuinely not there yet.
    }
    try {
      // Synchronous and non-preemptible: node:sqlite's .get() blocks the event
      // loop, so the attached gateway's withTimeout (a Promise.race against a
      // setTimeout) cannot interrupt it once it starts — the real backstop for
      // a pathologically large findings table is the harness's own 10s
      // SessionStart hook kill.
      //
      // Paid at most once per POSTURE_REPORT_INTERVAL_MS: createPostureReporter
      // checks the throttle before calling readStore(), and that throttle
      // advances on ATTEMPT. The distinction is the whole reason this bound
      // holds — while it advanced only on a successful send, an unreachable
      // control plane re-paid this scan on every SessionStart (measured 5 per 5
      // sessions inside one hour), which is precisely when you least want to
      // be spending 4s of a 10s budget.
      const agg = db
        .prepare(
          `SELECT count(*) AS n, min(f.first_detected_at) AS firstAt, max(f.first_detected_at) AS lastAt
             FROM inspection_findings f JOIN audit_events e ON e.id = f.audit_event_id
            WHERE e.event_type IN ${CAPTURE_EVENT_TYPES_SQL}`,
        )
        .get() as { n: number; firstAt: number | null; lastAt: number | null };
      findingsTotal = agg.n;
      findingsFirstAt = agg.firstAt;
      findingsLastAt = agg.lastAt;
    } catch (err) {
      if (!isSchemaAbsent(err)) throw err;
      // findings* stay at their zeroed defaults — genuinely not there yet.
    }
    return currentReadout();
  } catch {
    // Reaching the OUTER catch now means a real read failure — SQLITE_BUSY,
    // corruption, a WAL/-shm attachment failure, or `PRAGMA user_version`
    // itself failing (which would mean the file isn't a sound SQLite
    // database at all) — since each of the three table queries above
    // already handles its own "no such table" internally and re-throws
    // anything else. The file is THERE but we could not read it. Flagged
    // rather than reported as an absent store: the two are indistinguishable
    // in this readout, and scoring a locked-but-healthy store as absent is a
    // false wipe alarm on the control plane (see isRegression) plus a fabricated
    // "zero packs, zero policies" row that stands until the next hourly report.
    return emptyReadout(true);
  } finally {
    try {
      db?.close();
    } catch {
      /* already closed or never opened */
    }
  }
}
