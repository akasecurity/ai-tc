import { createHash, randomUUID } from 'node:crypto';
import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { ActionTaken, InstalledPackInput, UsedByItem } from '@akasecurity/schema';
import {
  BuiltinPolicyId,
  DEFAULT_PACK_POLICY_ID,
  KNOWN_BUILTIN_IDS,
  policyIdIsReversible,
  policyIdToAction,
  Rule,
} from '@akasecurity/schema';

import { safeJson } from '../internal/json.ts';
import { allRows, boolToInt, countBy, getRow, intToBool } from '../internal/rows.ts';
import { withTransaction } from '../internal/transactions.ts';
import type { FloorRule, PackPolicyFloor } from '../policy-floor.ts';
import {
  controlPlanePolicyFloor,
  policyAssignmentRefusal,
  PolicyFloorError,
} from '../policy-floor.ts';
import type { InstalledPacksReadPort } from '../ports.ts';
import { compareBinaryVersions, isParseableBinaryVersion } from '../semver.ts';
import { parseRules } from './detections.ts';

// The built-in policy id an installed pack with no explicit policy_id falls
// under, for the "governed" count coalescing below. There is no policy_id
// backfill, so unassigned packs stay NULL; the Detections views render them
// tagged with dashboard-ui's PLACEHOLDER_POLICY ('monitor'). Coalescing to the
// same id (the shared DEFAULT_PACK_POLICY_ID) keeps the Policies "governed"
// counts consistent with what Detections shows for the very same packs.
const DEFAULT_POLICY_ID = DEFAULT_PACK_POLICY_ID;

// pack policy_id → enforcement action is the shared @akasecurity/schema mapping
// (policyIdToAction), so read surfaces can never drift on how a per-pack
// Monitor/Warn/Redact/Block choice resolves. NULL/unknown → monitor/log.

// Inventory rollup for the Detections page stat tiles: total detections, the
// snapshotted rules across them, and how many are enabled (active).
export interface InstalledPackCounts {
  packs: number;
  rules: number;
  enabled: number;
}

// The failure half of `Rule.safeParse`, derived from the schema rather than
// imported: this package depends on `@akasecurity/schema`, not on zod.
type RuleParseError = Extract<ReturnType<typeof Rule.safeParse>, { success: false }>['error'];

// The entry's own `id`, but only when it satisfies the schema's own id pattern.
// Asking `Rule.shape.id` rather than restating that regex keeps the check from
// drifting away from the rule it mirrors.
function printableRuleId(entry: unknown): string | null {
  if (typeof entry !== 'object' || entry === null) return null;
  const candidate: unknown = (entry as { id?: unknown }).id;
  return Rule.shape.id.safeParse(candidate).success ? (candidate as string) : null;
}

// `<dotted path>: <issue code>` for the first issue — path and code only. An
// issue with no path (the entry was the wrong shape entirely) reports the code
// alone.
//
// NOT `issue.message`. Most messages describe the expectation rather than the
// input ("expected one of ..."), but the commonest rejection here does the
// opposite: an unrecognized key reports `Unrecognized key: "<the key>"`, quoting
// a name straight out of an entry that never passed validation. Path and code
// are schema-side and cannot carry any of the entry's own bytes.
function firstIssueReason(error: RuleParseError): string {
  const issue = error.issues[0];
  if (!issue) return 'unknown';
  const path = issue.path.map((segment) => String(segment)).join('.');
  return path ? `${path}: ${issue.code}` : issue.code;
}

// How many rejected rules `rejectedRules` describes before it stops growing.
// One corrupt pack can hold thousands of entries; the list feeds an operator
// notice, so it is a sample rather than a ledger. `invalidRules` stays exact.
export const REJECTED_RULE_DETAIL_CAP = 10;

// Why one rule under an enabled pack was rejected, in terms safe to print.
export interface RejectedRule {
  // `namespace/packId` of the pack the entry came from.
  pack: string;
  // The entry's own `id`, and ONLY when it satisfies the schema's own id
  // pattern — that alphabet (lowercase, digits, hyphen, one slash) cannot carry
  // a secret. Anything else, including a missing or non-string id, reports null
  // rather than echoing unvalidated input.
  ruleId: string | null;
  // Dotted schema path plus the Zod issue code, e.g. `postValidators.0:
  // invalid_union`. Built from `issue.path` and `issue.code` ALONE — see
  // firstIssueReason on why the human-readable message is not usable here.
  reason: string;
}

// The scan-time view of the installed inventory: every valid rule from every
// ENABLED pack, plus the row counts the caller's fail-open ladder needs to tell
// "empty/foreign store" (fall back to bundled rules) apart from "the user
// disabled everything" (respect the empty set).
export interface InstalledRuleset {
  installedPacks: number;
  enabledPacks: number;
  rules: Rule[];
  // Rules under enabled packs that failed Rule validation (foreign/corrupt
  // rows). All-invalid ⇒ the caller treats the snapshot as unusable.
  invalidRules: number;
  // Identifying detail for the first REJECTED_RULE_DETAIL_CAP of those, in
  // encounter order. Rejecting ONE rule costs the caller the whole snapshot, so
  // without this a user loses every custom rule and every per-detection
  // enforcement action with nothing naming the entry responsible. May be
  // shorter than `invalidRules`; never longer.
  rejectedRules: RejectedRule[];
  // Per valid rule (by id): the enforcement action its pack's assigned policy
  // resolves to (see policyIdToAction). The standalone gateway turns these into
  // ruleId-targeted policies so a detection's Monitor/Warn/Redact/Block choice
  // actually drives enforcement instead of being overridden by the seeded
  // per-category defaults. Only ids present in `rules` appear here.
  ruleActions: Map<string, ActionTaken>;
  // The rule ids whose pack is assigned a REVERSIBLE archetype (Redact & Vault)
  // — see policyIdIsReversible. A second axis over the same action rather than a
  // second action: every id in here also carries `redact` in ruleActions, and
  // what differs is whether the stripped value is kept recoverably or destroyed.
  //
  // A SET rather than a per-rule map because reversibility is only ever asked of
  // rules that are already being redacted, and absence is the whole answer for
  // the rest. Only ids present in `rules` appear here.
  reversibleRules: Set<string>;
  // Per valid rule (by id): the version of the installed pack it came from. The
  // standalone gateway carries this onto the policy bundle so a captured
  // finding is stamped with the pack's real version instead of the rule file
  // format constant. Only ids present in `rules` appear here.
  ruleVersions: Map<string, string>;
}

// A cheap order-independent fingerprint of an inventory: one
// `ns/pack@version#<rules-hash>` token per pack, sorted. Equal signatures ⇒
// nothing to record, so recordInventory skips the transaction entirely. The
// hash of the pack's serialized rules is folded in (not just the version) so a
// rules-only change with no version bump still flips the signature — a
// version-only signature would silently keep a stale snapshot on disk.
function inventorySignature(
  packs: { namespace: string; packId: string; version: string; rulesJson: string }[],
): string {
  return packs
    .map((p) => `${p.namespace}/${p.packId}@${p.version}#${hashRules(p.rulesJson)}`)
    .sort()
    .join(',');
}

// Content fingerprint of a pack's serialized rules, for change detection only —
// this is not a security boundary, and nothing authenticates anything with it.
//
// sha256 rather than sha1 anyway. The weakness sha1 has is irrelevant to
// comparing a value against itself, but reaching for it generates a standing
// static-analysis finding on a line nobody is going to revisit, and the cost of
// not doing so is nil: the signature is recomputed on BOTH sides of every
// comparison (see storedSignature) and never persisted, so the algorithm can
// change without migrating a single store.
function hashRules(rulesJson: string): string {
  return createHash('sha256').update(rulesJson).digest('hex');
}

// Parse a plain "major.minor.patch" pack version to a numeric triplet, or null
// when it isn't semver-shaped ('2.0', 'v2.0.0', '', 'latest', …).
function parseVersion(v: string): [number, number, number] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(v);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

// The mirror's downgrade guard: would writing `incoming` over `stored` REDUCE
// the recorded inventory? The plugin and CLI are separately-installed binaries
// sharing one store, so version skew is normal — an OLDER binary must never
// rewrite the mirror to a weaker snapshot, or `applyUpdate` would present that
// downgrade as an update. Coverage-monotonic at a fixed version: equal versions
// only advance when the incoming rule-id set is a SUPERSET (adds coverage),
// never when it drops or diverges. Fails CLOSED on an unparsable INCOMING
// version (refuse the rewrite — a downgrade guard must distrust exactly the
// malformed input it exists to catch), while still letting a valid incoming
// replace an unparsable STORED row so a bad row can heal.
function isMirrorDowngrade(
  incoming: { version: string; ruleIds: Set<string> },
  stored: { version: string; ruleIds: Set<string> },
): boolean {
  const a = parseVersion(incoming.version);
  if (a === null) return true; // distrust unparsable incoming — fail closed
  const b = parseVersion(stored.version);
  if (b === null) return false; // stored is malformed → let the valid incoming heal it
  for (let i = 0; i < 3; i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    if (ai !== bi) return ai < bi; // strictly older → downgrade; strictly newer → ok
  }
  // Equal version: a downgrade UNLESS incoming covers every stored rule id.
  for (const id of stored.ruleIds) if (!incoming.ruleIds.has(id)) return true;
  return false;
}

// Rule ids present in a serialized rules_json (tolerant — a malformed blob or a
// rule without a string id simply contributes no ids to the coverage set).
function ruleIdsOf(rulesJson: string): Set<string> {
  const ids = new Set<string>();
  const raw = safeJson<unknown>(rulesJson, []);
  if (!Array.isArray(raw)) return ids;
  for (const entry of raw) {
    if (entry && typeof entry === 'object') {
      const id = (entry as { id?: unknown }).id;
      if (typeof id === 'string') ids.add(id);
    }
  }
  return ids;
}

/**
 * installed_packs + available_packs writer/reader, bound to one open DB.
 *
 * Two tables, one invariant: **`installed_packs` is user state; the seeding
 * path never mutates an existing row.**
 *
 * WRITE-GATE FOOTGUN (migration 0006): a database trigger silently ignores —
 * `changes = 0`, NO error — every UPDATE of installed_packs
 * version/name/rules_json while the `_pack_write_gate` row is closed. Silence
 * is required (already-shipped legacy binaries run a compiled-in upsert on the
 * hook path; an error would break the user's session), but it cuts both ways:
 * a FUTURE writer that legitimately needs to move those columns will see its
 * UPDATE vanish without a trace. Any such writer must go through applyUpdate —
 * the only code that opens the gate, inside its own transaction. Do not write
 * those columns from anywhere else; the legacy-writers suite pins this.
 *
 * - `available_packs` mirrors the detection inventory the currently running
 *   plugin/CLI binary ships — refreshed on every recordInventory (gateway open
 *   / `aka init`). Comparing it against installed_packs is how the dashboards
 *   and CLI compute "update available".
 * - `installed_packs` is the user's ACTIVE snapshot — what the runtime scans
 *   with. recordInventory only INSERTs packs that are missing entirely (new
 *   packs auto-install under the monitor-by-default posture); version/rule
 *   changes to packs the user already has are applied exclusively through
 *   `applyUpdate` (the manual update flow in the web-ui / `aka detections
 *   update` / the plugin command).
 *
 * The plugin owns these tables (the gateway records on open).
 */
export class SqliteInstalledPacksRepository implements InstalledPacksReadPort {
  private readonly insertMissingStmt: StatementSync;
  private readonly upsertAvailableStmt: StatementSync;
  private readonly signatureStmt: StatementSync;

  /**
   * `baseDir` is the `~/.aka` LAYOUT BASE, not the data dir — the control-plane
   * floor needs both halves of it (settings/ says whether this machine is
   * attached, data/ holds the cached bundle). It is optional because a caller
   * holding only a DatabaseSync — every test construction site, and any embedder
   * that opens the store itself — has no layout to point at, and such a caller
   * gets the pre-existing behaviour: no floor, no lock. Production threads it in
   * from `openLocalDatabase`, which is the single construction site that owns a
   * real `~/.aka`.
   */
  constructor(
    private readonly db: DatabaseSync,
    private readonly baseDir?: string,
  ) {
    // Install-if-absent: a pack the user already has (by (namespace, packId)) is
    // NEVER touched here — not its version, rules, enabled state, or policy.
    // Updates to existing packs are manual (applyUpdate).
    this.insertMissingStmt = db.prepare(
      `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
       VALUES (:id, :namespace, :packId, :version, :name, :rulesJson, 1, :now, :now)
       ON CONFLICT (namespace, pack_id) DO NOTHING`,
    );
    // The available mirror always reflects the running binary; the WHERE keeps
    // an unchanged row a no-op so steady-state re-records rewrite nothing.
    // recorded_by is deliberately NOT in the change-detection WHERE: it names
    // the binary that last CHANGED the mirror content, so a different binary
    // re-recording identical content stays a no-op rather than churning the row.
    this.upsertAvailableStmt = db.prepare(
      `INSERT INTO available_packs (id, namespace, pack_id, version, name, rules_json, recorded_by, updated_at)
       VALUES (:id, :namespace, :packId, :version, :name, :rulesJson, :recordedBy, :now)
       ON CONFLICT (namespace, pack_id) DO UPDATE SET
         version = excluded.version,
         name = excluded.name,
         rules_json = excluded.rules_json,
         recorded_by = excluded.recorded_by,
         updated_at = excluded.updated_at
       WHERE available_packs.version <> excluded.version
          OR available_packs.name <> excluded.name
          OR available_packs.rules_json <> excluded.rules_json`,
    );
    this.signatureStmt = db.prepare(
      `SELECT namespace, pack_id AS packId, version, rules_json AS rulesJson FROM available_packs`,
    );
  }

  /**
   * Record the running binary's detection inventory. Refreshes the
   * available_packs mirror (pruning packs the binary no longer ships) and
   * installs packs the user doesn't have yet — it never modifies an existing
   * installed row (updates are manual; see applyUpdate). Fail-open: this runs
   * on the hook path, so any error is swallowed.
   *
   * Downgrade guard: the plugin and CLI are separately-installed binaries
   * sharing one store, so version skew is a normal state. A mirror row is
   * never rewritten to an OLDER (or, at an equal version, a non-superset) pack
   * snapshot — otherwise an outdated binary would re-arm "update available"
   * pointing at weaker rules and the manual update flow would present a
   * protection DOWNGRADE as an update. The guard read and the writes run under
   * one BEGIN IMMEDIATE write lock so a concurrent writer can't slip a newer
   * version between the read and the write (TOCTOU).
   *
   * `meta.recordedBy` names the recording binary (`plugin@<v>` /
   * `aka-cli@<v>`) and is stamped onto mirror rows this call actually changes.
   * Optional — callers that can't know their version (old writers, most plugin
   * hooks) simply leave it null.
   */
  recordInventory(packs: InstalledPackInput[], meta?: { recordedBy?: string }): void {
    if (packs.length === 0) return;
    try {
      // Serialize each pack's rules ONCE here, then reuse the string for both the
      // change-detection signature and the writes below. This runs on every
      // gateway open (every hook): the signature gate — against the AVAILABLE
      // mirror, which tracks the binary — skips the transaction entirely in the
      // steady state; the write runs only when the binary's inventory changed (a
      // plugin upgrade). The signature read sits INSIDE the try so a locked or
      // foreign store drops the bookkeeping instead of escaping into gateway
      // resolution (and taking detection with it) on the hook path. It is a
      // lock-free fast path only — the authoritative downgrade decision is
      // re-read under the write lock below, so a race here at worst costs an
      // extra transaction, never a wrong write.
      const rows = packs.map((pack) => ({
        namespace: pack.namespace,
        packId: pack.packId,
        version: pack.version,
        name: pack.name,
        rulesJson: JSON.stringify(pack.rules),
        ruleIds: new Set(pack.rules.map((r) => r.id)),
      }));
      if (this.storedSignature() === inventorySignature(rows)) return;

      const now = Date.now();
      // BEGIN IMMEDIATE takes the write lock up front, so mirrorState() reads
      // the same snapshot the writes commit against — the guard can't act on a
      // stale mirror another process has already advanced.
      withTransaction(
        this.db,
        () => {
          const mirror = this.mirrorState();
          let behind = false;
          for (const row of rows) {
            const params = {
              id: randomUUID(),
              namespace: row.namespace,
              packId: row.packId,
              version: row.version,
              name: row.name,
              rulesJson: row.rulesJson,
              now,
            };
            const stored = mirror.get(`${row.namespace}/${row.packId}`);
            // Refresh the mirror only when this binary's snapshot is not a
            // downgrade of what's recorded. A missing row is always written (new
            // pack); an older/narrower one is left as-is. Either way the pack is
            // still install-if-absent below (additive), and a newer binary flags
            // the update later.
            if (stored === undefined || !isMirrorDowngrade(row, stored)) {
              this.upsertAvailableStmt.run({
                ...params,
                id: randomUUID(),
                recordedBy: meta?.recordedBy ?? null,
              });
            } else {
              behind = true;
            }
            this.insertMissingStmt.run(params);
          }
          // Prune available rows for packs this binary no longer ships — a stale
          // mirror row would otherwise keep offering a bogus "update". Skipped
          // when this binary is BEHIND the mirror anywhere: an older binary's
          // narrower inventory must not delete the newer binary's records.
          if (!behind) this.pruneAvailable(rows.map((r) => `${r.namespace}/${r.packId}`));
        },
        'IMMEDIATE',
      );
    } catch {
      // Fail-open: dropping inventory bookkeeping never breaks a session. BEGIN
      // stays inside the try (mirrors recordCapture) so a failed BEGIN/ROLLBACK
      // can't escape into gateway resolution and skip detection for the hook.
    }
  }

  // The mirror's current (namespace/packId → {version, ruleIds}) map — the
  // input to the downgrade guard. Read INSIDE the write transaction.
  private mirrorState(): Map<string, { version: string; ruleIds: Set<string> }> {
    const rows = allRows<{ namespace: string; packId: string; version: string; rulesJson: string }>(
      this.db.prepare(
        `SELECT namespace, pack_id AS packId, version, rules_json AS rulesJson FROM available_packs`,
      ),
    );
    return new Map(
      rows.map((r) => [
        `${r.namespace}/${r.packId}`,
        { version: r.version, ruleIds: ruleIdsOf(r.rulesJson) },
      ]),
    );
  }

  // Delete available_packs rows whose (namespace, packId) is not in `keep`
  // (keys joined with '/', matching the detection id slug encoding — packId may
  // itself contain '/', but namespace may not, so the join is unambiguous).
  private pruneAvailable(keep: string[]): void {
    const rows = allRows<{ namespace: string; packId: string }>(
      this.db.prepare(`SELECT namespace, pack_id AS packId FROM available_packs`),
    );
    const keepSet = new Set(keep);
    const del = this.db.prepare(`DELETE FROM available_packs WHERE namespace = ? AND pack_id = ?`);
    for (const r of rows) {
      if (!keepSet.has(`${r.namespace}/${r.packId}`)) del.run(r.namespace, r.packId);
    }
  }

  /**
   * Manually apply the available (binary-shipped) snapshot to one installed
   * pack: copies version/name/rules_json from available_packs, PRESERVING the
   * user's enabled state, policy assignment, and created_at. Returns false when
   * the pack isn't installed or has no available counterpart. Not on the hook
   * path — errors surface to the caller (mirrors setPolicy/setEnabled).
   *
   * This is the ONLY writer that opens the `_pack_write_gate` — the migration
   * 0006 trigger silently ignores every other UPDATE of
   * version/name/rules_json on installed_packs, which is what stops
   * already-shipped legacy binaries (≤alpha.5 hooks run a compiled-in
   * auto-sync upsert) from clobbering an applied update. The gate flips INSIDE
   * the transaction: a ROLLBACK — error or crash mid-txn — reverts it, so the
   * gate can never be left open; and BEGIN IMMEDIATE holds the single write
   * lock, so no other process can slip an UPDATE in while it is open.
   */
  applyUpdate(namespace: string, packId: string): boolean {
    // Owns its transaction — composing it into a caller's open transaction
    // would break the gate contract (the caller's COMMIT/ROLLBACK, not ours,
    // would decide when the gate closes). Assert the precondition explicitly
    // so a future composed caller gets a contract error, not SQLite's opaque
    // nested-BEGIN throw.
    if (this.db.isTransaction) {
      throw new Error('applyUpdate must not be called inside an open transaction');
    }
    let changed = false;
    withTransaction(
      this.db,
      () => {
        this.db.exec('UPDATE _pack_write_gate SET open = 1 WHERE id = 1');
        const res = this.db
          .prepare(
            `UPDATE installed_packs SET
             version = (SELECT a.version FROM available_packs a
                        WHERE a.namespace = :namespace AND a.pack_id = :packId),
             name = (SELECT a.name FROM available_packs a
                     WHERE a.namespace = :namespace AND a.pack_id = :packId),
             rules_json = (SELECT a.rules_json FROM available_packs a
                           WHERE a.namespace = :namespace AND a.pack_id = :packId),
             updated_at = :now
           WHERE namespace = :namespace AND pack_id = :packId
             AND EXISTS (SELECT 1 FROM available_packs a
                         WHERE a.namespace = :namespace AND a.pack_id = :packId)`,
          )
          .run({ namespace, packId, now: Date.now() });
        this.db.exec('UPDATE _pack_write_gate SET open = 0 WHERE id = 1');
        changed = Number(res.changes) > 0;
      },
      'IMMEDIATE',
    );
    return changed;
  }

  /**
   * The scan-time ruleset: every rule under an ENABLED installed pack that
   * passes Rule validation (foreign/corrupt entries are counted, not thrown —
   * the caller's fail-open ladder decides what an unusable snapshot means).
   * Strict parsing here — deliberately NOT the display-tolerant parseRules,
   * which silently returns [] for malformed JSON / non-array payloads: at scan
   * time that silence would make a corrupt store indistinguishable from a
   * legitimately empty one, and the ladder would authorize an EMPTY ruleset
   * (all detection off) instead of falling back to the bundled packs. Every
   * JSON-level failure therefore counts as invalid.
   */
  /**
   * ORDERED, because a rule id is unique only WITHIN a pack — the sole unique
   * index is (namespace, pack_id) — so two enabled packs may contribute the same
   * id, and the per-rule maps below are last-write-wins. Without an ORDER BY the
   * winner is whatever order SQLite happens to return, which makes a collision
   * resolve differently on two machines holding identical stores. Ordering by
   * (namespace, pack_id) makes the loser deterministic and therefore testable.
   */
  installedRuleset(): InstalledRuleset {
    const rows = allRows<{
      enabled: number;
      policyId: string | null;
      rulesJson: string;
      version: string;
      namespace: string;
      packId: string;
    }>(
      this.db.prepare(
        `SELECT enabled, policy_id AS policyId, rules_json AS rulesJson, version,
                namespace, pack_id AS packId
           FROM installed_packs
          ORDER BY namespace, pack_id`,
      ),
    );

    const out: InstalledRuleset = {
      installedPacks: rows.length,
      enabledPacks: 0,
      rules: [],
      invalidRules: 0,
      rejectedRules: [],
      ruleActions: new Map(),
      ruleVersions: new Map(),
      reversibleRules: new Set(),
    };
    // Records a rejection without ever copying the entry's own bytes. Callers
    // still bump `invalidRules` themselves — that count is exact, this list is
    // capped.
    const reject = (pack: string, ruleId: string | null, reason: string): void => {
      if (out.rejectedRules.length >= REJECTED_RULE_DETAIL_CAP) return;
      out.rejectedRules.push({ pack, ruleId, reason });
    };
    for (const row of rows) {
      if (!intToBool(row.enabled)) continue;
      out.enabledPacks += 1;
      // The whole pack shares one policy; each of its valid rules inherits it —
      // both the action it resolves to and whether that action is reversible.
      const action = policyIdToAction(row.policyId);
      const reversible = policyIdIsReversible(row.policyId);
      const pack = `${row.namespace}/${row.packId}`;
      let raw: unknown;
      try {
        raw = JSON.parse(row.rulesJson);
      } catch {
        out.invalidRules += 1; // whole pack unusable (malformed JSON)
        reject(pack, null, 'rules_json: malformed JSON');
        continue;
      }
      if (!Array.isArray(raw)) {
        out.invalidRules += 1; // whole pack unusable (not a rule array)
        reject(pack, null, 'rules_json: not an array');
        continue;
      }
      for (const entry of raw) {
        const parsed = Rule.safeParse(entry);
        if (parsed.success) {
          out.rules.push(parsed.data);
          out.ruleActions.set(parsed.data.id, action);
          out.ruleVersions.set(parsed.data.id, row.version);
          // Symmetric with ruleActions above, which is a Map and therefore
          // last-write-wins. Nothing makes a rule id unique ACROSS packs — the
          // only unique index is (namespace, packId) — so two enabled packs can
          // contribute the same id, and an add-only Set would keep the first
          // pack's reversibility after a later pack's plain-Redact assignment
          // had already won the action. That combination (action 'redact',
          // reversible true) never occurs for a singly-owned rule, and it
          // vaults a value the winning policy said to destroy.
          if (reversible) out.reversibleRules.add(parsed.data.id);
          else out.reversibleRules.delete(parsed.data.id);
        } else {
          out.invalidRules += 1;
          reject(pack, printableRuleId(entry), firstIssueReason(parsed.error));
        }
      }
    }
    return out;
  }

  /**
   * The newest binary that ever changed the available mirror, parsed from the
   * `recorded_by` stamps (`<binary>@<version>`). Powers the stale-session
   * notice: a session whose plugin is older than this learns a newer binary
   * is on the machine. Null when nothing parseable was recorded (pre-hardening
   * stores) — the notice simply stays silent. Stamps are skipped when the
   * `<binary>@<version>` structure is malformed OR the version doesn't parse:
   * an unparseable version compares equal to every other, so keeping one as the
   * running max would mask a genuinely-newer parseable stamp.
   */
  newestRecordedBinary(): { binary: string; version: string } | null {
    const rows = allRows<{ recordedBy: string }>(
      this.db.prepare(
        `SELECT DISTINCT recorded_by AS recordedBy FROM available_packs WHERE recorded_by IS NOT NULL`,
      ),
    );
    let newest: { binary: string; version: string } | null = null;
    for (const row of rows) {
      const at = row.recordedBy.lastIndexOf('@');
      if (at <= 0 || at === row.recordedBy.length - 1) continue; // malformed structure
      const binary = row.recordedBy.slice(0, at);
      const version = row.recordedBy.slice(at + 1);
      if (!isParseableBinaryVersion(version)) continue; // unparseable version → skip
      if (newest === null || compareBinaryVersions(version, newest.version) > 0) {
        newest = { binary, version };
      }
    }
    return newest;
  }

  counts(): Promise<InstalledPackCounts> {
    const row = getRow<InstalledPackCounts>(
      this.db.prepare(
        `SELECT count(*) AS packs,
                coalesce(sum(json_array_length(rules_json)), 0) AS rules,
                coalesce(sum(enabled), 0) AS enabled
         FROM installed_packs`,
      ),
    );
    return Promise.resolve(row ?? { packs: 0, rules: 0, enabled: 0 });
  }

  // ─── Policy-catalog reads ────────────────────────────────────────────────────
  // Back the Policies page's built-in catalog: how many
  // detections a built-in policy governs, and which ones.

  /**
   * Detection counts keyed by their effective built-in policy id — one
   * `GROUP BY` scan the Policies page shares for both its list (per-id
   * usedByCount) and its stats (total governed), instead of a COUNT per id.
   * NULL policy_id coalesces to DEFAULT_POLICY_ID so unassigned packs are
   * attributed to Monitor, matching the Detections views.
   */
  countsByPolicyId(): Map<string, number> {
    return countBy(
      this.db,
      `SELECT coalesce(policy_id, '${DEFAULT_POLICY_ID}') AS k, count(*) AS n
         FROM installed_packs
         GROUP BY k`,
    );
  }

  /** The detections governed by a built-in policy — one UsedByItem per pack. */
  listByPolicyId(policyId: string): UsedByItem[] {
    // Coalesce so the Monitor detail lists the same NULL-policy packs its count
    // includes (and the Detections views tag as Monitor).
    const rows = allRows<{
      namespace: string;
      packId: string;
      name: string;
      enabled: number;
      rulesJson: string;
    }>(
      this.db.prepare(
        `SELECT namespace, pack_id AS packId, name, enabled, rules_json AS rulesJson
         FROM installed_packs
         WHERE coalesce(policy_id, '${DEFAULT_POLICY_ID}') = ?
         ORDER BY name ASC`,
      ),
      [policyId],
    );
    return rows.map((r) => ({
      id: `${r.namespace}/${r.packId}`,
      name: r.name,
      ruleCount: parseRules(r.rulesJson).length,
      enabled: intToBool(r.enabled),
    }));
  }

  // ─── Writes ────────────────────────────────────────────────────────────────
  // User-driven edits from the OSS Detections page (via a Next.js Server Action),
  // NOT on the hook path — so, unlike recordInventory, these surface errors to the
  // caller rather than swallowing them. Each returns whether a row matched, so the
  // caller can tell an edit from a no-such-detection.

  /**
   * The rules one installed pack owns, reduced to what a floor computation
   * reads. Display-tolerant parsing on purpose: a pack whose snapshot is
   * unreadable contributes no rules to a scan either, so it is not a detection
   * the control plane can be governing, and an empty list correctly imposes no
   * floor. Enabled state is deliberately not filtered — a disabled pack is one
   * the user can re-enable, and its assignment stays governed meanwhile.
   */
  private packFloorRules(namespace: string, packId: string): FloorRule[] {
    const row = getRow<{ rulesJson: string }>(
      this.db.prepare(
        `SELECT rules_json AS rulesJson FROM installed_packs
          WHERE namespace = ? AND pack_id = ?`,
      ),
      [namespace, packId],
    );
    if (!row) return [];
    return parseRules(row.rulesJson).map((rule) => ({ id: rule.id, category: rule.category }));
  }

  /**
   * What the connected control plane imposes on one installed pack, or null on a
   * machine that is its own authority (standalone, no cached bundle, or a
   * repository constructed without a layout base).
   *
   * Exposed as a READ so a surface can render the constraint — grey out the
   * choices below the floor, mark a locked detection as locked — rather than
   * offer the user a picker whose selections it will then be told it may not
   * make. The refusal in `setPolicy` does not depend on any surface calling this.
   */
  policyFloor(namespace: string, packId: string): PackPolicyFloor | null {
    if (this.baseDir === undefined) return null;
    return controlPlanePolicyFloor(this.packFloorRules(namespace, packId), this.baseDir);
  }

  /**
   * Assign (or clear, with null) the enforcement policy for one installed pack.
   * `policyId` must be a known built-in id (monitor/warn/redact/block/vault).
   *
   * On an ATTACHED machine the organization's bundle is a floor this refuses to
   * write below, and a detection the organization has authored a policy for is
   * refused outright — see policy-floor.ts for both, and for why the refusal is
   * a throw rather than a silently substituted value. This is the one device-local
   * write path for the assignment, so the check belongs here rather than on any
   * surface that offers the choice.
   */
  setPolicy(namespace: string, packId: string, policyId: string | null): boolean {
    // Validate against the schema's canonical built-in enum — the single
    // source every policy-assignment surface validates against.
    if (policyId !== null && !BuiltinPolicyId.safeParse(policyId).success) {
      throw new Error(
        `Unknown policy '${policyId}'. Must be one of: ${KNOWN_BUILTIN_IDS.join(', ')}.`,
      );
    }
    // Past the enum check, so the cast reflects what was just proven.
    const requested = policyId as BuiltinPolicyId | null;
    const floor = this.policyFloor(namespace, packId);
    if (floor !== null) {
      const refusal = policyAssignmentRefusal(requested, floor);
      if (refusal !== null) {
        throw new PolicyFloorError(`${namespace}/${packId}`, requested, floor.floor, refusal);
      }
    }
    const res = this.db
      .prepare(
        `UPDATE installed_packs SET policy_id = :policyId, updated_at = :now
         WHERE namespace = :namespace AND pack_id = :packId`,
      )
      .run({ policyId, now: Date.now(), namespace, packId });
    return Number(res.changes) > 0;
  }

  /** Enable or disable one installed pack. */
  setEnabled(namespace: string, packId: string, enabled: boolean): boolean {
    const res = this.db
      .prepare(
        `UPDATE installed_packs SET enabled = :enabled, updated_at = :now
         WHERE namespace = :namespace AND pack_id = :packId`,
      )
      .run({ enabled: boolToInt(enabled), now: Date.now(), namespace, packId });
    return Number(res.changes) > 0;
  }

  // Fingerprint of the recorded available mirror — compared against the
  // incoming inventory's signature to skip the write entirely when the running
  // binary's inventory hasn't changed since the last record.
  private storedSignature(): string {
    const rows = allRows<{
      namespace: string;
      packId: string;
      version: string;
      rulesJson: string;
    }>(this.signatureStmt);
    return inventorySignature(rows);
  }
}
