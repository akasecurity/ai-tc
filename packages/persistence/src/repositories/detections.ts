import type { DatabaseSync } from 'node:sqlite';

import type {
  DetectionDetail,
  DetectionStats,
  DetectionSummaryInput,
  ListDetectionsQuery,
  ListDetectionsResponse,
  Rule,
} from '@akasecurity/schema';
import {
  buildDetectionsList,
  CAPTURE_EVENT_TYPES_SQL,
  rowToDetectionDetail,
  splitDetectionId,
} from '@akasecurity/schema';

import { safeJson } from '../internal/json.ts';
import { allRows, countScalar, getRow, intToBool } from '../internal/rows.ts';
import { placeholders } from '../internal/sql-text.ts';
import type { DetectionsReadPort } from '../ports.ts';

const DAY_MS = 86_400_000;

// Raw installed_packs row for the summary projection (rule count parsed in JS —
// see listDetections; SQL json_array_length would throw on a malformed row).
interface SummaryRow {
  namespace: string;
  packId: string;
  version: string;
  name: string;
  enabled: number;
  policyId: string | null;
  rulesJson: string;
}

// Raw installed_packs row for the detail projection (rules parsed in JS).
interface DetailRow {
  namespace: string;
  packId: string;
  version: string;
  name: string;
  enabled: number;
  policyId: string | null;
  rulesJson: string;
  updatedAt: number;
}

// Tolerant parse of rules_json → Rule[]. The plugin validates rules before it
// writes them, but a malformed/foreign row must not fail the whole read — skip
// what won't parse (mirrors the security/findings repos' defensive JSON handling).
// Exported so the installed-packs repo shares one JSON-tolerance policy for its
// per-pack rule counts (no drift between the Detections and Policies pages).
export function parseRules(rulesJson: string): Rule[] {
  const raw = safeJson<unknown>(rulesJson, []);
  if (!Array.isArray(raw)) return [];
  const rules: Rule[] = [];
  for (const entry of raw) {
    // Rules were validated on write; trust their shape here (a full Rule.parse per
    // row on every read would be wasteful). We only need id/name/category/severity/
    // matcher, which rowToDetectionDetail reads.
    if (entry && typeof entry === 'object') rules.push(entry as Rule);
  }
  return rules;
}

// The available_packs mirror row a detection is compared against to decide
// whether an update is available (see availableByPack).
interface AvailableRow {
  version: string;
  rulesJson: string;
}

// An update exists when the installed snapshot differs from the binary's
// available mirror by version OR serialized rule content. Content matters: pack
// coverage can grow within the same manifest version, and a version-only
// compare would hide those updates forever. Both sides serialize through the
// same JSON.stringify(Rule[]) pipeline, so string equality is a sound proxy.
function hasDrift(
  installed: { version: string; rulesJson: string },
  latest: AvailableRow,
): boolean {
  return installed.version !== latest.version || installed.rulesJson !== latest.rulesJson;
}

/**
 * Detections read views over the tenant-free local store — the read side of
 * the Detections page. Reads installed_packs (+ inspection_findings⋈audit_events
 * for the 30-day count, + available_packs for update availability) and shapes the finished
 * @akasecurity/schema responses via the shared pure builders, so read surfaces
 * never diverge.
 *
 * OSS "updates" come from the available_packs mirror — the inventory the
 * currently running plugin/CLI binary ships, recorded on every gateway open. A
 * pack has an update when its installed snapshot differs from the mirror by
 * VERSION OR RULE CONTENT (content matters: coverage can grow within the same
 * manifest version). Updates are applied manually (installed-packs
 * applyUpdate); nothing here mutates. The clock is injectable so the 30-day
 * window is deterministic under test.
 */
export class SqliteDetectionsRepository implements DetectionsReadPort {
  constructor(
    private readonly db: DatabaseSync,
    private readonly now: () => number = () => Date.now(),
  ) {}

  listDetections(query: ListDetectionsQuery): Promise<ListDetectionsResponse> {
    const rows = allRows<SummaryRow>(
      this.db.prepare(
        `SELECT namespace, pack_id AS packId, version, name, enabled, policy_id AS policyId,
                rules_json AS rulesJson
         FROM installed_packs`,
      ),
    );
    const available = this.availableByPack();

    const summaries: DetectionSummaryInput[] = rows.map((r) => {
      const latest = available.get(`${r.namespace}/${r.packId}`);
      return {
        namespace: r.namespace,
        packId: r.packId,
        version: r.version,
        name: r.name,
        enabled: intToBool(r.enabled),
        // Count rules in JS via the tolerant parse rather than SQL json_array_length,
        // which THROWS "malformed JSON" on a corrupt/foreign rules_json and would
        // crash the whole list. This also keeps ruleCount identical to the detail
        // view (rowToDetectionDetail uses parseRules().length) — no list/detail drift.
        ruleCount: parseRules(r.rulesJson).length,
        policyId: r.policyId,
        // Only set when the mirror actually differs — an equal snapshot or a
        // pack with no mirror row (foreign/custom) reports no update.
        ...(latest && hasDrift(r, latest) ? { latestVersion: latest.version } : {}),
      };
    });

    return Promise.resolve(buildDetectionsList(summaries, query));
  }

  // available_packs keyed by the "namespace/packId" slug (one read per list /
  // detail call; the table is a handful of rows).
  private availableByPack(): Map<string, AvailableRow> {
    const rows = allRows<{ namespace: string; packId: string; version: string; rulesJson: string }>(
      this.db.prepare(
        `SELECT namespace, pack_id AS packId, version, rules_json AS rulesJson
         FROM available_packs`,
      ),
    );
    return new Map(rows.map((r) => [`${r.namespace}/${r.packId}`, r]));
  }

  getDetectionStats(): Promise<DetectionStats> {
    // Read installed_packs ONCE and derive every stat in JS. SQL json_array_length
    // would throw on a malformed/foreign rules_json (the JS parse is tolerant), and
    // a single scan also removes the second pass the rule-id union used to make.
    const rows = allRows<{ enabled: number; rulesJson: string }>(
      this.db.prepare('SELECT enabled, rules_json AS rulesJson FROM installed_packs'),
    );

    let rules = 0;
    let active = 0;
    const ruleIds = new Set<string>();
    for (const r of rows) {
      if (intToBool(r.enabled)) active += 1;
      const parsed = parseRules(r.rulesJson);
      rules += parsed.length;
      // Union of rule ids for the 30-day findings count (skip any without one).
      for (const rule of parsed) {
        if (typeof rule.id === 'string') ruleIds.add(rule.id);
      }
    }

    return Promise.resolve({
      detections: rows.length,
      rules,
      active,
      findingsLast30d: this.countFindingsLast30d([...ruleIds]),
    });
  }

  getDetectionDetail(id: string): Promise<DetectionDetail | null> {
    const parts = splitDetectionId(id);
    if (!parts) return Promise.resolve(null);
    const { namespace, packId } = parts;

    const row = getRow<DetailRow>(
      this.db.prepare(
        `SELECT namespace, pack_id AS packId, version, name, enabled, policy_id AS policyId,
                rules_json AS rulesJson, updated_at AS updatedAt
         FROM installed_packs
         WHERE namespace = ? AND pack_id = ?`,
      ),
      [namespace, packId],
    );
    if (!row) return Promise.resolve(null);

    const rules = parseRules(row.rulesJson);
    // Skip rules without a string id (a foreign/partial row may carry one) — the
    // same guard getDetectionStats applies. Binding undefined into the IN (…) list
    // throws in node:sqlite, which would crash the whole detail read.
    const ruleIds = rules.map((r) => r.id).filter((id): id is string => typeof id === 'string');
    const findingsLast30d = this.countFindingsLast30d(ruleIds);

    // Update availability against the available_packs mirror: no mirror row ⇒
    // honestly unknown (null); a matching snapshot ⇒ explicit "up to date";
    // version OR rule-content drift ⇒ available, with the latest rule count so
    // the UI can show a meaningful delta for same-version content growth.
    const latest = this.availableByPack().get(`${row.namespace}/${row.packId}`);
    const update = latest
      ? hasDrift(row, latest)
        ? {
            available: true,
            latestVersion: latest.version,
            latestRuleCount: parseRules(latest.rulesJson).length,
          }
        : { available: false, latestVersion: latest.version }
      : null;

    return Promise.resolve(
      rowToDetectionDetail(
        {
          namespace: row.namespace,
          packId: row.packId,
          version: row.version,
          name: row.name,
          enabled: intToBool(row.enabled),
          rules,
          updatedAt: new Date(row.updatedAt),
          policyId: row.policyId,
        },
        findingsLast30d,
        update,
      ),
    );
  }

  // Findings whose parent audit event occurred in the last 30 days, is one of
  // the four capture kinds, and whose definition's rule_id is in the given set.
  // Mirrors the security repo's inspection_findings⋈audit_events window join.
  // rule_id lives on inspection_definitions, not the finding row, so the join
  // chains through it. audit_events also holds structural rows (session, run,
  // tool_call, llm_call, source_lookup, config_scan) that never had a legacy
  // events counterpart, so the event_type predicate keeps this count identical
  // to the old findings⋈events one.
  private countFindingsLast30d(ruleIds: string[]): number {
    // WHERE rule_id IN () is invalid SQL and the answer is always 0.
    if (ruleIds.length === 0) return 0;
    const since = this.now() - 30 * DAY_MS;
    const inClause = placeholders(ruleIds.length);
    return countScalar(
      this.db,
      `SELECT count(*) AS n
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         JOIN inspection_definitions d ON d.id = f.inspection_definition_id
         WHERE e.started_at >= ?
           AND e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
           AND d.rule_id IN (${inClause})`,
      [since, ...ruleIds],
    );
  }
}
