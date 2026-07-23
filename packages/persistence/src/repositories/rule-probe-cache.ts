import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { RuleProbeVerdict } from '@akasecurity/schema';

import { getRow } from '../internal/rows.ts';
import { failOpenTransaction } from '../internal/transactions.ts';

// One rule's cached ReDoS timing verdict.
export interface RuleProbeCacheEntry {
  verdict: RuleProbeVerdict;
  worstProbeMs: number;
}

/**
 * rule_probe_cache reader/writer, bound to one open DB. One row per rule,
 * keyed by a content hash of its pattern+flags, recording the one-time
 * adversarial-probe timing verdict for a regex rule that arrived from a
 * pulled or custom pack — so a rule already measured is never re-measured on
 * a later hook invocation. Bundled rules never reach this cache: they are
 * gated by the CI adversarial battery instead.
 */
export class SqliteRuleProbeCacheRepository {
  private readonly upsertStmt: StatementSync;
  private readonly readStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.upsertStmt = db.prepare(
      `INSERT INTO rule_probe_cache (rule_key, verdict, worst_probe_ms, checked_at)
       VALUES (:ruleKey, :verdict, :worstProbeMs, :checkedAt)
       ON CONFLICT (rule_key) DO UPDATE SET
         verdict = excluded.verdict,
         worst_probe_ms = excluded.worst_probe_ms,
         checked_at = excluded.checked_at`,
    );
    this.readStmt = db.prepare(
      `SELECT verdict, worst_probe_ms AS worstProbeMs FROM rule_probe_cache WHERE rule_key = :ruleKey`,
    );
  }

  getVerdict(ruleKey: string): RuleProbeCacheEntry | undefined {
    return getRow<RuleProbeCacheEntry>(this.readStmt, { ruleKey });
  }

  setVerdict(ruleKey: string, verdict: RuleProbeVerdict, worstProbeMs: number): void {
    // Fail-open: losing this cache entry only costs a re-measurement next
    // time, never a wrong safety decision now (the caller already has the
    // freshly computed verdict in memory for the current invocation).
    failOpenTransaction(this.db, () => {
      this.upsertStmt.run({ ruleKey, verdict, worstProbeMs, checkedAt: Date.now() });
    });
  }
}
