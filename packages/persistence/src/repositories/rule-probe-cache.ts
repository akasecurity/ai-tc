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
  private readonly countQuarantinedStmt: StatementSync;
  private readonly clearQuarantinedStmt: StatementSync;

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
    this.countQuarantinedStmt = db.prepare(
      `SELECT COUNT(*) AS n FROM rule_probe_cache WHERE verdict = 'quarantined'`,
    );
    this.clearQuarantinedStmt = db.prepare(
      `DELETE FROM rule_probe_cache WHERE verdict = 'quarantined'`,
    );
  }

  getVerdict(ruleKey: string): RuleProbeCacheEntry | undefined {
    return getRow<RuleProbeCacheEntry>(this.readStmt, { ruleKey });
  }

  /** How many rules are currently excluded by a cached quarantine verdict. */
  countQuarantined(): number {
    return getRow<{ n: number }>(this.countQuarantinedStmt, {})?.n ?? 0;
  }

  /**
   * Forgets every quarantine verdict, so the rules behind them are measured
   * again on the next load. This is the undo for a verdict the machine reached
   * on its own: a rule terminated mid-scan is cached forever and dropped from
   * every later scan, and a timing verdict is a wall-clock judgement that a
   * loaded or slow machine can reach about a rule that is in fact fine.
   *
   * Only 'quarantined' rows go — a 'safe' verdict is a measurement worth
   * keeping, and dropping it would make every rule pay the battery again.
   *
   * Reports `refused` from the write's own result rather than inferring it from
   * the row count. The two are NOT the same answer: `failOpenTransaction`
   * swallows a contended DELETE (another writer holding the lock past
   * `busy_timeout` — reads are unaffected in WAL), and a swallowed refusal
   * leaves the count unchanged, which is indistinguishable from "there was
   * nothing to clear". An undo that reports success while the quarantines are
   * still in place is worse than one that fails, because the rules it claimed
   * to restore are silently still disabled.
   */
  clearQuarantined(): { refused: boolean; cleared: number } {
    const before = this.countQuarantined();
    const committed = failOpenTransaction(this.db, () => {
      this.clearQuarantinedStmt.run();
    });
    return { refused: !committed, cleared: before - this.countQuarantined() };
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
