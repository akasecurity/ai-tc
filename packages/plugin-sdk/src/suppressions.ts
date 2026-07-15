import type { DetectionCategory } from '@akasecurity/schema';

// 30-day review window for a setup-triage FP suppression: a confirmed FP is
// silenced temporarily, then resurfaces for re-review.
export const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

export interface SuppressionEntry {
  ruleId: string;
  category: DetectionCategory;
  valueFingerprint: string;
  keyVersion: number;
  maskedValue: string;
  justification: string;
}

// Minimal slice of the exceptions repository's create(); the wizard adapter
// passes db.exceptions. `expiresAt` is an ISO string the repo converts on insert.
export interface ExceptionWriter {
  create(input: {
    ruleId: string;
    category: DetectionCategory;
    valueFingerprint: string;
    keyVersion: number;
    maskedValue: string;
    scope: 'temporary';
    expiresAt: string;
    maxUses: null;
    justification: string;
    conditions: null;
    createdBy: string;
    createdVia: 'setup-triage';
  }): Promise<unknown>;
}

function isDuplicateActive(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    (err as { code?: string }).code === 'duplicate-active-exception'
  );
}

// Write one temporary 30-day setup-triage grant per confirmed-FP entry. Idempotent:
// a re-run hits the active-constraint and create() throws DuplicateActiveExceptionError;
// that is caught per row so the batch never aborts. Any OTHER error rethrows (a real
// fault must be loud). Callers pre-resolve entries (join + fpCount fail-secure check
// live in the adapter) and drop any hit without a valueFingerprint.
export async function applySetupTriageSuppressions(
  entries: readonly SuppressionEntry[],
  writer: ExceptionWriter,
  opts: { createdBy: string; now: number },
): Promise<{ written: number; skippedDuplicate: number }> {
  let written = 0;
  let skippedDuplicate = 0;
  const expiresAt = new Date(opts.now + THIRTY_DAYS_MS).toISOString();
  for (const e of entries) {
    try {
      await writer.create({
        ruleId: e.ruleId,
        category: e.category,
        valueFingerprint: e.valueFingerprint,
        keyVersion: e.keyVersion,
        maskedValue: e.maskedValue,
        scope: 'temporary',
        expiresAt,
        maxUses: null,
        justification: e.justification,
        conditions: null,
        createdBy: opts.createdBy,
        createdVia: 'setup-triage',
      });
      written++;
    } catch (err) {
      if (isDuplicateActive(err)) {
        skippedDuplicate++;
        continue;
      }
      throw err;
    }
  }
  return { written, skippedDuplicate };
}
