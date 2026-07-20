/**
 * Pre-filled fixture/exception writer: given a chosen masked
 * false-positive pattern group (the false-positive signal, see
 * false-positive-patterns.ts) and a user-selected duration, write one
 * value-scoped exception per DISTINCT marked-hit value identity through the
 * existing exceptions machinery. Pure core: no DB/IO, the writer is
 * injected so this is unit-testable with a fake.
 *
 * Keys each written exception on the marked hit's EXACT value identity
 * (ruleId/valueFingerprint/keyVersion), never on the shared masked
 * `pattern` token: distinct raw values can render to one masked token, so a
 * group covering two distinct valueFingerprints writes TWO exceptions,
 * never one grant collapsing them — deduped on the full identity triple so
 * a repeated identical identity writes once. A value missing any part of
 * its identity is skipped: the producer already leaves such marks out of
 * `values`, this is a defensive re-check rather than the primary guard, so
 * an unkeyable mark is never written and never offered (fail-open, not a
 * wrongly-keyed or token-keyed grant).
 *
 * Does NOT reuse plugin-sdk's ExceptionWriter/applySetupTriageSuppressions:
 * those hardcode scope 'temporary' / maxUses null. The duration the user
 * selects — once / temporary / permanent, resolved through the shared scope
 * resolver (resolveScopeFlags/scopeFromAnswer in @akasecurity/schema) —
 * must persist as its whole {scope, expiresAt, maxUses} triple.
 */
import type {
  DetectionCategory,
  FalsePositivePatternGroup,
  ResolvedScope,
} from '@akasecurity/schema';

// Minimal slice of the exceptions repository's create(), matching
// SqliteExceptionsRepository.create's CreateExceptionInput shape (the
// wizard adapter passes db.exceptions; the repo stamps id/timestamps/
// useCount itself). createdVia is always 'setup-triage' — the same enum
// value plugin-sdk's applySetupTriageSuppressions writes; the read-back
// distinguisher between the two is scope/maxUses, not createdVia.
export interface FixtureExceptionWriter {
  create(
    input: {
      ruleId: string;
      category: DetectionCategory;
      valueFingerprint: string;
      keyVersion: number;
      maskedValue: string;
      justification: string;
      conditions: null;
      createdBy: string;
      createdVia: 'setup-triage';
    } & ResolvedScope,
  ): Promise<unknown>;
}

// The real repository (SqliteExceptionsRepository.create) throws a
// duplicate-active-exception when an active grant already exists for the same
// (ruleId, valueFingerprint, keyVersion) — the identity setup-triage's own
// 30-day grants also target. Duck-typed by `code` so the pure core stays free
// of a persistence import, matching plugin-sdk's applySetupTriageSuppressions.
function isDuplicateActive(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    (err as { code?: string }).code === 'duplicate-active-exception'
  );
}

// Accept path: write one exception per distinct value identity in the
// chosen group. Each value carries its OWN `category` (denormalized from its
// hit): the group is keyed by masked token alone, and one masked token can
// collide across categories, so a single group-level category would stamp a
// sibling's category onto some grants. `scope` is the ALREADY-RESOLVED
// {scope, expiresAt, maxUses} triple (via resolveScopeFlags/scopeFromAnswer)
// for the duration the user selected.
//
// Idempotent, mirroring plugin-sdk's applySetupTriageSuppressions: a value
// whose identity already has an active grant collides on the repository's
// active-constraint (create() throws duplicate-active-exception); that is
// caught per row and counted as skippedDuplicate so the batch never aborts
// mid-loop with a partial write, and a re-run is a no-op. Any OTHER create()
// error rethrows — a real fault must be loud.
export async function acceptFixtureExceptionOffer(
  group: Pick<FalsePositivePatternGroup, 'pattern' | 'values'>,
  scope: ResolvedScope,
  writer: FixtureExceptionWriter,
  opts: { justification: string; createdBy: string },
): Promise<{ written: number; skippedDuplicate: number }> {
  const seen = new Set<string>();
  let written = 0;
  let skippedDuplicate = 0;
  for (const value of group.values) {
    if (
      typeof value.ruleId !== 'string' ||
      typeof value.category !== 'string' ||
      typeof value.valueFingerprint !== 'string' ||
      typeof value.keyVersion !== 'number'
    ) {
      continue; // defensive: an unkeyable mark is never written
    }
    const identity = `${value.ruleId}\u0000${value.valueFingerprint}\u0000${String(value.keyVersion)}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    try {
      await writer.create({
        ruleId: value.ruleId,
        category: value.category,
        valueFingerprint: value.valueFingerprint,
        keyVersion: value.keyVersion,
        maskedValue: group.pattern,
        ...scope,
        justification: opts.justification,
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

// Decline path: writes nothing. A distinct, symmetric entry point so the
// wizard adapter's accept/decline branch always calls a function from this
// module — the value-scoped exception is never written any other way in
// response to a decline.
export function declineFixtureExceptionOffer(): { written: number } {
  return { written: 0 };
}
