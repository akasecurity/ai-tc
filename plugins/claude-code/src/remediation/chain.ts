/**
 * The pure, dependency-injected core of the secret-leak remediation chain.
 *
 * Given a secret-leak findings set plus an entry context — and no wizard state —
 * it produces the batched remediation decision presentation model: one decision moment
 * over all the surfaced secret-leak findings, the count copy templated over the
 * real count, and the exactly-four remediation options. Its input is the same
 * raw-free MaskedSecretFinding[] the loader reads from the calibration frame — a
 * secret-only set by construction, so it reads only the count and stays
 * entry-point-agnostic (a direct caller supplies the same shape a first-run entry
 * does); all IO (store reads, redaction, stdout) lives outside this module.
 */
import type {
  BatchedRemediation,
  BatchedRemediationDecision,
  MaskedSecretFinding,
  RemediationEntryContext,
  RemediationOption,
} from '@akasecurity/schema';

import type { StandingPostureResult } from './posture.ts';

// The four options of the remediation decision, in stable order — no more, no fewer.
// Typed to the schema's four-entry tuple so a dropped/reordered/extra option is a
// compile error, not just a runtime validation failure.
const REMEDIATION_OPTIONS: BatchedRemediationDecision['options'] = [
  { id: 'redact-rotation-checklist', label: 'Redact + rotation checklist' },
  { id: 'redact-only', label: 'Redact only' },
  { id: 'set-secret-redact', label: "Set 'secret' to redact" },
  { id: 'leave', label: 'Leave' },
];

// The count copy, templated over the real number of secret findings. It names
// the count and where the keys were found; it carries no status word, because the
// finding's status is what the data holds (state:'unknown' by default) and surfaces
// per-row in the finding table (render.ts).
function countCopy(secretCount: number): string {
  const noun = secretCount === 1 ? 'key' : 'keys';
  return `${secretCount.toString()} exposed secret ${noun} found in old transcripts`;
}

// Build the batched remediation decision over the surfaced secret leaks. The
// input is secret-only by construction (the loader reads only the frame's
// maskedFindings, derived from genuine secret hits — customer-data / PII findings
// never reach this shape), so the exclusion is a type-level
// guarantee here rather than a runtime filter. An empty set degrades honestly to
// a no-decision outcome.
export function presentBatchedRemediation(
  findings: readonly MaskedSecretFinding[],
  entryContext: RemediationEntryContext,
): BatchedRemediation {
  if (findings.length === 0) {
    return { kind: 'no-decision' };
  }
  const secretCount = findings.length;
  return {
    kind: 'decision',
    entrySource: entryContext.entrySource,
    secretCount,
    prompt: countCopy(secretCount),
    options: REMEDIATION_OPTIONS,
  };
}

// The side-effecting capabilities the remediation option router dispatches to. Injected as
// closures so the core holds no store, fs, or redaction access: `redact` strikes the
// findings' recovered raw values within the transcript/temp scope and returns the
// count redacted; `setStandingRedactPosture` writes the standing 'secret'→Redact
// policy and returns the write result.
export interface RemediationHandlers {
  redact: () => number;
  setStandingRedactPosture: () => StandingPostureResult;
}

// What the router did for the chosen option: the redaction path carries whether a
// rotation checklist was requested and the redacted-key count, the posture path
// carries the write result, and the leave path carries nothing.
export type RemediationRouteOutcome =
  | { kind: 'redacted'; withRotationChecklist: boolean; redactedKeys: number }
  | { kind: 'posture-set'; posture: StandingPostureResult }
  | { kind: 'left' };

// Route a chosen remediation option to exactly what it says and nothing more. Each of the
// four options does one thing: the two 'Redact' options route through the same
// injected redaction mechanism; 'Set secret to redact' writes only the standing
// posture; 'Leave' exits with no side effect at all.
export function routeRemediationOption(
  option: RemediationOption,
  handlers: RemediationHandlers,
): RemediationRouteOutcome {
  switch (option) {
    case 'redact-only':
      return { kind: 'redacted', withRotationChecklist: false, redactedKeys: handlers.redact() };
    case 'redact-rotation-checklist': {
      const redactedKeys = handlers.redact();
      // The redact-and-checklist path performs the redaction here; the rotation
      // checklist and resolved-summary deliverable are produced by a later step.
      // This branch records that a checklist was requested via withRotationChecklist
      // so the deliverable step can attach to it.
      return { kind: 'redacted', withRotationChecklist: true, redactedKeys };
    }
    case 'set-secret-redact':
      return { kind: 'posture-set', posture: handlers.setStandingRedactPosture() };
    case 'leave':
      return { kind: 'left' };
  }
}
