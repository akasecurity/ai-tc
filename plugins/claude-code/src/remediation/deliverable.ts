import type { MaskedSecretFinding } from '@akasecurity/schema';

import { renderResolvedSummary } from './render.ts';
import { buildChecklistEntries, generateRotationChecklist } from './rotation-checklist.ts';

export function resolveRemediationDeliverable(input: {
  readonly findings: readonly MaskedSecretFinding[];
  readonly redactedKeys: number;
  // How many of `redactedKeys` were replaced with recoverable vault pointers
  // rather than struck one-way — defaults to 0 (irreversible-strike wording).
  readonly pointeredKeys?: number;
  // Which of `findings` the redaction pass did NOT strike — defaults to empty
  // (every finding redacted) for callers that know redaction was complete.
  readonly unredactedFindings?: readonly MaskedSecretFinding[];
  readonly cwd: string;
}) {
  const pointeredKeys = input.pointeredKeys ?? 0;
  const unredactedFindings = input.unredactedFindings ?? [];
  const entries = buildChecklistEntries(input.findings);
  const writeResult = generateRotationChecklist({ entries, cwd: input.cwd });
  const summary =
    writeResult.status === 'written'
      ? renderResolvedSummary({
          redactedKeys: input.redactedKeys,
          pointeredKeys,
          findings: input.findings,
          unredactedFindings,
          location: writeResult.locationLabel,
          entries,
        })
      : renderResolvedSummary({
          redactedKeys: input.redactedKeys,
          pointeredKeys,
          findings: input.findings,
          unredactedFindings,
          degradedNote: writeResult.note,
          entries,
        });

  return { summary, writeResult, entries };
}
