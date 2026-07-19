import type { MaskedSecretFinding } from '@akasecurity/schema';

import { renderResolvedSummary } from './render.ts';
import { buildChecklistEntries, generateRotationChecklist } from './rotation-checklist.ts';

export function resolveRemediationDeliverable(input: {
  readonly findings: readonly MaskedSecretFinding[];
  readonly redactedKeys: number;
  readonly cwd: string;
}) {
  const entries = buildChecklistEntries(input.findings);
  const writeResult = generateRotationChecklist({ entries, cwd: input.cwd });
  const summary =
    writeResult.status === 'written'
      ? renderResolvedSummary({
          redactedKeys: input.redactedKeys,
          findings: input.findings,
          location: writeResult.locationLabel,
          entries,
        })
      : renderResolvedSummary({
          redactedKeys: input.redactedKeys,
          findings: input.findings,
          degradedNote: writeResult.note,
          entries,
        });

  return { summary, writeResult, entries };
}
