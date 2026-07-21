/**
 * The leaked-key presentation: the full layout the batched remediation
 * decision is shown over. A provider/token/where/state finding table rendered
 * from the masked per-finding summaries (masked tokens only — no raw key ever
 * crosses here), the most-exposed-first recommendation line, and the closing
 * chaining line naming the single secret-scan continuation the installed plugin
 * registers. Pure formatter: the count and the registry are threaded in, so it
 * unit-tests without I/O.
 */
import type {
  MaskedSecretFinding,
  RotationChecklistEntry,
  SecretFindingState,
} from '@akasecurity/schema';

import { selectSecretScanContinuation } from '../command-registry.ts';
import { table } from '../present.ts';
import {
  renderChecklistMarkdown,
  renderRotationChecklistResolvedLine,
} from './rotation-checklist.ts';

// The verbatim recommendation line: redact, then rotate, most-exposed-first.
const RECOMMENDATION_LINE = "I'd redact them and get you rotating, most-exposed first";

// The finding state as human-facing text — the table renders each finding's own
// state, not the enum token. A leaked key's validity is unverifiable offline, so
// the default 'unknown' reads as 'unknown'; 'still valid' is claimed only for a
// finding a caller could actually verify.
const STATE_LABEL: Record<SecretFindingState, string> = {
  'still-valid': 'still valid',
  unknown: 'unknown',
  invalid: 'invalid',
};

// Render the full decision layout over the masked findings: the finding table, the
// recommendation line, and the chaining line. `moreCount` templates the chaining
// line's 'N more worth a look' count; `registry` is the installed command set
// (readRegisteredCommands()), resolved at the caller's I/O boundary and threaded
// in so this stays a pure formatter — the chaining line's secret-scan
// continuation is selected against it, so it names only a command the plugin
// actually registers and throws rather than naming an unregistered one.
export function renderRemediationDecision(
  findings: readonly MaskedSecretFinding[],
  moreCount: number,
  registry: readonly string[],
): string {
  const scanCommand = selectSecretScanContinuation(registry);
  const rows = findings.map((f) => [
    f.provider,
    f.maskedToken,
    f.where.filePath,
    STATE_LABEL[f.state],
  ]);
  const findingTable = table(['Provider', 'Token', 'Where', 'State'], rows, { rowSep: true });
  const chainingLine = `${String(moreCount)} more worth a look — run ${scanCommand} when you're ready.`;
  return [findingTable, '', RECOMMENDATION_LINE, '', chainingLine].join('\n');
}

// The confirmation line shown once redaction has run: '✓ Redacted N keys',
// templated over the REAL count of keys the redaction mechanism struck (never a
// literal). It reports the redaction and nothing more — the 'Redact only' choice
// draws only this line, with no rotation-checklist deliverable — so the count is
// the sole variable. The redact-plus-checklist resolved summary composes this
// same line with its deliverable line.
export function renderRedactionConfirmation(redactedKeys: number): string {
  const noun = redactedKeys === 1 ? 'key' : 'keys';
  return `✓ Redacted ${String(redactedKeys)} ${noun}`;
}

// The honest partial-strike line — "Redacted N of M keys; K still need attention
// in <files>" — shared by the redact-only confirmation and the resolved summary
// so a partial redaction reads identically wherever it surfaces.
export function renderPartialRedactionLine(
  redactedKeys: number,
  totalKeys: number,
  unredactedFindings: readonly MaskedSecretFinding[],
): string {
  const remainingCount = unredactedFindings.length;
  const remainingFiles = [...new Set(unredactedFindings.map((finding) => finding.where.filePath))];
  const totalNoun = totalKeys === 1 ? 'key' : 'keys';
  const remainingNoun = remainingCount === 1 ? 'key' : 'keys';
  const remainingVerb = remainingCount === 1 ? 'needs' : 'need';
  return (
    `Redacted ${String(redactedKeys)} of ${String(totalKeys)} ${totalNoun}; ` +
    `${String(remainingCount)} ${remainingNoun} still ${remainingVerb} attention in ${remainingFiles.join(', ')}`
  );
}

// The standalone redaction confirmation for the redact-only route (no rotation
// checklist, so no resolved summary carries the strike). Honest about a partial
// strike: when some findings were left unredacted it names the count still
// outstanding and the file(s) that still hold a live key, rather than a bare
// "✓ Redacted N keys" that a partial strike must never earn.
export function renderRedactionOutcome(input: {
  readonly redactedKeys: number;
  readonly findings: readonly MaskedSecretFinding[];
  readonly unredactedFindings: readonly MaskedSecretFinding[];
}): string {
  const totalKeys = input.findings.length;
  const isComplete = input.redactedKeys === totalKeys && input.unredactedFindings.length === 0;
  if (isComplete) return `${renderRedactionConfirmation(input.redactedKeys)}.`;
  return renderPartialRedactionLine(input.redactedKeys, totalKeys, input.unredactedFindings);
}

// The "resolved" framing is only ever honest when every leaked key was struck.
// `renderResolvedSummary` renders that framing exactly when `redactedKeys`
// covers every finding AND the caller reports no finding left unredacted —
// otherwise it renders an honest partial-redaction message naming the count
// still outstanding and the file(s) that still hold a live key, rather than the
// clean "resolved" header a partial strike must never earn.
export function renderResolvedSummary(
  input: {
    readonly redactedKeys: number;
    readonly findings: readonly MaskedSecretFinding[];
    // Exactly which of `findings` the redaction pass did NOT strike — empty when
    // every finding was redacted. Required (not inferred from the count alone) so
    // the file(s) still holding a live key can be named in the partial message.
    readonly unredactedFindings: readonly MaskedSecretFinding[];
    readonly entries: readonly RotationChecklistEntry[];
  } & (
    | { readonly location: string; readonly degradedNote?: never }
    | { readonly location?: never; readonly degradedNote: string }
  ),
): string {
  const totalKeys = input.findings.length;
  const isComplete = input.redactedKeys === totalKeys && input.unredactedFindings.length === 0;
  const preview = renderChecklistMarkdown(input.entries).trimEnd();
  const checklistLine = input.degradedNote ?? renderRotationChecklistResolvedLine(input.location);

  if (!isComplete) {
    const redactionLine = renderPartialRedactionLine(
      input.redactedKeys,
      totalKeys,
      input.unredactedFindings,
    );

    return ['Leaked secrets — partially redacted', redactionLine, checklistLine, '', preview].join(
      '\n',
    );
  }

  const transcriptCount = new Set(input.findings.map((finding) => finding.where.filePath)).size;
  const transcriptNoun = transcriptCount === 1 ? 'transcript' : 'transcripts';
  const redactionLine = `${renderRedactionConfirmation(input.redactedKeys)} across ${String(transcriptCount)} ${transcriptNoun}`;

  return ['Leaked secrets — resolved', redactionLine, checklistLine, '', preview].join('\n');
}
