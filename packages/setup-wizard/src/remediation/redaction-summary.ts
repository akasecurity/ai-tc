/**
 * The redaction/resolved-summary formatters: pure text layout over already-masked
 * findings (no raw key ever crosses here) and the rotation-checklist deliverable.
 * Harness-agnostic — nothing here names a harness command (the pointered note's
 * `aka vault show` is the shared CLI, present on every install), so every
 * harness plugin renders these identically. The one formatter that DOES name a
 * harness command (the batched decision layout's chaining line) stays in each
 * plugin's own render module.
 */
import type { MaskedSecretFinding, RotationChecklistEntry } from '@akasecurity/schema';

import {
  renderChecklistMarkdown,
  renderRotationChecklistResolvedLine,
} from './rotation-checklist.ts';

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

// The recoverable-pointer sentence, spoken only when at least one struck value
// was replaced with a vault pointer rather than destroyed: it names exactly how
// many values are recoverable and where to view them. The one-way strike copy
// never carries it, so an irreversible strike is never described as recoverable
// — and a recoverable one is never passed off as gone.
function renderPointeredNote(pointeredKeys: number): string {
  const subject = pointeredKeys === 1 ? 'value was' : 'values were';
  return (
    `${String(pointeredKeys)} ${subject} replaced with recoverable vault pointers — ` +
    'view them in the dashboard or with `aka vault show`.'
  );
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
  // How many of `redactedKeys` were replaced with recoverable vault pointers
  // rather than struck one-way. Drives the recoverability sentence; omitted or
  // 0 keeps the irreversible-strike wording exactly as it always was.
  readonly pointeredKeys?: number;
}): string {
  const pointeredKeys = input.pointeredKeys ?? 0;
  const totalKeys = input.findings.length;
  const isComplete = input.redactedKeys === totalKeys && input.unredactedFindings.length === 0;
  if (isComplete) {
    const confirmation = `${renderRedactionConfirmation(input.redactedKeys)}.`;
    return pointeredKeys === 0
      ? confirmation
      : `${confirmation} ${renderPointeredNote(pointeredKeys)}`;
  }
  const partialLine = renderPartialRedactionLine(
    input.redactedKeys,
    totalKeys,
    input.unredactedFindings,
  );
  return pointeredKeys === 0
    ? partialLine
    : `${partialLine}. ${renderPointeredNote(pointeredKeys)}`;
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
    // How many of `redactedKeys` were replaced with recoverable vault pointers
    // rather than struck one-way — see `renderRedactionOutcome`.
    readonly pointeredKeys?: number;
    readonly entries: readonly RotationChecklistEntry[];
  } & (
    | { readonly location: string; readonly degradedNote?: never }
    | { readonly location?: never; readonly degradedNote: string }
  ),
): string {
  const pointeredKeys = input.pointeredKeys ?? 0;
  const totalKeys = input.findings.length;
  const isComplete = input.redactedKeys === totalKeys && input.unredactedFindings.length === 0;
  const preview = renderChecklistMarkdown(input.entries).trimEnd();
  const checklistLine = input.degradedNote ?? renderRotationChecklistResolvedLine(input.location);
  // Appended to the redaction line only when some struck values are actually
  // recoverable; the irreversible wording stays untouched otherwise.
  const withPointeredNote = (line: string): string =>
    pointeredKeys === 0 ? line : `${line}. ${renderPointeredNote(pointeredKeys)}`;

  if (!isComplete) {
    const redactionLine = withPointeredNote(
      renderPartialRedactionLine(input.redactedKeys, totalKeys, input.unredactedFindings),
    );

    return ['Leaked secrets — partially redacted', redactionLine, checklistLine, '', preview].join(
      '\n',
    );
  }

  const transcriptCount = new Set(input.findings.map((finding) => finding.where.filePath)).size;
  const transcriptNoun = transcriptCount === 1 ? 'transcript' : 'transcripts';
  const redactionLine = withPointeredNote(
    `${renderRedactionConfirmation(input.redactedKeys)} across ${String(transcriptCount)} ${transcriptNoun}`,
  );

  return ['Leaked secrets — resolved', redactionLine, checklistLine, '', preview].join('\n');
}
