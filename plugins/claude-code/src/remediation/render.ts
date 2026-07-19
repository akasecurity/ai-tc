/**
 * The leaked-key presentation: the full layout the batched remediation
 * decision is shown over. A provider/token/where/state finding table rendered
 * from the masked per-finding summaries (masked tokens only — no raw key ever
 * crosses here), the most-exposed-first recommendation line, and the closing
 * chaining line naming the single secret-scan continuation the installed plugin
 * registers. Pure formatter: the count and the registry are threaded in, so it
 * unit-tests without I/O.
 */
import type { MaskedSecretFinding, SecretFindingState } from '@akasecurity/schema';

import { selectSecretScanContinuation } from '../command-registry.ts';
import { table } from '../present.ts';

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
  const chainingLine = `${String(moreCount)} more worth a look — run ${scanCommand}`;
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
