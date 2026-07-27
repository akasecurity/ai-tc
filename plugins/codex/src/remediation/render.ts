/**
 * The leaked-key presentation: the full layout the batched remediation
 * decision is shown over. A provider/token/where/state finding table rendered
 * from the masked per-finding summaries (masked tokens only — no raw key ever
 * crosses here), the most-exposed-first recommendation line, and the closing
 * chaining line naming the single secret-scan continuation the installed plugin
 * registers. Pure formatter: the count and the registry are threaded in, so it
 * unit-tests without I/O.
 *
 * This module stays in the plugin because it is the one remediation formatter
 * that names a HOST skill (`aka-secretscan` · `aka-scan`) and so cannot be
 * shared across harnesses. The harness-agnostic redaction/resolved-summary
 * formatters live in `@akasecurity/setup-wizard`'s redaction-summary module.
 */
import type { MaskedSecretFinding, SecretFindingState } from '@akasecurity/schema';

import { table } from '../present.ts';
import { selectSecretScanContinuation } from '../skills-registry.ts';

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
// line's 'N more worth a look' count; `registry` is the installed skill set
// (readRegisteredSkills()), resolved at the caller's I/O boundary and threaded
// in so this stays a pure formatter — the chaining line's secret-scan
// continuation is selected against it, so it names only a skill the plugin
// actually registers and throws rather than naming an unregistered one.
export function renderRemediationDecision(
  findings: readonly MaskedSecretFinding[],
  moreCount: number,
  registry: readonly string[],
): string {
  const scanSkill = selectSecretScanContinuation(registry);
  const rows = findings.map((f) => [
    f.provider,
    f.maskedToken,
    f.where.filePath,
    STATE_LABEL[f.state],
  ]);
  const findingTable = table(['Provider', 'Token', 'Where', 'State'], rows, { rowSep: true });
  const chainingLine = `${String(moreCount)} more worth a look — run the ${scanSkill} skill when you're ready.`;
  return [findingTable, '', RECOMMENDATION_LINE, '', chainingLine].join('\n');
}
