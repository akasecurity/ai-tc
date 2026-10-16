// Vaulting for whole-file scans: which detected values a scan holds in the
// vault, and the stored copy of the file that carries their pointers.
import type { MatchResult } from '@akasecurity/detections';
import { redact } from '@akasecurity/detections';
import type { PointerToken, VaultSightingKind } from '@akasecurity/schema';

export interface VaultSpansOptions {
  // The findings to vault. The rest are still read, so a span they overlap is
  // left alone.
  selected: ReadonlySet<MatchResult>;
  sighting: { location: string; kind: VaultSightingKind };
}

export interface AtRestVault {
  /**
   * Vault each selected finding whose span overlaps no other finding and still
   * slices to its raw match, and record a sighting for each pointer. Returns
   * the pointer for every finding that was vaulted; without vault consent, or
   * on any fault, a finding is simply absent. Never throws.
   */
  vaultSpans(
    text: string,
    findings: readonly MatchResult[],
    opts: VaultSpansOptions,
  ): Promise<Map<MatchResult, PointerToken>>;
}

/**
 * Whether a scan holds this finding's value in the vault: any secret, whatever
 * its resolved action. An exception decides enforcement, not storage, so a
 * secret an exception allows is vaulted too.
 */
export function isScanVaultable(finding: MatchResult): boolean {
  return finding.category === 'secret';
}

/**
 * The stored copy of a scanned text: each vaulted span carries its pointer,
 * each masked span is redacted one-way, and everything else is kept as read.
 *
 * Expects vaulted spans that overlap no masked span, which is what `vaultSpans`
 * returns. Should one overlap anyway, every vaulted span is redacted one-way
 * instead, so no part of a value is ever stored in the clear.
 */
export function composeAtRestContent(
  text: string,
  masked: readonly MatchResult[],
  vaulted: ReadonlyMap<MatchResult, PointerToken>,
): string {
  if (vaulted.size === 0) return redact(text, [...masked]);

  const pointers = [...vaulted.entries()].sort(([a], [b]) => a.span.start - b.span.start);
  const rest = masked.filter((finding) => !vaulted.has(finding));
  const placed = new Set<MatchResult>();

  const redactBetween = (start: number, end: number): string => {
    const inside = rest.filter((f) => f.span.start >= start && f.span.end <= end);
    for (const finding of inside) placed.add(finding);
    return redact(
      text.slice(start, end),
      inside.map((f) => ({ ...f, span: { start: f.span.start - start, end: f.span.end - start } })),
    );
  };

  let out = '';
  let cursor = 0;
  for (const [finding, pointer] of pointers) {
    if (finding.span.start < cursor) {
      return redact(text, [...masked, ...vaulted.keys()]);
    }
    out += redactBetween(cursor, finding.span.start) + pointer;
    cursor = finding.span.end;
  }
  out += redactBetween(cursor, text.length);

  if (placed.size !== rest.length) return redact(text, [...masked, ...vaulted.keys()]);
  return out;
}
