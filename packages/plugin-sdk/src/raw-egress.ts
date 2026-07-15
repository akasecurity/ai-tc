import type { MatchResult } from '@akasecurity/detections';
import { maskMatch, redact } from '@akasecurity/detections';
import type { Span } from '@akasecurity/schema';

// The single boundary-crossing validator for raw secret text leaving an
// isolated scan/judge process toward the interactive session or a persisted
// exceptions row. maskMatch/redact are re-verified here, not trusted directly.
export class RawEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RawEgressError';
  }
}

export interface EgressHit {
  rawMatch: string;
  span: Span;
}

// Shared length threshold for every raw-value containment check in this module.
// Below this length a raw value is too short to reliably treat a substring
// match as significant.
const MIN_RAW_LEN = 4;

// Mask a context window: redact every hit overlapping the slice, with each
// span rebased to the slice's own start, then verify no raw value survives.
export function maskContextSlice(
  slice: string,
  sliceStart: number,
  hits: readonly EgressHit[],
): string {
  const findings: MatchResult[] = [];
  for (const h of hits) {
    const start = Math.max(0, h.span.start - sliceStart);
    const end = Math.min(slice.length, h.span.end - sliceStart);
    if (end > start) {
      findings.push({
        ruleId: 'raw-egress',
        category: 'secret',
        severity: 'critical',
        span: { start, end },
        rawMatch: '',
        confidence: 1,
      });
    }
  }
  const masked = findings.length > 0 ? redact(slice, findings) : slice;
  for (const h of hits) {
    if (h.rawMatch.length >= MIN_RAW_LEN && masked.includes(h.rawMatch)) {
      throw new RawEgressError('raw match survived context masking');
    }
  }
  return masked;
}

// maskMatch, guaranteed to never equal or contain the raw value. maskMatch's
// short-local-email pass-through (e.g. "a@b.com") is the one documented case
// where its output can still equal the raw value; fall back to '***' there.
export function safeMaskedMatch(rawMatch: string): string {
  const masked = maskMatch(rawMatch);
  if (masked === rawMatch || (rawMatch.length >= MIN_RAW_LEN && masked.includes(rawMatch))) {
    return '***';
  }
  return masked;
}

// Reject free-form text if any raw value from this run appears in it verbatim.
export function assertRawFree(text: string, rawValues: readonly string[]): string {
  for (const raw of rawValues) {
    if (raw.length >= MIN_RAW_LEN && text.includes(raw)) {
      throw new RawEgressError('text contained a raw detected value');
    }
  }
  return text;
}
