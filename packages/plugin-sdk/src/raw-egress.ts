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

// The shortest run of a raw value whose survival into outbound text is still a
// disclosure. A whole-value check (`text.includes(raw)`) matches only if the
// ENTIRE value survives, so text carrying a TRUNCATED run passes it — and a run
// of a high-entropy credential is still a live credential's prefix. Truncating
// is exactly what a model does to a long token it quotes back, which is why the
// two writeback sites scrubbing model free text are the most exposed callers.
//
// Eight characters is a substantial fraction of every value the bundled rules
// match, and for the shorter ones it is most of the secret. It is the same
// number the test-side `no-echo` helpers use, for the same reason — but they are
// INDEPENDENT copies across a package wall, so neither pins the other and each
// is held by its own suite.
//
// The floor below it is MIN_RAW_LEN, not zero: a raw value shorter than one
// window cannot fill one, so it keeps the whole-value check it already had
// rather than being silently exempted. Widening this number back is a
// deliberate act — `test/raw-egress.test.ts` fails on the first character of it.
const RAW_RUN_LEN = 8;

// Does `text` carry any run of any value in `rawValues` long enough to be a
// disclosure? Mirrors the test-side `expectNoEchoOf`: the two window sets are
// compared for an intersection, so any RAW_RUN_LEN-long slice of any raw value
// that survives into `text` is a rejection.
//
// The index is built over `text` rather than over `rawValues`, and the asymmetry
// is deliberate. A search per window is quadratic in the size of a real triage
// run, so one side has to be indexed — but indexing the RAW side rebuilds a set
// whose size grows with the hit count on every call, and `buildJoinEntries`
// calls this once per hit with every hit's value against a short context window.
// Indexing `text` bounds the set by the text instead, builds it lazily (a run of
// values all below the window length never builds one at all), and leaves the
// large-text plan-document caller unchanged.
function carriesRawRun(text: string, rawValues: readonly string[]): boolean {
  let windows: Set<string> | null = null;
  for (const raw of rawValues) {
    if (raw.length < MIN_RAW_LEN) continue;
    // Shorter than one window: checked whole, exactly as before.
    if (raw.length < RAW_RUN_LEN) {
      if (text.includes(raw)) return true;
      continue;
    }
    if (windows === null) {
      windows = new Set<string>();
      for (let i = 0; i + RAW_RUN_LEN <= text.length; i += 1) {
        windows.add(text.slice(i, i + RAW_RUN_LEN));
      }
    }
    // `text` is shorter than one window, so no value this long can match — but
    // a SHORTER value later in the list is still checked whole, so skip this
    // one rather than returning: an early exit here would let a short raw that
    // does appear in `text` through whenever a long one happened to come first.
    if (windows.size === 0) continue;
    for (let i = 0; i + RAW_RUN_LEN <= raw.length; i += 1) {
      if (windows.has(raw.slice(i, i + RAW_RUN_LEN))) return true;
    }
  }
  return false;
}

// Mask a context window: redact every hit overlapping the slice, with each
// span rebased to the slice's own start, then verify no raw value survives.
// `sliceStart` and each hit's `span` are whatever coordinate space the caller
// chooses (e.g. offsets into the original source text, or offsets into the
// slice itself with sliceStart 0) — this function carries no state between
// calls, so nothing needs to be persisted alongside the slice to reuse it.
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
  // Run-by-run, with assertRawFree below: this backstop exists to catch a span
  // that did not cover its value, and a span covering only PART of one leaves a
  // live run behind exactly as a missing span leaves the whole value. Neither
  // caller is destabilised by the tightening, but for different reasons. The
  // join builder hands the same text to assertRawFree on the very next line, so
  // the run check runs there regardless. The history walk only CATCHES this
  // throw — it must never throw on a user's transcript — and its fallback splits
  // on the whole value, so it cannot remove a partial run; that path is no worse
  // than before the tightening, not made safe by it.
  const rawValues = hits.map((h) => h.rawMatch);
  if (carriesRawRun(masked, rawValues)) {
    throw new RawEgressError('raw match survived context masking');
  }
  return masked;
}

// maskMatch, guaranteed to never equal or contain the raw value. maskMatch's
// short-local-email pass-through (e.g. "a@b.com") is the one documented case
// where its output can still equal the raw value; fall back to '***' there.
//
// DELIBERATELY WHOLE-VALUE, unlike its two siblings above and below. They scrub
// text that must carry NO trace of a raw value; this one verifies a preview that
// is built to REVEAL a fragment on purpose, so a surviving run is the feature
// rather than the leak. maskMatch's email branch reveals the first local
// character plus the WHOLE domain ("user@example.com" -> "u***@example.com"),
// which is a run far past RAW_RUN_LEN — so a run check here would reject every
// email preview and collapse it to '***', destroying the disclosure the
// dashboard and the CLI both render. The generic branch reveals the first and
// last character around fixed asterisks: two characters that are never adjacent,
// so they sit in two runs of ONE and cannot fill a window at any width. The
// margin that reasoning spends is pinned in `cli/test/helpers/no-echo.test.ts`.
export function safeMaskedMatch(rawMatch: string): string {
  const masked = maskMatch(rawMatch);
  if (masked === rawMatch || (rawMatch.length >= MIN_RAW_LEN && masked.includes(rawMatch))) {
    return '***';
  }
  return masked;
}

// Reject free-form text if it carries any RUN of a raw value from this run, not
// only a whole one. This is the module's central containment: its callers route
// a model's reasoning and notes, a downstream error message bound for the parent
// command's stderr, the serialized plan document, a masked context window and a
// file path through it. The guarantee each of them leans on is that a FUTURE
// echo is covered too, and a future echo that interpolates `value.slice(0, 12)`
// is covered only by the run check.
export function assertRawFree(text: string, rawValues: readonly string[]): string {
  if (carriesRawRun(text, rawValues)) {
    throw new RawEgressError('text contained a raw detected value');
  }
  return text;
}
