// Historical backfill: when the user granted "full" review at onboarding, sweep
// their prior Claude Code transcripts for secrets that leaked BEFORE AKA was
// installed (the live hooks cover everything after). Format-agnostic — the
// Claude Code transcript shape lives in ./transcripts; here we just feed each
// message through the same SDK detect→mask→record path the hooks use, so a
// backfilled finding is indistinguishable from a live one.
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { EgressHit, PluginConfig } from '@akasecurity/plugin-sdk';
import {
  contentHashOf,
  createPluginRuntime,
  maskContextSlice,
  safeMaskedMatch,
} from '@akasecurity/plugin-sdk';
import type { DetectionCategory, Severity, Span, TriageHit } from '@akasecurity/schema';

import { type HistoryWalkOptions, iterateHistory } from './transcripts.ts';

export interface ScanSummary {
  // false when historicalAccess !== 'full' — the scan is a no-op without consent.
  consented: boolean;
  scanned: number; // messages examined this run
  skipped: number; // messages already recorded (deduped) — not re-scanned
  findings: number; // findings recorded this run
  bySeverity: Record<string, number>;
  windowDays: number;
}

// ±chars of surrounding text captured around a match span for the triage sink.
const CONTEXT_RADIUS = 120;

// Redact every OTHER finding's raw value that overlaps this context window,
// leaving only the current finding's own match legible (it is already exposed
// verbatim via TriageHit.rawMatch, so nothing is lost by leaving it in place).
// Falls back to a blunt string-level redaction if the guarded mask can't
// verify full removal (e.g. two findings sharing identical raw text) —
// scanning a user's history must never throw on a pathological input.
function redactOverlapping(
  rawContext: string,
  contextStart: number,
  others: readonly EgressHit[],
): string {
  if (others.length === 0) return rawContext;
  try {
    return maskContextSlice(rawContext, contextStart, others);
  } catch {
    let safe = rawContext;
    for (const other of others) {
      if (other.rawMatch.length > 0) safe = safe.split(other.rawMatch).join('[REDACTED]');
    }
    return safe;
  }
}

// Build the transient triage hit for one finding. f is a structural subset of
// @akasecurity/detections's MatchResult, so this module never imports
// @akasecurity/detections directly. The returned TriageHit's `rawMatch` and
// `context` carry unmasked text by design (see @akasecurity/schema's TriageHit
// doc) — it is never persisted here, only handed to scanHistory's onHit sink.
// `otherFindings` are the message's other findings (if any); any of their raw
// values that fall inside this hit's context window are redacted, so a single
// hit never exposes a second, unrelated secret through its context.
export function buildTriageHit(
  text: string,
  f: {
    ruleId: string;
    category: DetectionCategory;
    severity: Severity;
    rawMatch: string;
    span: Span;
    confidence: number;
  },
  otherFindings: readonly { rawMatch: string; span: Span }[] = [],
): TriageHit {
  const start = Math.max(0, f.span.start - CONTEXT_RADIUS);
  const end = Math.min(text.length, f.span.end + CONTEXT_RADIUS);
  const rawContext = text.slice(start, end);
  const overlapping = otherFindings.filter((o) => o.span.start < end && o.span.end > start);
  return {
    ruleId: f.ruleId,
    category: f.category,
    severity: f.severity,
    maskedMatch: safeMaskedMatch(f.rawMatch),
    rawMatch: f.rawMatch,
    context: redactOverlapping(rawContext, start, overlapping),
    confidence: f.confidence,
  };
}

// Scan the host's transcript history and record any findings into the same
// local store the read surfaces query. Gated on consent; reuses ONE gateway +
// runtime for the whole sweep and persists only messages that actually leaked
// (`with-findings`) so a benign 30-day history doesn't flood the store.
//
// Idempotent: messages whose content is already recorded (a prior scan, or a
// live capture) are skipped, so `/aka:setup` can re-run the scan any number of
// times without ever duplicating findings. A cleared store re-scans in full.
//
// `onHit`, when given, receives one TriageHit per finding as it is scanned —
// a transient, in-process stream for a same-process consumer (e.g. a triage
// judge) to read. Its `rawMatch` and its own match inside `context` are
// unmasked by design (see @akasecurity/schema's TriageHit); any OTHER
// finding's raw value that happens to fall inside the same context window is
// already redacted before the hit is emitted. A consumer must still run
// `rawMatch`/`context` through the @akasecurity/plugin-sdk raw-egress
// guardrails (`assertRawFree` / `maskContextSlice`) before either crosses out
// to a log, a rendered surface, or a persisted row.
export async function scanHistory(
  config: PluginConfig,
  opts: HistoryWalkOptions = {},
  onHit?: (hit: TriageHit) => void,
): Promise<ScanSummary> {
  const windowDays = opts.windowDays ?? 30;
  if (config.settings.historicalAccess !== 'full') {
    return { consented: false, scanned: 0, skipped: 0, findings: 0, bySeverity: {}, windowDays };
  }

  const gateway = resolveDataGateway(config);
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  const bySeverity: Record<string, number> = {};
  let scanned = 0;
  let skipped = 0;
  let findings = 0;
  try {
    // Hashes already in the store (and we add each one we record, so duplicate
    // messages within this same run dedup too).
    const seen = await gateway.knownContentHashes();
    for (const message of iterateHistory(opts)) {
      const hash = contentHashOf(message.text);
      if (seen.has(hash)) {
        skipped++;
        continue;
      }
      seen.add(hash);
      scanned++;
      const result = await runtime.capture(
        {
          kind: message.kind,
          sourceTool: 'claude-code',
          text: message.text,
          occurredAt: message.occurredAt,
        },
        // 'content-hash': a backfill re-run would otherwise re-record identical
        // messages under fresh event ids — the gateway uses the hash to drop
        // what it already recorded.
        { persist: 'with-findings', dedupe: 'content-hash' },
      );
      for (const finding of result.findings) {
        findings++;
        bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
        if (onHit) {
          const otherFindings = result.findings.filter((other) => other !== finding);
          const hit = buildTriageHit(message.text, finding, otherFindings);
          try {
            onHit(hit);
          } catch {
            // A misbehaving onHit sink must not abort the rest of the sweep —
            // this scan is fail-open like every other plugin surface.
          }
        }
      }
    }
  } finally {
    await runtime.close();
  }
  return { consented: true, scanned, skipped, findings, bySeverity, windowDays };
}
