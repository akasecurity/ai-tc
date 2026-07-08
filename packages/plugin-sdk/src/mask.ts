import { getLoadedRules, maskMatch, redact, scan } from '@akasecurity/detections';
import type { DetectionCategory, Severity, Span } from '@akasecurity/schema';

import { registerBundledPacks } from './rule-packs.ts';

// registerPack is keyed by pack id, so re-registering just overwrites (idempotent);
// the flag only avoids re-parsing the bundled JSON on every call.
let packsReady = false;
// A registration that THREW (a malformed bundled pack) is latched here so we neither
// re-pay the doomed parse on every call NOR fall through to an empty ruleset — an
// empty ruleset would match nothing and leak the raw target (fail-OPEN). Once latched,
// `scanText` short-circuits to a blanket `[REDACTED]` (fail-secure). Note this is
// registration-only: a per-input `scan()` failure is caught below and redacts just
// that one input, without poisoning every subsequent call.
let packsFailed = false;

// Register the bundled packs exactly once. Returns whether the pack registry is usable;
// a failed registration is remembered (see `packsFailed`) so callers stay fail-secure.
function ensureBundledPacks(): boolean {
  if (packsReady) return true;
  if (packsFailed) return false;
  try {
    registerBundledPacks();
    packsReady = true;
    return true;
  } catch {
    packsFailed = true;
    return false;
  }
}

// One detected secret, enriched with the rule identity the reconciler needs to
// write an `inspection_finding` (Layer 2b): the rule's name + version (for the
// inspection_definition), the category/severity, the span, the MASKED match, and
// the confidence. The raw matched value never leaves this module — only its mask.
export interface ScanFinding {
  ruleId: string;
  ruleName: string;
  ruleVersion: string;
  category: DetectionCategory;
  severity: Severity;
  span: Span;
  maskedMatch: string;
  confidence: number;
}

// Scan `text` with the bundled detection packs, returning BOTH the redacted string
// and the enriched findings in ONE pass — the reconciler needs the masked target
// (Layer 2a) and the per-secret findings (Layer 2b) from the same scan.
//
// Ruleset is the baseline: whatever is in the GLOBAL `@akasecurity/detections`
// pack registry, which here is just the bundled packs (an implicit coupling:
// it holds only because nothing else registers packs into that global in the
// reconciler process).
//
// FAIL-SECURE (unlike the fail-OPEN hook path): if the scan throws — or the bundled
// packs can't be loaded at all — returning the raw text would leak the very secret we
// set out to mask, so we return a blanket `[REDACTED]` and NO findings. A masking bug
// degrades to over-redaction, never a leak.
export function scanText(text: string): { masked: string; findings: ScanFinding[] } {
  // Packs unusable (a malformed bundled pack) → fail-secure without re-paying the parse.
  if (!ensureBundledPacks()) return { masked: '[REDACTED]', findings: [] };
  try {
    const rules = getLoadedRules();
    const matches = scan(text, rules);
    if (matches.length === 0) return { masked: text, findings: [] };

    const byId = new Map(rules.map((r) => [r.id, r]));
    const findings: ScanFinding[] = matches.map((m) => {
      const rule = byId.get(m.ruleId);
      return {
        ruleId: m.ruleId,
        ruleName: rule?.name ?? m.ruleId,
        ruleVersion: String(rule?.specVersion ?? 1),
        category: m.category,
        severity: m.severity,
        span: m.span,
        maskedMatch: maskMatch(m.rawMatch),
        confidence: m.confidence,
      };
    });
    return { masked: redact(text, matches), findings };
  } catch {
    return { masked: '[REDACTED]', findings: [] };
  }
}

/**
 * Redact any secrets the bundled detection packs find in `text`, returning the
 * masked string. The masking primitive the transcript reconciler applies to a
 * captured tool "target" before it is persisted, so a secret in e.g. a Bash command
 * never lands in the audit store. Delegates to {@link scanText} (same fail-secure
 * behavior); use `scanText` directly when you also need the findings.
 */
export function maskText(text: string): string {
  return scanText(text).masked;
}
