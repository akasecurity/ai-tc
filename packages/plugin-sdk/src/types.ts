import type { MatchResult } from '@akasecurity/detections';
import type {
  ActionTaken,
  EventKind,
  EventMetadata,
  PolicyBundle,
  SourceTool,
} from '@akasecurity/schema';

// The only tool-specific surface each adapter implements
export interface CaptureHooks {
  onPromptSubmit?: (prompt: string) => Promise<CaptureResult>;
  onResponse?: (response: string) => Promise<void>;
  onCodeChange?: (content: string, filePath: string) => Promise<CaptureResult>;
}

// One unit of captured text handed to the runtime/handleCapture: a prompt, a
// tool field, or a tool response. Tool-agnostic — adapters extract it.
export interface CaptureInput {
  kind: EventKind;
  sourceTool: SourceTool;
  text: string;
  // When the text actually occurred, ISO-8601. Omitted on the live hook path
  // (defaults to now); the historical backfill passes the original transcript
  // timestamp so a recorded finding lands on the timeline when it really leaked.
  occurredAt?: string | undefined;
  metadata?: EventMetadata | undefined;
}

// One blocked-detections ledger row reference, as surfaced to adapters: the
// short reference the CLI approve flow resolves, plus the masked preview and
// rule of the SAME ledger row — so a block message's preview and its approve
// command can never describe different values.
export interface BlockedDetectionRef {
  reference: string;
  ruleId: string;
  maskedValue: string;
}

export interface CaptureResult {
  action: ActionTaken;
  // The (possibly redacted) text to pass through, or null if blocked
  text: string | null;
  findings: MatchResult[];
  // For a 'redact' decision: exactly the findings whose spans the rewritten
  // `text` replaced (warn/log findings in the same field are not in it). A
  // caller substituting its own rewrite — a reversible one — must cover these
  // spans and only these, or the rewrite diverges from what the policy
  // enforced.
  enforcedFindings?: MatchResult[];
  // The subset of `enforcedFindings` whose own detection chose the reversible
  // archetype (Redact & Vault). A caller with a vault available substitutes a
  // recoverable rewrite for exactly these and destroys the rest one-way; a
  // caller without one redacts all of `enforcedFindings` one-way, which is the
  // degradation Redact & Vault promises when no consent is on file.
  //
  // Always a SUBSET of enforcedFindings, never a replacement for it: a caller
  // that rewrites only these leaves every other enforced span in the clear,
  // which is the failure this pairing exists to make hard to write.
  //
  // Set on a 'redact' decision only. A block produces no enforcedFindings and
  // makes no promise about the value's fate, so custody there is not an
  // enforcement question — see the prompt surface, which decides it separately.
  reversibleFindings?: MatchResult[];
  // Blocked-detections ledger rows recorded for this capture (one per unique
  // enforced (rule, value) pair), so adapters can surface them in the block
  // message for the CLI approve flow. Absent when nothing was enforced or no
  // ledger row could be written.
  blockedReferences?: BlockedDetectionRef[];
  // The stable at-rest finding_key(s) (see finding-key.ts) this capture
  // produced — set ONLY for worktree-scan (code_change) captures, so the
  // scanner can diff them against a path's previously-open at-rest keys to
  // auto-resolve findings that no longer reproduce (see packages/scanner's
  // re-scan resolver). Absent for in-flight (prompt/response) captures, which
  // carry no finding_key. Left unset (not []) when capture() takes the
  // 'with-findings' early-return (findings.length === 0) — callers that need
  // "no findings produced" should treat an absent value as an empty list.
  findingKeys?: string[];
  // What a redact this capture could NOT carry out resolved to instead: the
  // configured `redactFallback`, because the caller declared the field
  // unrewritable (CaptureOptions.rewritable). Absent when nothing degraded.
  //
  // It exists because that difference is invisible downstream otherwise: a
  // degraded redact and a policy that genuinely said `warn` produce the same
  // `action`, and an adapter that wants to say "masking was not possible here"
  // has nothing else to key on.
  //
  // The ACTION rather than a boolean, and that is the whole of its usefulness.
  // `action` above is the worst action across every finding, so on a capture
  // that also carries a `block` policy it is `block` while the degrade resolved
  // to something weaker — and a consumer told only THAT something degraded then
  // attaches "the fallback for that case is to block" to a deny the fallback did
  // not cause, naming a setting the workspace does not have. Gate on this value
  // (`=== 'block'`), never on its presence.
  //
  // Per CAPTURE, not per finding: `rewritable` is a property of the capture, so
  // every degraded finding in it took the same fallback. Where the ceiling caps
  // them differently, this is the strongest of what they resolved to.
  redactDegradedTo?: ActionTaken;
}

// AkaPluginAdapter signature
export interface AkaPluginAdapter {
  manifest: {
    id: string;
    tool: string;
    sdkVersion: string;
  };
  capture: CaptureHooks;
}

export interface StoredPolicyBundle {
  bundle: PolicyBundle;
  fetchedAtMs: number;
}
