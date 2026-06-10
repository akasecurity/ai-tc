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
