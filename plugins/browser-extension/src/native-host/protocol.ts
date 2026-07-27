import type { BlockedDetectionRef } from '@akasecurity/plugin-sdk';
import type { ActionTaken, EventKind } from '@akasecurity/schema';

// The web chat UIs this native host serves. Kept as a local literal union
// (not @akasecurity/schema's SourceTool) because it is the narrower set this
// RPC contract actually accepts — content.ts's provider registry is the one
// place new web providers (Gemini, DeepSeek, T3 Chat, …) get added, and each
// addition widens this union + WEB_TOOL_TO_SOURCE in host.ts together.
export type WebSourceTool = 'chatgpt' | 'claude-ai';

export interface SessionStartRequest {
  type: 'session_start';
  requestId: string;
  sessionId: string;
  tool: WebSourceTool;
  // The tab's location.hostname at session start (e.g. "chatgpt.com" vs the
  // legacy "chat.openai.com") — a descriptive, non-hashed fact snapshotted
  // onto the session root's own attributes, same role as Codex's
  // harnessInterface (see plugins/codex/src/hooks/session-start.ts).
  hostname: string;
}

export interface CaptureRequest {
  type: 'capture';
  requestId: string;
  sessionId: string;
  tool: WebSourceTool;
  kind: EventKind;
  text: string;
}

export interface PingRequest {
  type: 'ping';
  requestId: string;
}

export interface HealthRequest {
  type: 'health';
  requestId: string;
}

export type HostRequest = SessionStartRequest | CaptureRequest | PingRequest | HealthRequest;

export interface SessionStartResponse {
  type: 'session_start';
  requestId: string;
  ok: true;
}

export interface CaptureResponse {
  type: 'capture';
  requestId: string;
  ok: true;
  action: ActionTaken;
  // Present ONLY when the content script needs it: the masked text to write
  // back into the composer when action is 'redact', or null when action is
  // 'block' (nothing should be sent). Omitted for every other action — the
  // composer already holds the text, and echoing a large prompt back through
  // the host→Chrome pipe (which Chrome caps at 1 MB per message) would risk
  // killing the port for no benefit.
  text?: string | null;
  ruleIds: string[];
  blockedReferences?: BlockedDetectionRef[];
}

export interface PingResponse {
  type: 'ping';
  requestId: string;
  ok: true;
  dbPath: string;
  onboarded: boolean;
}

// Whole-store totals (not scoped to this extension's own captures) — the
// same @akasecurity/schema HealthSummary the CLI's `aka:health` surface
// reads, via DataGateway.healthSummary(). Good enough for an at-a-glance
// popup stat; a session/tab-scoped count would need its own query.
export interface HealthResponse {
  type: 'health';
  requestId: string;
  ok: true;
  findings: number;
  bySeverity: { critical: number; high: number; medium: number; low: number };
}

export interface ErrorResponse {
  type: 'error';
  requestId: string | undefined;
  ok: false;
  message: string;
}

export type HostResponse =
  SessionStartResponse | CaptureResponse | PingResponse | HealthResponse | ErrorResponse;

function isWebSourceTool(value: unknown): value is WebSourceTool {
  return value === 'chatgpt' || value === 'claude-ai';
}

// Runtime narrowing for whatever background.ts sends over the wire — mirrors
// the parseJson/getString style the CLI-hook packages already use for their
// own stdin payloads (plugins/codex/src/hooks/shared.ts) rather than pulling
// in a Zod dependency for a contract confined to this one package's own RPC.
export function isHostRequest(value: unknown): value is HostRequest {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  if (typeof v.requestId !== 'string') return false;
  switch (v.type) {
    case 'session_start':
      return (
        typeof v.sessionId === 'string' && isWebSourceTool(v.tool) && typeof v.hostname === 'string'
      );
    case 'capture':
      return (
        typeof v.sessionId === 'string' &&
        isWebSourceTool(v.tool) &&
        typeof v.kind === 'string' &&
        typeof v.text === 'string'
      );
    case 'ping':
    case 'health':
      return true;
    default:
      return false;
  }
}
