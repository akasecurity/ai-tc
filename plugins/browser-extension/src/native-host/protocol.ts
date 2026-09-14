import type { BlockedDetectionRef, WebCaptureState } from '@akasecurity/plugin-sdk';
import type { ActionTaken, WebEnforcementState, WebSourceTool } from '@akasecurity/schema';
import {
  EventKind,
  WebCaptureStatus,
  WebExchange,
  WebSourceTool as WebSourceToolEnum,
} from '@akasecurity/schema';

// The web chat UIs this native host serves. The SET now lives in
// @akasecurity/schema as a `SourceTool.extract([...])` narrowing, so the CLI's
// status surface enumerates the same sites without a second copy of the list.
const WEB_SOURCE_TOOLS = WebSourceToolEnum.options;
export type { WebEnforcementState, WebSourceTool } from '@akasecurity/schema';
// Re-exported so the popup — which cannot import @akasecurity/plugin-sdk in a
// browser bundle — can still type its own state handling against the real
// vocabulary. A type import erases, so this costs the bundle nothing.
export type { WebCaptureState } from '@akasecurity/plugin-sdk';

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

// One assistant turn as the isolated-world bridge parsed it off the network.
// Carries what the DOM path cannot see: the model, the token counts the site
// itself reported, the server-side tool calls, and the response text.
//
// `exchange` is a `WebExchange` on the wire. This interface is what
// background.ts relays and is not a substitute for parsing the payload where
// it lands — `isHostRequest` below re-validates with `WebExchange.safeParse`
// before this host ever acts on one.
export interface ExchangeRequest {
  type: 'exchange';
  requestId: string;
  sessionId: string;
  tool: WebSourceTool;
  exchange: WebExchange;
}

// What one tab's interception is actually doing. Reported so a tap that
// installed and sees nothing is distinguishable from a tab nobody used —
// installation alone is not visibility.
export interface CaptureStatusRequest {
  type: 'capture_status';
  requestId: string;
  sessionId: string;
  tool: WebSourceTool;
  status: WebCaptureStatus;
}

/** What every web chat site's capture is doing, for the popup. */
export interface CaptureStateRequest {
  type: 'capture_state';
  requestId: string;
}

export interface PingRequest {
  type: 'ping';
  requestId: string;
}

export interface HealthRequest {
  type: 'health';
  requestId: string;
}

export type HostRequest =
  | SessionStartRequest
  | CaptureRequest
  | ExchangeRequest
  | CaptureStatusRequest
  | CaptureStateRequest
  | PingRequest
  | HealthRequest;

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

export interface ExchangeResponse {
  type: 'exchange';
  requestId: string;
  ok: true;
  // Whether this host was permitted to record the exchange AND could key it.
  // False means nothing was written and nothing will be; `skipped` says which.
  accepted: boolean;
  skipped?: 'no-consent' | 'unkeyable';
  // How many leaves this host SUBMITTED for this exchange — not a row count.
  // Both leaf ids are content-addressed, so a re-observed turn collapses onto
  // the rows already there (INSERT OR IGNORE for a tool call, an
  // UPSERT-take-MAX for an llm call); and every gateway write on this path is
  // fail-open, so a dropped write is not reflected here either.
  llmCalls: number;
  toolCalls: number;
  // The response capture's decision. Absent when no reply text was captured
  // (no responseText, or the stored `responses` mode is 'never'). INFORMATIONAL:
  // the reply has already been rendered, so nothing is enforced on it here.
  responseAction?: ActionTaken;
  ruleIds: string[];
}

export interface CaptureStatusResponse {
  type: 'capture_status';
  requestId: string;
  ok: true;
  accepted: boolean;
  skipped?: 'no-consent';
}

export interface CaptureStateResponse {
  type: 'capture_state';
  requestId: string;
  ok: true;
  // False when no valid web-chat capture consent is recorded: nothing is being
  // observed or stored, which is a different answer from "nothing was seen".
  consented: boolean;
  sites: {
    tool: WebSourceTool;
    state: WebCaptureState;
    // What the DOM enforcement half reported about itself. Carried beside
    // `state` rather than folded into it: that vocabulary describes the NETWORK
    // path, and a tab can be reading the site perfectly while enforcing
    // nothing. Absent when this site has never reported.
    enforcement?: WebEnforcementState;
    // Absent when this site has never reported.
    observedAt?: string;
  }[];
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
  | SessionStartResponse
  | CaptureResponse
  | ExchangeResponse
  | CaptureStatusResponse
  | CaptureStateResponse
  | PingResponse
  | HealthResponse
  | ErrorResponse;

function isWebSourceTool(value: unknown): value is WebSourceTool {
  return (WEB_SOURCE_TOOLS as readonly unknown[]).includes(value);
}

// `kind` is handed to handleCapture and written straight through to the store's
// event_type. EventKind is used as a TYPE on that whole path — events.ts and
// types.ts both `import type` it, and there is no parse before the insert — so
// nothing downstream re-checks it. A bare typeof-string test therefore let any
// string land as an orphan row: written, then invisible to every capture-kind
// read, since those constrain to the four real kinds. This is the only runtime
// validator standing on that boundary, so it reads the enum itself. Type-only
// importers (messaging.ts, providers/types.ts) keep this out of the content
// -script bundle.
function isEventKind(value: unknown): value is EventKind {
  return typeof value === 'string' && (EventKind.options as readonly string[]).includes(value);
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
        isEventKind(v.kind) &&
        typeof v.text === 'string'
      );
    // A successful safeParse proves the payload is ACCEPTABLE, not that the
    // narrowed object carries the schema's defaults — `toolCalls` and
    // `truncated` are `.default(...)`, and a guard does not rewrite its input.
    // The handler re-parses and reads `parsed.data`; nothing may read
    // `request.exchange` / `request.status` directly.
    case 'exchange':
      return (
        typeof v.sessionId === 'string' &&
        isWebSourceTool(v.tool) &&
        WebExchange.safeParse(v.exchange).success
      );
    case 'capture_status':
      return (
        typeof v.sessionId === 'string' &&
        isWebSourceTool(v.tool) &&
        WebCaptureStatus.safeParse(v.status).success
      );
    case 'capture_state':
    case 'ping':
    case 'health':
      return true;
    default:
      // A request type this contract does not define at all (extension/host
      // version skew, or a stray value). Refused here so runHost answers it
      // with 'unrecognized request' rather than routing it to handleRequest.
      return false;
  }
}
