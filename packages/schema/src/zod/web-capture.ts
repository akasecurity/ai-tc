import { z } from 'zod';

import type { WebSourceTool } from './harness-map.ts';
import { CaptureStatusAttributes } from './meta.ts';

// The wire shapes the browser extension's native-messaging host validates, and
// the projections it turns into audit rows.
//
// Deliberately NO `.meta({ id })` on any shape here: these are host RPC inputs,
// not shapes anything refers to by name, and an orphan id leaks into the
// generated OpenAPI client (same rule LlmCallInput and ToolCallInput follow).

// How a turn's token counts were arrived at. 'site' means the site's own API
// reported them; 'estimated' means they were derived locally and must never be
// written into the priced fields; 'none' means no counts are known. Kept as a
// vocabulary rather than a boolean so the read side can render an estimate as
// an estimate instead of pricing it.
export const WebUsageSource = z.enum(['site', 'estimated', 'none']);
export type WebUsageSource = z.infer<typeof WebUsageSource>;

// Token counts as a site reported them. Every field optional: a site that
// reports only an output count contributes that and nothing else, rather than
// failing the whole exchange.
export const WebUsage = z.object({
  inputTokens: z.number().int().nonnegative().optional(),
  outputTokens: z.number().int().nonnegative().optional(),
  cacheReadInputTokens: z.number().int().nonnegative().optional(),
  cacheCreationInputTokens: z.number().int().nonnegative().optional(),
});
export type WebUsage = z.infer<typeof WebUsage>;

// One server-side tool call inside an assistant turn (a web search, a code
// execution, a connector action).
//
// `target` is the salient argument and arrives RAW. The host masks it with
// maskText before it reaches the stored attribute bag — the same treatment the
// transcript reconciler gives a tool_call target. Nothing here may be written
// to the store unmasked.
export const WebToolCall = z.object({
  toolUseId: z.string().min(1),
  toolName: z.string().min(1),
  target: z.string().optional(),
  isError: z.boolean().optional(),
  inputSize: z.number().int().nonnegative().optional(),
  outputSize: z.number().int().nonnegative().optional(),
});
export type WebToolCall = z.infer<typeof WebToolCall>;

// One assistant response observed on the network, before the host turns it into
// an `llm_call` leaf, its `tool_call` leaves, and a `response` capture.
//
// `messageId` is the natural key the deterministic row id hashes on, so it is
// required and non-empty: a blank one collapses every turn in a conversation
// onto a single row, and the llm_call writer's UPSERT-take-MAX would then
// overwrite the session's token history with its largest single turn.
export const WebExchange = z.object({
  messageId: z.string().min(1),
  startedAt: z.iso.datetime(),
  model: z.string().optional(),
  usage: WebUsage.optional(),
  usageSource: WebUsageSource,
  stopReason: z.string().optional(),
  conversationId: z.string().optional(),
  turnIndex: z.number().int().nonnegative().optional(),
  toolCalls: z.array(WebToolCall).default([]),
  // Absent when the adapter recovered no text. Capped by the caller at
  // RESPONSE_TEXT_MAX_BYTES, so a short capture is never mistaken for a short
  // reply.
  responseText: z.string().optional(),
  // The stored text is short of the reply. It does NOT say which of the two
  // ceilings on this path cut it: the caller applies its own cap on the raw
  // bytes it reads off the wire, which can be reached by a stream whose
  // recovered text stays well under RESPONSE_TEXT_MAX_BYTES, and applies that
  // one to the text. A reader cannot tell them apart, and nothing downstream
  // should branch as though it could.
  truncated: z.boolean().default(false),
});
export type WebExchange = z.infer<typeof WebExchange>;

// What the DOM enforcement path is doing in the reporting tab.
//
// The DOM path binds only when BOTH a composer and a send button resolve: an
// intercepted send is completed by clicking the site's own button, so a
// composer without one would swallow every message rather than fail open. The
// two half-resolved states are named separately because each points at a
// different selector list, and both have been seen live on one site.
//
// 'unknown' is a report carrying no opinion — a build predating this field, or
// a tab whose DOM half has not run.
export const WebEnforcementState = z.enum([
  'watching',
  'composer-only',
  'button-only',
  'unattached',
  'unknown',
]);
export type WebEnforcementState = z.infer<typeof WebEnforcementState>;

// Ceiling on the assistant text one exchange may carry to the host. Beyond it
// the text is cut and `truncated` set — the scan then runs on what was kept.
export const RESPONSE_TEXT_MAX_BYTES = 2 * 1024 * 1024;

// What one tab's interception is actually doing, reported on change and at
// session end.
//
// `patched` says the tap installed; `live` says it has parsed a real exchange;
// `blind` says the DOM path saw sends the network path never did — which is the
// only one of the three that can be true while the other two look healthy, and
// the reason installation alone is not treated as proof of visibility.
export const WebCaptureStatus = z.object({
  patched: z.boolean(),
  live: z.boolean(),
  blind: z.boolean(),
  sendsSeenDom: z.number().int().nonnegative(),
  exchangesSeenNet: z.number().int().nonnegative(),
  parseFailures: z.number().int().nonnegative(),
  unparsedBodies: z.number().int().nonnegative(),
  // The adapter-declared JSON key paths that were absent from a real payload —
  // the earliest signal that a site's contract moved.
  shapeMisses: z.array(z.string()).default([]),
  // How many `kind: 'conversation'` endpoints the reporting tab's adapter
  // compiled. Zero means this build declares none for the site, so observing
  // nothing is the design rather than a fault — the one fact that separates a
  // site nobody has surveyed yet from one whose contract moved. Defaulted so a
  // build predating the field is read as declaring nothing rather than refused.
  conversationEndpoints: z.number().int().nonnegative().default(0),
  // What the DOM enforcement path is doing, which none of the counters above
  // can say: `sendsSeenDom` rises only once a send has COMPLETED, so a tab
  // whose watcher never bound reports zero exactly like a tab nobody typed in.
  // Defaulted to 'unknown' rather than 'watching' so a status from a build
  // predating the field is not read as reporting a healthy one.
  enforcement: WebEnforcementState.default('unknown'),
});
export type WebCaptureStatus = z.infer<typeof WebCaptureStatus>;

/**
 * Whether a report says anything about the site's turn path.
 *
 * False for a tab that installed, has conversation endpoints to watch, and has
 * seen no exchange, no fault and no missing field — a page that has just
 * loaded, or one whose only activity so far is DOM sends the network path has
 * not yet given up on. Such a report carries no verdict about the site.
 *
 * A build that declares no endpoints, and a tab whose tap did not install, both
 * count as saying something: each is a statement about this build rather than
 * an absence of evidence.
 */
export function webCaptureStatusObservedTurnPath(status: WebCaptureStatus): boolean {
  if (!status.patched) return true;
  if (status.conversationEndpoints === 0) return true;
  return (
    status.blind ||
    status.shapeMisses.length > 0 ||
    status.parseFailures > 0 ||
    status.unparsedBodies > 0 ||
    status.exchangesSeenNet > 0
  );
}

/**
 * The report a surface should show, from candidates in preference order
 * (newest first).
 *
 * The first candidate that observed the turn path wins, so a run of
 * watching-only reports ahead of it does not replace it. Without that, the
 * newest report always wins and a page load — which relays a fresh
 * nothing-seen-yet report the moment the tap says it patched — silently
 * replaces the report that told the user to reload the tab, before anything
 * has re-tested what was wrong. A report that DID observe the turn path
 * replaces it immediately, so a site whose next turn is captured clears at
 * once.
 *
 * With no such candidate the newest is returned, so a site that has only ever
 * been watched still shows its newest state.
 */
export function pickReportedCaptureStatus<T extends { status: WebCaptureStatus }>(
  candidates: readonly T[],
): T | undefined {
  return candidates.find((c) => webCaptureStatusObservedTurnPath(c.status)) ?? candidates[0];
}

/**
 * How far back a read looks for a site's reported status.
 *
 * The other read-policy decision about these rows, and it sits beside the
 * picker for that reason. A status is a report about what one tab saw at one
 * instant, and nothing ever supersedes it except a later report from the same
 * site — so a store keeps the last one for ever, and the browser extension is
 * its only writer. Unbounded, an extension that was uninstalled a year ago
 * goes on making a live-sounding claim ("reload the tab") about a tab nothing
 * is watching, and no later report can arrive to clear it.
 *
 * Bounding the read is what makes the claim decay instead: past this window a
 * site reads as `unreported` — nobody has confirmed anything recently — which
 * is what the evidence actually supports. It also bounds the SQL, whose
 * per-site seek otherwise walks every `capture_status` row ever written when
 * the site it asks for has none (`audit_events` has no retention policy).
 *
 * Thirty days, matching the dashboard's own default range.
 */
export const CAPTURE_STATUS_RECENCY_MS = 30 * 24 * 60 * 60 * 1000;

/** `CAPTURE_STATUS_RECENCY_MS` in whole days, for copy that names the window. */
export const CAPTURE_STATUS_RECENCY_DAYS = CAPTURE_STATUS_RECENCY_MS / (24 * 60 * 60 * 1000);

/** One site's reported status, as the local store holds it. */
export interface StoredCaptureStatus {
  tool: WebSourceTool;
  /** When the host received it, ISO-8601 — the row's own `started_at`. */
  observedAt: string;
  status: WebCaptureStatus;
}

// WebCaptureStatus <-> the snake_case CaptureStatusAttributes bag an
// audit_events row carries. `source_tool` rides the canonical key so the
// generated column (migration 0025) can name it directly, exactly as
// toCaptureAttributes/toCaptureDefinitionInput do for the capture-grain bags
// in local.ts.
export function toCaptureStatusAttributes(
  status: WebCaptureStatus,
  tool: WebSourceTool,
): CaptureStatusAttributes {
  return {
    source_tool: tool,
    patched: status.patched,
    live: status.live,
    blind: status.blind,
    sends_seen_dom: status.sendsSeenDom,
    exchanges_seen_net: status.exchangesSeenNet,
    parse_failures: status.parseFailures,
    unparsed_bodies: status.unparsedBodies,
    shape_misses: status.shapeMisses,
    conversation_endpoints: status.conversationEndpoints,
    enforcement: status.enforcement,
  };
}

/** `null` for a bag that is not a status this version can read. */
export function fromCaptureStatusAttributes(bag: unknown): WebCaptureStatus | null {
  const parsedBag = CaptureStatusAttributes.safeParse(bag);
  if (!parsedBag.success) return null;
  const b = parsedBag.data;
  const parsedStatus = WebCaptureStatus.safeParse({
    patched: b.patched,
    live: b.live,
    blind: b.blind,
    sendsSeenDom: b.sends_seen_dom,
    exchangesSeenNet: b.exchanges_seen_net,
    parseFailures: b.parse_failures,
    unparsedBodies: b.unparsed_bodies,
    shapeMisses: b.shape_misses,
    conversationEndpoints: b.conversation_endpoints,
    enforcement: b.enforcement,
  });
  return parsedStatus.success ? parsedStatus.data : null;
}
