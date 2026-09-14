import { z } from 'zod';

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
  // RESPONSE_TEXT_MAX_BYTES; `truncated` records that the cap was reached, so a
  // short capture is never mistaken for a short reply.
  responseText: z.string().optional(),
  truncated: z.boolean().default(false),
});
export type WebExchange = z.infer<typeof WebExchange>;

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
});
export type WebCaptureStatus = z.infer<typeof WebCaptureStatus>;
