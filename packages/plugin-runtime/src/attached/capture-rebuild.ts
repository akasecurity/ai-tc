import { captureWireId } from '@akasecurity/persistence';
import type { AuditEventRow, EventMetadata } from '@akasecurity/schema';
import { EventKind, IngestEvent, SourceTool } from '@akasecurity/schema';

/**
 * One stored capture row → the wire event the outbox owes the deployment.
 *
 * The sibling of `rebuildAuditEvent`, and the inverse of it in the one respect
 * that matters: THIS LANE CARRIES `content`. That is not a relaxation of the
 * rule over there, it is the reason the two lanes exist. A structural row goes
 * to /v1/audit-events, which persists `content` verbatim, so that rebuilder
 * drops it; a capture goes to /v1/events, which scans `content` in memory and
 * stores NULL. Sending a capture down the structural lane would strip the text
 * that is the whole point AND write every other field to disk for keeps.
 *
 * PURE and offline: it reads nothing, sends nothing, and decides only whether a
 * row can be expressed on the wire at all. Returns undefined for one that
 * cannot, so a malformed row becomes a counted, permanent skip rather than a
 * request refused for ever — same contract as the structural rebuilder.
 *
 * THE ID IS REPRODUCED, NOT MINTED, and that is what makes a retry safe. The
 * live path sent this capture under `captureWireId(sessionId, contentHash,
 * filePath)`; the row is keyed on the same tuple by `captureId`, so the same
 * three fields are recoverable here and yield the same uuid. The receiver's
 * id-dedup then recognises a redelivery instead of writing a second copy —
 * which is exactly what happens when a stamp was lost after a successful
 * forward. Minting a fresh id here would turn every such row into a duplicate.
 *
 * `sessionId` comes off the ROW COLUMN rather than the attributes bag, because
 * that is where recordCapture put it: `rootSessionId: sessionId`. The bag never
 * carried it — a capture's session is expressed as a foreign key, not an
 * attribute — so reading `attributes.session_id` would silently derive every id
 * against `null` and duplicate the entire backlog.
 */
export function rebuildCapture(row: AuditEventRow): IngestEvent | undefined {
  // Only the capture grain belongs on this lane. A structural row reaching here
  // means a caller crossed the lanes, and sending it to /v1/events would file a
  // session or tool_call under a kind the receiver reads as captured text.
  const kind = EventKind.safeParse(row.eventType);
  if (!kind.success) return undefined;

  // `content` and `contentHash` are REQUIRED on the wire and nullable in the
  // table (every structural row leaves them null, and a capture written by a
  // much older build may too). A row missing either cannot be expressed, and
  // no retry will change that.
  // `?? null` on the way in: AuditEventRow is an INSERT type, so a nullable
  // column is `T | null | undefined` and the two absent forms must collapse
  // before anything downstream can treat one of them as a value.
  const content = row.content ?? null;
  const contentHash = row.contentHash ?? null;
  const rootSessionId = row.rootSessionId ?? null;
  if (content === null || contentHash === null) return undefined;

  // Converted before anything else that can fail, because this is the field
  // whose conversion THROWS: `new Date(NaN).toISOString()` raises rather than
  // returning an invalid string, and one damaged timestamp would take the whole
  // drain down instead of becoming a single counted skip.
  const occurredAt = isoOrUndefined(row.startedAt);
  if (occurredAt === undefined) return undefined;

  const attributes = parseAttributes(row.attributes ?? null);
  // Required on the wire, and it identifies which harness produced the row, so
  // there is nothing safe to default it to. An unparseable value is a skip.
  const sourceTool = SourceTool.safeParse(attributes.source_tool);
  if (!sourceTool.success) return undefined;

  const filePath = stringOrUndefined(attributes.file_path);
  const metadata: EventMetadata = {
    ...(rootSessionId === null ? {} : { sessionId: rootSessionId }),
    ...(filePath === undefined ? {} : { filePath }),
    ...pick(attributes, {
      repo: 'repo',
      toolName: 'tool_name',
      model: 'model',
      traceId: 'trace_id',
      correlationId: 'correlation_id',
    }),
    ...(typeof attributes.gitignored === 'boolean' ? { gitignored: attributes.gitignored } : {}),
    ...(typeof attributes.whole_file === 'boolean' ? { wholeFile: attributes.whole_file } : {}),
    ...(typeof attributes.turn_index === 'number' ? { turnIndex: attributes.turn_index } : {}),
    // inspectionMs is DELIBERATELY not carried. It measures latency a live host
    // session actually waited on, and a row being drained hours later is not
    // that; the field's own contract says a replay leaves it absent rather than
    // reporting a number no session experienced.
  };

  // VALIDATED, not merely assembled, and this is the difference between a row
  // that is skipped here and one that retires the whole lane.
  //
  // Several attribute values are constrained on the wire in ways the local
  // column is not: `correlationId` is a uuid and `traceId` is 32 hex chars,
  // while the attributes bag is free-form JSON that older builds, a migration,
  // or a hand edit can have left anything in. An event that fails those
  // constraints is refused by the deployment with a 400 — and because the drain
  // reads the head of the unstamped set with no cursor, that same row would be
  // rebuilt into the same rejected body on every pass, for ever, taking every
  // capture behind it down with it.
  //
  // So the check happens HERE, where the answer is "this row can never be
  // expressed" and the caller already knows what to do with that: skip it once
  // and move on. Returning the PARSED value rather than the input also makes the
  // declared return type honest — what leaves this function has been through the
  // schema, not merely shaped like it.
  const parsed = IngestEvent.safeParse({
    id: captureWireId(rootSessionId, contentHash, filePath ?? null),
    sourceTool: sourceTool.data,
    kind: kind.data,
    occurredAt,
    contentHash,
    content,
    metadata,
  });
  return parsed.success ? parsed.data : undefined;
}

function isoOrUndefined(epochMs: number): string | undefined {
  if (!Number.isFinite(epochMs)) return undefined;
  const iso = new Date(epochMs);
  return Number.isNaN(iso.getTime()) ? undefined : iso.toISOString();
}

/** The attributes bag, or an empty one — a damaged bag costs metadata, not the row. */
function parseAttributes(raw: string | null): Record<string, unknown> {
  if (raw === null) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** Copy the string-valued attributes that map 1:1, omitting anything absent. */
function pick(
  attributes: Record<string, unknown>,
  mapping: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [wire, column] of Object.entries(mapping)) {
    const value = stringOrUndefined(attributes[column]);
    if (value !== undefined) out[wire] = value;
  }
  return out;
}
