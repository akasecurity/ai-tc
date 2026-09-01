import type { HistorySyncInspectionRow } from '@akasecurity/persistence';
import type { AuditEventRow, RecordAuditEventRequest } from '@akasecurity/schema';
import {
  epochMillisToIso,
  RecordAuditEventRequest as RecordAuditEventRequestSchema,
  ToolCallInspection,
} from '@akasecurity/schema';

/**
 * The rule-version namespace the receiving side mints for itself.
 *
 * An inspection claiming it is refused by the request shape, which would cost
 * the whole event. Dropping the one inspection keeps the tool call.
 */
const CAPTURE_VERSION_PREFIX = 'capture/';

/**
 * Rebuild one stored row into the request the live path would have sent.
 *
 * PURE, and offline: it reads nothing, sends nothing, and decides only whether
 * a row can be expressed on the wire at all.
 *
 * Returns undefined for a row that cannot — a years-old store is the work of
 * many writers, and a row one of them left half-shaped must become a counted,
 * permanent skip rather than a request that is refused for ever.
 *
 * Three things are deliberately dropped:
 *
 *   content       Never sent by this lane. The field exists on the wire shape
 *                 and a stored row may carry one, so this is the one place the
 *                 omission has to be deliberate rather than incidental.
 *
 *   inventory ids hostId, harnessId and sourceProjectId are a different id space
 *                 by construction — content-addressed locally, re-scoped on the
 *                 receiving side — so a local id names a row that does not exist
 *                 there. They are real foreign keys, so sending one wrong costs
 *                 the whole session; sending none costs one degraded join. What
 *                 a reader actually sees — harness, cwd, repo, branch — lives in
 *                 attributes, which does travel.
 *
 *   contentHash   Not sent by the live path either, so it stays off this one:
 *                 the two lanes have to produce the same shape or the receiving
 *                 side's idempotency stops being a single behaviour.
 */
export function rebuildAuditEvent(
  row: AuditEventRow,
  inspections: readonly HistorySyncInspectionRow[] = [],
): RecordAuditEventRequest | undefined {
  // Converted before anything else, because this is the one field whose
  // conversion can THROW: `new Date(NaN).toISOString()` raises rather than
  // returning an invalid string, and a stored row with a damaged timestamp would
  // otherwise take the whole drain down instead of becoming one counted skip.
  const startedAt = isoOrUndefined(row.startedAt);
  if (startedAt === undefined) return undefined;
  const endedAt = isoOrUndefined(row.endedAt);

  const candidate = {
    id: row.id,
    eventType: row.eventType,
    startedAt,
    ...(endedAt === undefined ? {} : { endedAt }),
    ...(row.parentId === null || row.parentId === undefined ? {} : { parentId: row.parentId }),
    ...(row.rootSessionId === null || row.rootSessionId === undefined
      ? {}
      : { rootSessionId: row.rootSessionId }),
    ...(row.severity === null || row.severity === undefined ? {} : { severity: row.severity }),
    ...(row.priority === null || row.priority === undefined ? {} : { priority: row.priority }),
    ...attributesOf(row.attributes),
    inspections: inspections
      .filter((i) => !i.ruleVersion.startsWith(CAPTURE_VERSION_PREFIX))
      .map((i) =>
        ToolCallInspection.safeParse({
          ruleId: i.ruleId,
          ruleName: i.ruleName,
          ruleVersion: i.ruleVersion,
          category: i.category,
          severity: i.severity,
          span: { start: i.spanStart, end: i.spanEnd },
          maskedMatch: i.maskedMatch,
          actionTaken: i.actionTaken,
          confidence: i.confidence,
        }),
      )
      // EACH ONE ON ITS OWN, for the same reason the reserved namespace is
      // filtered above: one stored detection the current shape will not accept —
      // a category or action from a retired enum, a confidence an older writer
      // put on a 0-100 scale — would otherwise cost the whole tool call, which
      // is then stamped permanently skipped for a child row's defect.
      .filter((parsed) => parsed.success)
      .map((parsed) => parsed.data),
  };

  const parsed = RecordAuditEventRequestSchema.safeParse(candidate);
  return parsed.success ? parsed.data : undefined;
}

/**
 * The largest magnitude `new Date(ms)` represents. Beyond it `toISOString()`
 * raises rather than returning anything, which is the ECMA-262 bound on a time
 * value, not a Node detail.
 */
const MAX_EPOCH_MS = 8_640_000_000_000_000;

/**
 * An epoch-millis column as an ISO string, or undefined when it is not an
 * instant at all — absent, not a number, or outside the range a Date can hold.
 *
 * THE RANGE CHECK IS NOT REDUNDANT with the finiteness one. A writer that
 * stamped microseconds instead of milliseconds produces something like 1.7e18:
 * finite, and far outside what `toISOString()` will render. Letting that throw
 * would not cost one row — the throw leaves the rebuild, leaves the drain, and
 * is swallowed by the pass's outer catch, which returns "no attempt made". The
 * row is never marked skipped, so every later pass reaches it and dies the same
 * way, no progress is ever recorded, and every row ordered behind it in the
 * session is stranded. Returning undefined is what makes it the one counted skip
 * this module's contract promises.
 */
function isoOrUndefined(ms: number | null | undefined): string | undefined {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return undefined;
  if (Math.abs(ms) > MAX_EPOCH_MS) return undefined;
  return epochMillisToIso(ms);
}

/**
 * The stored attributes bag, or nothing.
 *
 * Stored as a JSON string, so a damaged one is a real possibility. An
 * unparseable bag costs the attributes rather than the event: the event's
 * structure is what this lane is for, and the bag is what decorates it.
 * A non-object parse (a bare string, an array, null) is treated the same way.
 */
function attributesOf(raw: string | null | undefined): { attributes?: Record<string, unknown> } {
  if (raw === null || raw === undefined || raw === '') return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {};
    return { attributes: parsed as Record<string, unknown> };
  } catch {
    return {};
  }
}
