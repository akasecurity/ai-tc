/**
 * The minimal `recordCapture` pair — one event and one already-masked finding.
 *
 * A fault test cares about whether a write landed, not about what was in it, so
 * these carry the smallest valid shape rather than a realistic one. Both mint a
 * fresh id and `contentHash` per call: `recordCapture` is content-addressed on
 * (sessionId, contentHash, filePath), so reusing either would collapse two
 * captures onto one audit row and make a dropped write indistinguishable from a
 * deduped one.
 *
 * `maskedMatch` is a masked preview by contract — the SDK masks before calling —
 * so nothing here is a raw value, and it matches no rule.
 */
import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, IngestEvent } from '@akasecurity/schema';

export function captureEvent(overrides: Partial<IngestEvent> = {}): IngestEvent {
  return {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date().toISOString(),
    contentHash: `hash-${randomUUID()}`,
    content: 'a prompt worth recording',
    ...overrides,
  };
}

/**
 * `distinct` defaults to a fresh value per call, and that default is
 * load-bearing rather than tidy.
 *
 * `maskedMatch` is half of the FINDING-level session dedup key —
 * `recordCapture` skips a finding when `(ruleId, maskedMatch, sessionId)` has
 * already been seen (`database.ts`, `isSessionDuplicate`). A shared constant
 * would therefore make a second capture in the same session land as zero rows
 * **by design**, which is indistinguishable from the write having been dropped:
 * every "the event is gone" assertion in `test/faults/` would pass whether or
 * not the fault did anything. That needs only a caller setting
 * `metadata.sessionId` — one field — so the value varies here instead of
 * relying on nobody adding it.
 *
 * Pass an explicit `distinct` to exercise the dedup on purpose.
 */
export function captureFinding(
  eventId: string,
  overrides: Partial<DetectedFinding> = {},
  distinct: string = randomUUID().slice(0, 8),
): DetectedFinding {
  return {
    id: randomUUID(),
    eventId,
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 0, end: 4 },
    maskedMatch: `A***${distinct}`,
    actionTaken: 'block',
    confidence: 0.9,
    ...overrides,
  };
}

/**
 * How many CAPTURES the store holds, which is not how many `audit_events` rows
 * it holds.
 *
 * `ensureSessionRoot` plants one `event_type = 'session'` row per session before
 * the capture's own row can reference it, so counting the table counts those
 * structural roots too and every "the write landed" assertion reads one high.
 * Stated as "not a root" rather than "is a prompt": pinning a `kind` here would
 * make a test that captures some other kind read as loss.
 */
export function captureCount(db: DatabaseSync): number {
  return (
    db.prepare("SELECT count(*) AS n FROM audit_events WHERE event_type != 'session'").get() as {
      n: number;
    }
  ).n;
}
