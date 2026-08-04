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

export function captureFinding(
  eventId: string,
  overrides: Partial<DetectedFinding> = {},
): DetectedFinding {
  return {
    id: randomUUID(),
    eventId,
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 0, end: 4 },
    maskedMatch: 'A***E',
    actionTaken: 'block',
    confidence: 0.9,
    ...overrides,
  };
}
