import { createHash, randomUUID } from 'node:crypto';

import type { EventKind, EventMetadata, IngestEvent, SourceTool } from '@akasecurity/schema';

export interface BuildEventInput {
  kind: EventKind;
  sourceTool: SourceTool;
  content: string;
  // Hash of the ORIGINAL text, supplied when `content` is a redacted-for-storage
  // copy (secrets-at-rest): the row keeps a fingerprint of the real input for
  // dedup/sync while never persisting the secret. Defaults to hash(content).
  contentHash?: string | undefined;
  // When the event occurred, ISO-8601. Defaults to now (the live hook path); the
  // historical backfill passes the original transcript timestamp.
  occurredAt?: string | undefined;
  metadata?: EventMetadata | undefined;
}

// The canonical content fingerprint: sha256 hex of the ORIGINAL text. One
// definition so the live capture path, the stored event `contentHash`, and the
// historical backfill's dedup all agree — if these diverged, the backfill's
// dedup set would stop matching stored hashes and silently re-create findings.
export function contentHashOf(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

// One place to construct a schema-valid IngestEvent so adapters never
// hand-roll ids, timestamps, or hashes.
export function buildIngestEvent(input: BuildEventInput): IngestEvent {
  return {
    id: randomUUID(),
    sourceTool: input.sourceTool,
    kind: input.kind,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
    contentHash: input.contentHash ?? contentHashOf(input.content),
    content: input.content,
    // Stamp a per-capture correlation id so a recorded event can be tied back to
    // its origin once synced — the lightweight plugin "trace propagation" (no OTel
    // SDK boot in the fail-open hook path). Preserve any id the caller already set.
    metadata: {
      ...input.metadata,
      correlationId: input.metadata?.correlationId ?? randomUUID(),
    },
  };
}
