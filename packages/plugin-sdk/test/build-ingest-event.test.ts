import { captureId, captureWireId } from '@akasecurity/persistence';
import { IngestEvent } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { buildIngestEvent, contentHashOf } from '../src/events.ts';

// `buildIngestEvent` mints the id a capture is SENT under. It used to be a
// `randomUUID()` that was discarded, which meant a stored capture could never be
// matched to what was sent. It is now derived from the same tuple the stored row
// is keyed on, so the row can always reproduce it.
describe('buildIngestEvent — a derived, reproducible capture id', () => {
  const base = {
    kind: 'prompt',
    sourceTool: 'claude-code',
    content: 'hello world',
  } as const;

  it('mints an id the Event schema accepts', () => {
    // The acceptance criterion for the derivation: `Event.id` is `z.guid()`, so a
    // raw 64-hex digest would be rejected outright. This is what forces the UUID
    // rendering rather than sending captureId itself.
    const event = buildIngestEvent({ ...base, metadata: { sessionId: 'sess_1' } });
    expect(() => IngestEvent.parse(event)).not.toThrow();
  });

  it('derives the same id for the same capture, twice', () => {
    const input = { ...base, metadata: { sessionId: 'sess_1', filePath: 'src/a.ts' } };
    // occurredAt and correlationId differ between these two calls; the id must not.
    expect(buildIngestEvent(input).id).toBe(buildIngestEvent(input).id);
  });

  it('derives the id from the tuple the local row is keyed on', () => {
    // The join that makes delivery recordable: given a stored row, re-deriving
    // this id must land on the id the deployment was given. Both directions are
    // spelled out here because a change to either side breaks retry idempotency
    // silently — the send still succeeds, it just writes a second copy.
    const hash = contentHashOf('hello world');
    const event = buildIngestEvent({
      ...base,
      metadata: { sessionId: 'sess_1', filePath: 'src/a.ts' },
    });
    expect(event.contentHash).toBe(hash);
    expect(event.id).toBe(captureWireId('sess_1', hash, 'src/a.ts'));
    // …and that wire id is a rendering of the row's own key, not a parallel space.
    expect(event.id.replaceAll('-', '').slice(0, 12)).toBe(
      captureId('sess_1', hash, 'src/a.ts').slice(0, 12),
    );
  });

  it('honours a caller-supplied contentHash, so a redacted copy still derives the original id', () => {
    // Secrets-at-rest: `content` is the masked copy but `contentHash` is the hash
    // of the ORIGINAL. The id must follow the hash, or a redacted capture and its
    // unredacted twin would occupy different ids on the wire while sharing a row.
    const original = contentHashOf('my-secret-value');
    const event = buildIngestEvent({
      ...base,
      content: '***masked***',
      contentHash: original,
      metadata: { sessionId: 'sess_1' },
    });
    expect(event.id).toBe(captureWireId('sess_1', original, null));
  });

  it('separates captures that the row-level key separates', () => {
    const mk = (metadata: Record<string, string>) => buildIngestEvent({ ...base, metadata }).id;
    const inSession = mk({ sessionId: 'sess_1' });
    expect(inSession).not.toBe(mk({ sessionId: 'sess_2' }));
    expect(inSession).not.toBe(mk({ sessionId: 'sess_1', filePath: 'src/a.ts' }));
    expect(mk({ sessionId: 'sess_1', filePath: 'src/a.ts' })).not.toBe(
      mk({ sessionId: 'sess_1', filePath: 'src/b.ts' }),
    );
    // A session-less capture folds onto the sentinel rather than shortening the join.
    expect(buildIngestEvent(base).id).toBe(captureWireId(null, contentHashOf(base.content), null));
  });

  it('keeps correlationId random — it identifies the request, not the capture', () => {
    // Deriving this one too would collapse two separate requests that happened to
    // carry identical text onto one correlation, losing the origin link.
    const input = { ...base, metadata: { sessionId: 'sess_1' } };
    expect(buildIngestEvent(input).metadata?.correlationId).not.toBe(
      buildIngestEvent(input).metadata?.correlationId,
    );
  });
});
