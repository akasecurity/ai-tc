import { captureWireId } from '@akasecurity/persistence';
import { buildIngestEvent } from '@akasecurity/plugin-sdk';
import type { AuditEventRow } from '@akasecurity/schema';
import { IngestEvent } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { rebuildCapture } from '../../src/attached/capture-rebuild.ts';

const SESSION = 'session-1';
const HASH = 'a'.repeat(64);

const row = (over: Partial<AuditEventRow> = {}): AuditEventRow => ({
  id: 'row-1',
  eventType: 'prompt',
  startedAt: Date.parse('2026-09-01T10:00:00.000Z'),
  rootSessionId: SESSION,
  parentId: SESSION,
  content: 'the text of a prompt',
  contentHash: HASH,
  attributes: JSON.stringify({ source_tool: 'claude-code', repo: 'acme/api' }),
  ...over,
});

describe('rebuildCapture', () => {
  // The lane's whole reason to exist. If this ever stops holding, the drain is
  // sending prompt rows stripped of the text they were queued for.
  it('carries the captured text and its hash', () => {
    const event = rebuildCapture(row());
    expect(event?.content).toBe('the text of a prompt');
    expect(event?.contentHash).toBe(HASH);
  });

  // THE RETRY PROPERTY. A drained row must be sent under the id the live path
  // would have used, or the receiver files a second copy of everything whose
  // stamp was lost. Asserted against the SDK's own builder rather than against a
  // literal, so the two derivations cannot drift apart while both stay green.
  it('reproduces the id the live path would have sent', () => {
    const live = buildIngestEvent({
      kind: 'prompt',
      sourceTool: 'claude-code',
      content: 'the text of a prompt',
      contentHash: HASH,
      occurredAt: '2026-09-01T10:00:00.000Z',
      metadata: { sessionId: SESSION },
    });
    expect(rebuildCapture(row())?.id).toBe(live.id);
  });

  it('derives the id from the session, hash and file path', () => {
    const withFile = row({
      attributes: JSON.stringify({ source_tool: 'claude-code', file_path: 'src/a.ts' }),
    });
    expect(rebuildCapture(withFile)?.id).toBe(captureWireId(SESSION, HASH, 'src/a.ts'));
    // A different file with identical content is a different capture.
    expect(rebuildCapture(withFile)?.id).not.toBe(captureWireId(SESSION, HASH, null));
  });

  it('emits something the wire schema actually accepts', () => {
    expect(IngestEvent.safeParse(rebuildCapture(row())).success).toBe(true);
  });

  it('carries the session so the receiver can stub its root', () => {
    expect(rebuildCapture(row())?.metadata?.sessionId).toBe(SESSION);
  });

  it('maps the attributes bag back onto wire metadata', () => {
    const rich = row({
      attributes: JSON.stringify({
        source_tool: 'claude-code',
        repo: 'acme/api',
        file_path: 'src/a.ts',
        tool_name: 'Bash',
        gitignored: true,
        whole_file: true,
        turn_index: 3,
      }),
    });
    expect(rebuildCapture(rich)?.metadata).toMatchObject({
      repo: 'acme/api',
      filePath: 'src/a.ts',
      toolName: 'Bash',
      gitignored: true,
      wholeFile: true,
      turnIndex: 3,
    });
  });

  // Replayed work is not latency any session waited on — the field's own
  // contract says absent, never a number.
  it('drops inspectionMs rather than replaying it as latency', () => {
    const measured = row({
      attributes: JSON.stringify({ source_tool: 'claude-code', inspection_ms: 42 }),
    });
    expect(rebuildCapture(measured)?.metadata?.inspectionMs).toBeUndefined();
  });

  // An OPTIONAL attribute the wire constrains more tightly than the column does
  // costs itself, never the capture. Skipping the row instead would write
  // synced_at = -1 and put that prompt permanently out of reach — the same data
  // loss the outbox exists to stop, reached by a different door.
  describe('an unusable optional attribute is dropped, not the row', () => {
    const withBag = (bag: Record<string, unknown>) =>
      rebuildCapture(row({ attributes: JSON.stringify({ source_tool: 'claude-code', ...bag }) }));

    it('drops a correlation id that is not a uuid', () => {
      const event = withBag({ correlation_id: 'legacy-7' });
      expect(event?.content).toBe('the text of a prompt');
      expect(event?.metadata?.correlationId).toBeUndefined();
    });

    it('keeps a correlation id that is a uuid', () => {
      const id = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';
      expect(withBag({ correlation_id: id })?.metadata?.correlationId).toBe(id);
    });

    it('drops a trace id that is not 32 hex characters', () => {
      expect(withBag({ trace_id: 'nope' })?.metadata?.traceId).toBeUndefined();
      expect(withBag({ trace_id: 'a'.repeat(32) })?.metadata?.traceId).toBe('a'.repeat(32));
    });

    it('drops a negative or fractional turn index', () => {
      expect(withBag({ turn_index: -1 })?.metadata?.turnIndex).toBeUndefined();
      expect(withBag({ turn_index: 1.5 })?.metadata?.turnIndex).toBeUndefined();
      expect(withBag({ turn_index: 3 })?.metadata?.turnIndex).toBe(3);
    });

    it('carries the exception ids the live forward carries', () => {
      const ids = ['3f2504e0-4f89-41d3-9a0c-0305e82c3301'];
      expect(withBag({ exception_ids: ids })?.metadata?.exceptionIds).toEqual(ids);
    });

    // The list form of the same rule. A bag holding a non-guid string is a plain
    // array of strings, so a `typeof` filter passes it and the assembled event is
    // then refused — turning one unusable id into a permanently skipped prompt.
    it('drops an exception id that is not a guid, and keeps the capture', () => {
      const good = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';
      const event = withBag({ exception_ids: [good, 'legacy-grant-7'] });
      expect(event?.content).toBe('the text of a prompt');
      expect(event?.metadata?.exceptionIds).toEqual([good]);
    });

    it('drops the field entirely when no exception id survives', () => {
      const event = withBag({ exception_ids: ['legacy-grant-7'] });
      expect(event?.content).toBe('the text of a prompt');
      expect(event?.metadata?.exceptionIds).toBeUndefined();
    });
  });

  describe('rows that can never be expressed become a permanent skip', () => {
    it('refuses a structural row that strayed onto this lane', () => {
      expect(rebuildCapture(row({ eventType: 'tool_call' }))).toBeUndefined();
      expect(rebuildCapture(row({ eventType: 'session' }))).toBeUndefined();
    });

    // code_change IS a capture kind, so EventKind admits it and only this
    // explicit refusal keeps whole source files off the lane. Pinned here as
    // well as in the ledger's SQL so the two must move together.
    it('refuses a code_change, which is a capture kind this lane excludes', () => {
      expect(rebuildCapture(row({ eventType: 'code_change' }))).toBeUndefined();
    });

    it('refuses a row with no content or no hash', () => {
      expect(rebuildCapture(row({ content: null }))).toBeUndefined();
      expect(rebuildCapture(row({ contentHash: null }))).toBeUndefined();
    });

    it('refuses a row with a damaged timestamp instead of throwing', () => {
      expect(() => rebuildCapture(row({ startedAt: Number.NaN }))).not.toThrow();
      expect(rebuildCapture(row({ startedAt: Number.NaN }))).toBeUndefined();
    });

    it('refuses a row whose source tool is missing or unknown', () => {
      expect(rebuildCapture(row({ attributes: JSON.stringify({}) }))).toBeUndefined();
      expect(
        rebuildCapture(row({ attributes: JSON.stringify({ source_tool: 'nope' }) })),
      ).toBeUndefined();
    });
  });

  // A damaged bag costs the metadata it held, not the row and not the text.
  it('survives an unparseable attributes bag only if the tool is recoverable', () => {
    expect(rebuildCapture(row({ attributes: '{not json' }))).toBeUndefined();
  });

  it('handles a capture recorded outside any session', () => {
    const orphan = row({ rootSessionId: null, parentId: null });
    expect(rebuildCapture(orphan)?.id).toBe(captureWireId(null, HASH, null));
    expect(rebuildCapture(orphan)?.metadata?.sessionId).toBeUndefined();
  });
});
