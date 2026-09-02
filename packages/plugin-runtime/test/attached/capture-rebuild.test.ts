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

  describe('rows that can never be expressed become a permanent skip', () => {
    it('refuses a structural row that strayed onto this lane', () => {
      expect(rebuildCapture(row({ eventType: 'tool_call' }))).toBeUndefined();
      expect(rebuildCapture(row({ eventType: 'session' }))).toBeUndefined();
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
