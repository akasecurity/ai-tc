import type { HistorySyncInspectionRow } from '@akasecurity/persistence';
import type { AuditEventRow } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { rebuildAuditEvent } from '../../src/attached/history-rebuild.ts';

const STARTED = Date.parse('2026-08-01T12:00:00.000Z');

const row = (over: Partial<AuditEventRow> = {}): AuditEventRow => ({
  id: 'e-1',
  parentId: null,
  rootSessionId: null,
  eventType: 'session',
  hostId: null,
  harnessId: null,
  sourceProjectId: null,
  startedAt: STARTED,
  endedAt: null,
  severity: null,
  priority: null,
  content: null,
  contentHash: null,
  attributes: null,
  ...over,
});

const inspection = (over: Partial<HistorySyncInspectionRow> = {}): HistorySyncInspectionRow => ({
  ruleId: 'aws-access-key',
  ruleName: 'AWS access key',
  ruleVersion: '3',
  category: 'secret',
  severity: 'high',
  spanStart: 10,
  spanEnd: 30,
  maskedMatch: 'AKIA****************',
  actionTaken: 'redact',
  confidence: 0.9,
  ...over,
});

describe('rebuildAuditEvent', () => {
  it('rebuilds a session root with its time as an ISO string', () => {
    const built = rebuildAuditEvent(row());
    expect(built).toMatchObject({
      id: 'e-1',
      eventType: 'session',
      startedAt: '2026-08-01T12:00:00.000Z',
    });
  });

  it('carries the tree pointers a leaf needs', () => {
    const built = rebuildAuditEvent(
      row({ id: 'e-2', eventType: 'llm_call', parentId: 'e-1', rootSessionId: 'e-1' }),
    );
    expect(built).toMatchObject({ parentId: 'e-1', rootSessionId: 'e-1' });
  });

  it('includes endedAt when the row has one, and omits it when it does not', () => {
    expect(rebuildAuditEvent(row({ endedAt: STARTED + 5_000 }))?.endedAt).toBe(
      '2026-08-01T12:00:05.000Z',
    );
    expect(rebuildAuditEvent(row())).not.toHaveProperty('endedAt');
  });

  // THE INVARIANT OF THIS LANE. `content` is an optional field on the wire shape
  // and a stored row can carry one, so nothing in the type system stops it
  // travelling — only this omission does, which is why it has its own case.
  it('never sends content, even from a row that has some', () => {
    const built = rebuildAuditEvent(row({ content: 'the text of a prompt' }));
    expect(built).not.toHaveProperty('content');
  });

  it('never sends a content hash either, matching the live path', () => {
    const built = rebuildAuditEvent(row({ contentHash: 'sha256:abc' }));
    expect(built).not.toHaveProperty('contentHash');
  });

  // Local inventory ids name rows the receiving side does not have. They are
  // real foreign keys there, so sending one wrong costs the whole session.
  it('drops every inventory id', () => {
    const built = rebuildAuditEvent(
      row({ hostId: 'host-local', harnessId: 'harness-local', sourceProjectId: 'proj-local' }),
    );
    expect(built).not.toHaveProperty('hostId');
    expect(built).not.toHaveProperty('harnessId');
    expect(built).not.toHaveProperty('sourceProjectId');
  });

  // What a reader actually sees survives in attributes, which is why dropping
  // the ids above costs a join rather than the display.
  it('keeps the attributes bag, which is where the readable detail lives', () => {
    const built = rebuildAuditEvent(
      row({ attributes: JSON.stringify({ repo: 'acme/api', branch: 'main' }) }),
    );
    expect(built?.attributes).toEqual({ repo: 'acme/api', branch: 'main' });
  });

  it('keeps the event when the attributes bag is damaged', () => {
    const built = rebuildAuditEvent(row({ attributes: '{not json' }));
    expect(built).toBeDefined();
    expect(built).not.toHaveProperty('attributes');
  });

  it('ignores an attributes bag that is not an object', () => {
    expect(rebuildAuditEvent(row({ attributes: '"a string"' }))).not.toHaveProperty('attributes');
    expect(rebuildAuditEvent(row({ attributes: '[1,2]' }))).not.toHaveProperty('attributes');
  });
});

describe('rebuildAuditEvent — detections on a tool call', () => {
  const toolRow = row({ id: 'e-3', eventType: 'tool_call', parentId: 'e-1', rootSessionId: 'e-1' });

  // A tool call's target is not re-inspectable from the event, so the masked
  // detection is the only way the information survives.
  it('carries the masked detection and the rule that found it', () => {
    const built = rebuildAuditEvent(toolRow, [inspection()]);
    expect(built?.inspections).toEqual([
      {
        ruleId: 'aws-access-key',
        ruleName: 'AWS access key',
        ruleVersion: '3',
        category: 'secret',
        severity: 'high',
        span: { start: 10, end: 30 },
        maskedMatch: 'AKIA****************',
        actionTaken: 'redact',
        confidence: 0.9,
      },
    ]);
  });

  it('sends an empty list when nothing was detected', () => {
    expect(rebuildAuditEvent(toolRow)?.inspections).toEqual([]);
  });

  // A stored detection the current shape will not accept — a value from a
  // retired enum, a confidence an older writer put on a 0-100 scale — must cost
  // itself, not the tool call it hangs off. Otherwise one bad child row stamps
  // the whole event permanently skipped.
  it('drops a detection that will not parse rather than losing the event', () => {
    const built = rebuildAuditEvent(toolRow, [
      inspection({ ruleId: 'bad', confidence: 42 }),
      inspection({ ruleId: 'kept' }),
    ]);
    expect(built).toBeDefined();
    expect(built?.inspections.map((i) => i.ruleId)).toEqual(['kept']);
  });

  it('drops a detection whose category is not one this build knows', () => {
    const built = rebuildAuditEvent(toolRow, [
      inspection({ ruleId: 'bad', category: 'not-a-category' }),
      inspection({ ruleId: 'kept' }),
    ]);
    expect(built?.inspections.map((i) => i.ruleId)).toEqual(['kept']);
  });

  // The receiving side refuses the whole request over a reserved rule-version
  // namespace. Dropping the one inspection keeps the tool call.
  it('drops a reserved-namespace inspection rather than losing the event', () => {
    const built = rebuildAuditEvent(toolRow, [
      inspection({ ruleVersion: 'capture/1' }),
      inspection({ ruleId: 'kept' }),
    ]);
    expect(built).toBeDefined();
    expect(built?.inspections.map((i) => i.ruleId)).toEqual(['kept']);
  });
});

describe('rebuildAuditEvent — rows that cannot be sent', () => {
  // The driver hands back whatever is in the column; the row type is a claim
  // about that, not a guarantee. A store is years of writers, and one really can
  // hold an event type this build has never heard of — which is the case this
  // lane has to survive rather than the one it can rule out.
  const asStored = (over: Record<string, unknown>): AuditEventRow => ({ ...row(), ...over });

  // A store is years of writers. A row one of them left half-shaped has to
  // become a counted, permanent skip rather than a request refused for ever.
  it('refuses a row whose event type is not on the wire', () => {
    expect(rebuildAuditEvent(asStored({ eventType: 'not-a-real-type' }))).toBeUndefined();
  });

  it('refuses a row with no id', () => {
    expect(rebuildAuditEvent(row({ id: '' }))).toBeUndefined();
  });

  it('refuses a row whose time is not a real instant', () => {
    expect(rebuildAuditEvent(row({ startedAt: Number.NaN }))).toBeUndefined();
  });

  // The same conversion hazard on the optional half: a damaged end time costs
  // the field, not the event.
  it('keeps a row whose end time is damaged, without it', () => {
    const built = rebuildAuditEvent(row({ endedAt: Number.NaN }));
    expect(built).toBeDefined();
    expect(built).not.toHaveProperty('endedAt');
  });

  // Finite but far outside what a Date can hold — a writer that stamped
  // microseconds instead of millis. toISOString() RAISES on this rather than
  // returning anything, and an escaping throw would not cost one row: it leaves
  // the drain, is swallowed as "no attempt made", and the row is never marked
  // skipped — so every later pass reaches it and dies identically, with every
  // row behind it in the session stranded.
  it('refuses an out-of-range timestamp instead of throwing', () => {
    expect(() => rebuildAuditEvent(row({ startedAt: 1.7e18 }))).not.toThrow();
    expect(rebuildAuditEvent(row({ startedAt: 1.7e18 }))).toBeUndefined();
  });

  it('keeps a row whose end time is out of range, without it', () => {
    const built = rebuildAuditEvent(row({ endedAt: 1.7e18 }));
    expect(built).toBeDefined();
    expect(built).not.toHaveProperty('endedAt');
  });

  // Every inspection unusable is still a valid tool call with none — the event
  // is what this lane is for, and the detections decorate it.
  it('keeps a tool call whose every detection was dropped', () => {
    const toolRow = row({ eventType: 'tool_call', rootSessionId: 'e-1', parentId: 'e-1' });
    const built = rebuildAuditEvent(toolRow, [inspection({ confidence: 42 })]);
    expect(built).toBeDefined();
    expect(built?.inspections).toEqual([]);
  });
});
