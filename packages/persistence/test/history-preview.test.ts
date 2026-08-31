import { writeFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { readLocalHistoryPreview } from '../src/history-preview.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-history-preview-');

const NOW = Date.parse('2026-08-29T00:00:00.000Z');
const DAY = 86_400_000;
const iso = (msAgo: number): string => new Date(NOW - msAgo).toISOString();

describe('readLocalHistoryPreview', () => {
  // The store file appears on the first open, so a tree with no open yet is the
  // real "never recorded anything here" shape rather than a contrived one.
  //
  // A machine with no store has recorded NOTHING, which is a definite answer —
  // the strongest form of "nothing to ask about". Only a store that exists and
  // cannot be read is unknown, and the two must not be conflated: a caller that
  // read this as unknown would offer to send a history that does not exist.
  it('reports zero when no store file exists', () => {
    expect(readLocalHistoryPreview(store.dataDir, NOW)).toEqual({ sessions: 0, days: 0 });
  });

  it('reports zero sessions on a real but empty store', () => {
    store.open();
    expect(readLocalHistoryPreview(store.dataDir, NOW)).toEqual({ sessions: 0, days: 0 });
  });

  it('counts session roots and dates the span from the earliest', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-old', iso(47 * DAY));
    db.auditEvents.ensureSessionRoot('s-mid', iso(3 * DAY));
    db.auditEvents.ensureSessionRoot('s-new', iso(0));

    expect(readLocalHistoryPreview(store.dataDir, NOW)).toEqual({ sessions: 3, days: 47 });
  });

  // The count is of sessions, not of everything recorded — the prompt says
  // "sessions", so a store of mostly leaves must not read as a huge history.
  it('ignores non-session events', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', iso(DAY));
    db.auditEvents.insertAuditEvent({
      id: 'e-1',
      eventType: 'llm_call',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: iso(DAY),
    });

    expect(readLocalHistoryPreview(store.dataDir, NOW)).toEqual({ sessions: 1, days: 1 });
  });

  // A damaged store has UNKNOWN history. Reporting zero would understate what a
  // grant covers, so this degrades to "ask without numbers" instead.
  it('is undefined when the store cannot be opened', () => {
    writeFileSync(store.dbFile, 'not a database');
    expect(readLocalHistoryPreview(store.dataDir, NOW)).toBeUndefined();
  });

  it('never reports a negative span for a row stamped in the future', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-future', new Date(NOW + 5 * DAY).toISOString());
    expect(readLocalHistoryPreview(store.dataDir, NOW)?.days).toBe(0);
  });
});
