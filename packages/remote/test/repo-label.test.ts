import { describe, expect, it } from 'vitest';

import {
  auditEventForWire,
  batchForWire,
  ownerRepoWithoutQuery,
  repoNameWithoutQuery,
} from '../src/repo-label.ts';

describe('ownerRepoWithoutQuery', () => {
  it.each([
    ['acme/payments-api.git?t=not-a-real-query', 'acme/payments-api'],
    ['acme/payments-api?ref=main', 'acme/payments-api'],
    ['acme/payments-api.git?not-a-real-query', 'acme/payments-api'],
  ])('removes the query from %s', (label, expected) => {
    expect(ownerRepoWithoutQuery(label)).toBe(expected);
  });

  it.each(['acme/payments-api', 'acme/payments-api.git'])(
    'returns %s, which has no query, as given',
    (label) => {
      expect(ownerRepoWithoutQuery(label)).toBe(label);
    },
  );
});

describe('repoNameWithoutQuery', () => {
  it.each([
    ['payments-api.git?t=not-a-real-query', 'payments-api'],
    ['payments-api?ref=main&depth=1', 'payments-api'],
    ['payments-api.git?t=bm90LWEtcmVhbC1xdWVyeQ==', 'payments-api'],
  ])('removes the query from %s', (label, expected) => {
    expect(repoNameWithoutQuery(label)).toBe(expected);
  });

  it.each(['payments-api', 'payments-api.git', 'c#-tools'])(
    'returns %s, which has no query, as given',
    (label) => {
      expect(repoNameWithoutQuery(label)).toBe(label);
    },
  );

  it.each(['a?b', 'what?', 'notes?2026', 'a?b#c'])(
    'returns the folder name %s, with no `=` after its `?`, as given',
    (label) => {
      expect(repoNameWithoutQuery(label)).toBe(label);
    },
  );
});

describe('the wire projections', () => {
  const capture = (repo?: string) => ({
    id: 'cap-1',
    sourceTool: 'claude-code' as const,
    kind: 'prompt' as const,
    occurredAt: '2026-08-24T10:00:00.000Z',
    contentHash: 'hash',
    content: 'redacted content',
    ...(repo === undefined ? {} : { metadata: { repo } }),
  });
  const root = (attributes?: Record<string, unknown>) => ({
    id: 'evt-1',
    eventType: 'session' as const,
    startedAt: '2026-08-24T10:00:00.000Z',
    inspections: [],
    ...(attributes === undefined ? {} : { attributes }),
  });

  it('returns a batch and an event with nothing to change as the same objects', () => {
    const batch = { events: [capture('payments-api'), capture()] };
    expect(batchForWire(batch)).toBe(batch);
    const event = root({ repo: 'acme/payments-api', project: 'payments-api' });
    expect(auditEventForWire(event)).toBe(event);
    const bare = root();
    expect(auditEventForWire(bare)).toBe(bare);
  });

  it("keeps a folder name's `?` and removes an owner/repo label's query", () => {
    const batch = { events: [capture('a?b')] };
    expect(batchForWire(batch)).toBe(batch);
    const folder = root({ project: 'a?b' });
    expect(auditEventForWire(folder)).toBe(folder);
    const remote = root({ repo: 'acme/payments-api.git?not-a-real-query', project: 'a?b' });
    expect(auditEventForWire(remote).attributes).toEqual({
      repo: 'acme/payments-api',
      project: 'a?b',
    });
  });

  it('leaves the caller’s objects untouched', () => {
    const batch = { events: [capture('payments-api.git?t=q')] };
    const event = root({ repo: 'acme/payments-api.git?t=q', project: 7 });
    expect(batchForWire(batch).events[0]?.metadata?.repo).toBe('payments-api');
    expect(auditEventForWire(event).attributes).toEqual({ repo: 'acme/payments-api', project: 7 });
    expect(batch.events[0]?.metadata?.repo).toBe('payments-api.git?t=q');
    expect(event.attributes?.repo).toBe('acme/payments-api.git?t=q');
  });
});
