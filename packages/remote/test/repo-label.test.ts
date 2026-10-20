import { describe, expect, it } from 'vitest';

import { auditEventForWire, batchForWire, repoLabelWithoutQuery } from '../src/repo-label.ts';

describe('repoLabelWithoutQuery', () => {
  it.each([
    ['payments-api.git?t=not-a-real-query', 'payments-api'],
    ['acme/payments-api.git?t=not-a-real-query', 'acme/payments-api'],
    ['acme/payments-api?ref=main', 'acme/payments-api'],
    ['what?', 'what'],
  ])('removes the query from %s', (label, expected) => {
    expect(repoLabelWithoutQuery(label)).toBe(expected);
  });

  it.each(['payments-api', 'payments-api.git', 'c#-tools', 'acme/payments-api'])(
    'returns %s, which has no query, as given',
    (label) => {
      expect(repoLabelWithoutQuery(label)).toBe(label);
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

  it('leaves the caller’s objects untouched', () => {
    const batch = { events: [capture('payments-api.git?t=q')] };
    const event = root({ repo: 'acme/payments-api.git?t=q', project: 7 });
    expect(batchForWire(batch).events[0]?.metadata?.repo).toBe('payments-api');
    expect(auditEventForWire(event).attributes).toEqual({ repo: 'acme/payments-api', project: 7 });
    expect(batch.events[0]?.metadata?.repo).toBe('payments-api.git?t=q');
    expect(event.attributes?.repo).toBe('acme/payments-api.git?t=q');
  });
});
