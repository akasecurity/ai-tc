import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { SightingKey } from '@akasecurity/persistence';
import {
  captureWireId,
  dataDir as dataDirOf,
  loadOrCreateCaptureIdKey,
} from '@akasecurity/persistence';
import type { CaptureRecord } from '@akasecurity/plugin-sdk';
import { contentHashOf } from '@akasecurity/plugin-sdk';
import type { IngestBatch, IngestEvent, PolicyBundle, Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import { DECISION_PATH_BUDGET_MS } from '../../src/attached/forward-policy.ts';
import type { AttachedClient, AttachedDataGatewayDeps } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import { encodedWireId, FAIL_CLOSED_MARKER } from '../../src/attached/outbound-encoder.ts';
import {
  emailShaped,
  expectedToken,
  keyOf,
  patShaped,
  setSightingSharing,
  storeSightingKey,
} from '../helpers/sighting-fixtures.ts';

const KEY = 'github.com/org/api';

const passthrough: ForwardPolicy = {
  run: async <T>(op: () => Promise<T>): Promise<ForwardResult<T>> => {
    try {
      return { ok: true, value: await op() };
    } catch {
      return { ok: false, reason: 'unreachable' };
    }
  },
};

interface Seen {
  bundle: () => Promise<PolicyBundle>;
  forwards: number;
  bodies: string[];
  local: IngestEvent[];
  owed: number;
  delivered: number;
}

function quietLocal(seen: Seen): AttachedDataGatewayDeps['local'] {
  return {
    recordCapture: (record: CaptureRecord) => {
      seen.local.push(record.event);
      return Promise.resolve();
    },
    markCaptureDelivered: () => {
      seen.delivered += 1;
    },
    markCaptureOwed: () => {
      seen.owed += 1;
    },
    getPolicyBundle: () => seen.bundle(),
    close: () => Promise.resolve(),
  } as unknown as AttachedDataGatewayDeps['local'];
}

function recordingClient(seen: Seen): AttachedClient {
  return {
    ingestEvents: (batch: IngestBatch) => {
      seen.bodies.push(JSON.stringify(batch));
      return Promise.resolve({ accepted: 1, duplicates: 0 });
    },
  } as unknown as AttachedClient;
}

let base: string;
beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sightings-'));
});
afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function storeKey(key: SightingKey, opts: { issuedBy?: string } = {}): void {
  storeSightingKey(base, key, opts);
}

function build(seen: Seen, overrides: Partial<AttachedDataGatewayDeps> = {}): AttachedDataGateway {
  return new AttachedDataGateway({
    dataDir: dataDirOf(base),
    local: quietLocal(seen),
    client: recordingClient(seen),
    readCachedBundle: () => Promise.resolve(null),
    forward: passthrough,
    attachment: { mode: 'machine', keys: new Set<string>() },
    ...overrides,
  });
}

const bundleOf = (rules: Rule[]): PolicyBundle => ({
  version: 'v',
  policies: [],
  rules,
  customKeywords: [],
  fetchedAt: '2026-01-01T00:00:00.000Z',
});

const emptySeen = (): Seen => ({
  bundle: () => Promise.resolve(bundleOf([])),
  forwards: 0,
  bodies: [],
  local: [],
  owed: 0,
  delivered: 0,
});

const counting = (seen: Seen): ForwardPolicy => ({
  run: <T>(op: () => Promise<T>, opts?: { decisionPath?: boolean }) => {
    seen.forwards += 1;
    return passthrough.run(op, opts);
  },
});

const capture = (content: string): CaptureRecord => ({
  event: {
    id: captureWireId('sess-9', contentHashOf(content), null),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: '2026-10-01T10:00:00.000Z',
    contentHash: contentHashOf(content),
    content,
    metadata: { sessionId: 'sess-9', repo: 'org/api' },
  },
  findings: [],
  scopeKey: KEY,
});

describe('attached gateway: secrets leave only as sighting tokens', () => {
  const value = patShaped(51);

  it('forwards the token and its metadata, never the value, and keeps the local copy raw', async () => {
    const key = keyOf(7, 3);
    storeKey(key);
    const seen = emptySeen();
    const record = capture(`deploy with ${value} and mail ${emailShaped()}`);

    await build(seen).recordCapture(record);

    expect(seen.bodies).toHaveLength(1);
    const body = seen.bodies[0] ?? '';
    expect(body).not.toContain(value);
    const sent = (JSON.parse(body) as IngestBatch).events[0];
    expect(sent?.content).toBe(
      `deploy with ${expectedToken(key, value)} and mail ${emailShaped()}`,
    );
    expect(sent?.metadata).toEqual({
      sessionId: 'sess-9',
      repo: 'org/api',
      sightings: [
        { token: expectedToken(key, value), ruleId: 'secrets/github-pat', category: 'secret' },
      ],
    });
    expect(seen.local[0]?.content).toContain(value);
    expect(record.event.content).toContain(value);
    expect(seen.delivered).toBe(1);
  });

  it('encodes the scoped copy too', async () => {
    const key = keyOf(2, 8);
    storeKey(key);
    const seen = emptySeen();
    await build(seen, { attachment: { mode: 'scoped', keys: new Set([KEY]) } }).recordCapture(
      capture(`x ${value}`),
    );
    expect(seen.bodies[0]).not.toContain(value);
    expect(seen.bodies[0]).toContain(expectedToken(key, value));
  });

  it('sends the marker when no key is stored', async () => {
    const seen = emptySeen();
    await build(seen).recordCapture(capture(`x ${value} y`));
    const sent = (JSON.parse(seen.bodies[0] ?? '{}') as IngestBatch).events[0];
    expect(sent?.content).toBe(`x ${FAIL_CLOSED_MARKER} y`);
    expect(sent?.metadata).toEqual({ sessionId: 'sess-9', repo: 'org/api' });
  });

  it('never throws into the session when the encoder fails, and owes the row', async () => {
    const seen = emptySeen();
    const gateway = build(seen, {
      encoder: {
        encodeContent: () => Promise.reject(new Error('encoder fault')),
        encodeEvent: () => Promise.reject(new Error('encoder fault')),
        redactContent: () => Promise.reject(new Error('encoder fault')),
        close: () => Promise.resolve(),
      },
    });
    await expect(gateway.recordCapture(capture(`x ${value}`))).resolves.toBeUndefined();
    expect(seen.bodies).toEqual([]);
    expect(seen.owed).toBe(1);
  });

  it('sends a capture with no secret exactly as before', async () => {
    const seen = emptySeen();
    const record = capture('nothing to see');
    await build(seen).recordCapture(record);
    expect(seen.bodies[0]).toBe(JSON.stringify({ events: [record.event] }));
  });

  it('sends neither the raw content hash nor an id derived from it', async () => {
    storeKey(keyOf(1, 6));
    const seen = emptySeen();
    const record = capture(value);
    await build(seen).recordCapture(record);
    const sent = (JSON.parse(seen.bodies[0] ?? '{}') as IngestBatch).events[0];
    expect(seen.bodies[0]).not.toContain(contentHashOf(value));
    expect(sent?.id).not.toBe(record.event.id);
    expect(sent?.contentHash).toBe(contentHashOf(sent?.content ?? ''));
    const idKey = loadOrCreateCaptureIdKey(dataDirOf(base));
    expect(sent?.id).toBe(encodedWireId(idKey, 'sess-9', record.event.contentHash, null));
  });

  it('tokenises a value only an installed secret rule matches', async () => {
    const key = keyOf(4, 4);
    storeKey(key);
    const seen = emptySeen();
    const installedValue = ['ACME', 'TOK', '9'.repeat(10)].join('');
    seen.bundle = () =>
      Promise.resolve(
        bundleOf([
          {
            specVersion: 1,
            id: 'acme/internal-token',
            name: 'Internal token',
            category: 'secret',
            severity: 'high',
            matcher: { type: 'keyword', keywords: [installedValue], caseSensitive: true },
          },
        ]),
      );
    await build(seen).recordCapture(capture(`x ${installedValue} y`));
    expect(seen.bodies[0]).not.toContain(installedValue);
    expect(seen.bodies[0]).toContain(expectedToken(key, installedValue));
    expect(seen.bodies[0]).toContain('acme/internal-token');
  });

  it('holds the capture as owed, without a forward, when the rules cannot be loaded', async () => {
    storeKey(keyOf(1, 7));
    const seen = emptySeen();
    seen.bundle = () => Promise.reject(new Error('store unreadable'));
    await expect(
      build(seen, { forward: counting(seen) }).recordCapture(capture(`x ${value}`)),
    ).resolves.toBeUndefined();
    expect(seen.bodies).toEqual([]);
    expect(seen.forwards).toBe(0);
    expect(seen.owed).toBe(1);
  });

  it('holds the capture as owed when encoding outlasts the decision budget', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const seen = emptySeen();
      const gateway = build(seen, {
        forward: counting(seen),
        encoder: {
          encodeContent: () => new Promise(() => undefined),
          encodeEvent: () => new Promise(() => undefined),
          redactContent: () => new Promise(() => undefined),
          close: () => Promise.resolve(),
        },
      });
      const pending = gateway.recordCapture(capture(`x ${value}`));
      await vi.advanceTimersByTimeAsync(DECISION_PATH_BUDGET_MS);
      await expect(pending).resolves.toBeUndefined();
      expect(seen.bodies).toEqual([]);
      expect(seen.forwards).toBe(0);
      expect(seen.owed).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('still tokenises a bundled secret when a cached rule reuses its id with another matcher', async () => {
    const key = keyOf(6, 6);
    storeKey(key);
    const seen = emptySeen();
    seen.bundle = () =>
      Promise.resolve(
        bundleOf([
          {
            specVersion: 1,
            id: 'secrets/github-pat',
            name: 'Shadow',
            category: 'secret',
            severity: 'low',
            matcher: { type: 'keyword', keywords: ['never-present-keyword'], caseSensitive: true },
          },
        ]),
      );
    await build(seen).recordCapture(capture(`x ${value}`));
    expect(seen.bodies[0]).not.toContain(value);
    expect(seen.bodies[0]).toContain(expectedToken(key, value));
  });

  it('sends the marker when the stored key was issued by another endpoint', async () => {
    storeKey(keyOf(2, 2), { issuedBy: 'https://other.example.test' });
    const seen = emptySeen();
    await build(seen).recordCapture(capture(`x ${value} y`));
    expect(seen.bodies[0]).not.toContain(value);
    const sent = (JSON.parse(seen.bodies[0] ?? '{}') as IngestBatch).events[0];
    expect(sent?.content).toBe(`x ${FAIL_CLOSED_MARKER} y`);
    expect(sent?.metadata?.sightings).toBeUndefined();
  });

  it('delivers a value only an installed regex rule matches through the real worker scan', async () => {
    const key = keyOf(7, 7);
    storeKey(key);
    const seen = emptySeen();
    const installedValue = ['ACME', 'RGX', '5'.repeat(10)].join('');
    seen.bundle = () =>
      Promise.resolve(
        bundleOf([
          {
            specVersion: 1,
            id: 'acme/internal-regex',
            name: 'Internal token by pattern',
            category: 'secret',
            severity: 'high',
            matcher: { type: 'regex', pattern: 'ACMERGX[0-9]{10}', flags: 'g' },
          },
        ]),
      );
    // Generous bounds, so the assertion is about the worker path and never
    // about how quickly a worker starts on this machine.
    const gateway = build(seen, {
      encodeBudgetMs: 60_000,
      scanBound: { budgetMs: 30_000, startBudgetMs: 30_000 },
    });
    try {
      await gateway.recordCapture(capture(`x ${installedValue} y`));
    } finally {
      await gateway.close();
    }
    expect(seen.owed).toBe(0);
    expect(seen.bodies[0]).not.toContain(installedValue);
    expect(seen.bodies[0]).toContain(expectedToken(key, installedValue));
    expect(seen.bodies[0]).toContain('acme/internal-regex');
  }, 90_000);

  it('sends only markers, with no token or sightings anywhere in the body, while sharing is off', async () => {
    storeSightingKey(base, keyOf(3, 3), { sharing: false });
    const seen = emptySeen();
    await build(seen).recordCapture(capture(`a ${value} b`));
    const body = seen.bodies[0] ?? '';
    expect(body).not.toContain(value);
    expect(body).not.toContain('[[aka:fp:');
    expect(body).not.toContain('sightings');
    expect(body).toContain(FAIL_CLOSED_MARKER);
  });

  it('applies a change of the sharing answer to the next capture', async () => {
    const key = keyOf(4, 1);
    storeSightingKey(base, key);
    const seen = emptySeen();
    const gateway = build(seen);
    await gateway.recordCapture(capture(`one ${value}`));
    setSightingSharing(base, false);
    await gateway.recordCapture(capture(`two ${value}`));
    setSightingSharing(base, true);
    await gateway.recordCapture(capture(`three ${value}`));
    expect(seen.bodies[0]).toContain(expectedToken(key, value));
    expect(seen.bodies[1]).not.toContain('[[aka:fp:');
    expect(seen.bodies[1]).toContain(FAIL_CLOSED_MARKER);
    expect(seen.bodies[2]).toContain(expectedToken(key, value));
  });
});
