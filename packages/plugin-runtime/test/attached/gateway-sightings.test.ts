import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { SightingKey } from '@akasecurity/persistence';
import {
  createSightingKeyStore,
  dataDir as dataDirOf,
  keysDir as keysDirOf,
} from '@akasecurity/persistence';
import type { CaptureRecord } from '@akasecurity/plugin-sdk';
import type { IngestBatch, IngestEvent } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import type { AttachedClient, AttachedDataGatewayDeps } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import { FAIL_CLOSED_MARKER } from '../../src/attached/outbound-encoder.ts';
import {
  emailShaped,
  expectedToken,
  keyOf,
  materialOf,
  patShaped,
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

function storeKey(key: SightingKey): void {
  createSightingKeyStore('file', keysDirOf(base)).replace({
    keyVersion: key.keyVersion,
    algorithm: 'hmac-sha256',
    key: materialOf(key),
    fetchedAtMs: 1,
  });
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

const emptySeen = (): Seen => ({ bodies: [], local: [], owed: 0, delivered: 0 });

const capture = (content: string): CaptureRecord => ({
  event: {
    id: '00000000-0000-4000-8000-0000000000a1',
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: '2026-10-01T10:00:00.000Z',
    contentHash: 'c'.repeat(64),
    content,
    metadata: { repo: 'org/api' },
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
    expect(sent?.metadata).toEqual({ repo: 'org/api' });
  });

  it('never throws into the session when the encoder fails, and owes the row', async () => {
    const seen = emptySeen();
    const gateway = build(seen, {
      encoder: {
        encodeContent: () => Promise.reject(new Error('encoder fault')),
        encodeEvent: () => Promise.reject(new Error('encoder fault')),
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
});
