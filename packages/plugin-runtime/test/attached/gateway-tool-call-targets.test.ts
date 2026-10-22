import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir as dataDirOf } from '@akasecurity/persistence';
import type {
  PolicyBundle,
  RecordAuditEventRequest,
  Rule,
  ToolCallInput,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import type { AttachedClient, AttachedDataGatewayDeps } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import { FAIL_CLOSED_MARKER } from '../../src/attached/outbound-encoder.ts';
import { keyOf, patShaped, storeSightingKey } from '../helpers/sighting-fixtures.ts';

const passthrough: ForwardPolicy = {
  run: async <T>(op: () => Promise<T>): Promise<ForwardResult<T>> => {
    try {
      return { ok: true, value: await op() };
    } catch {
      return { ok: false, reason: 'unreachable' };
    }
  },
};

const bundleOf = (rules: Rule[]): PolicyBundle => ({
  version: 'v',
  policies: [],
  rules,
  customKeywords: [],
  fetchedAt: '2026-01-01T00:00:00.000Z',
});

/** A secret only the organization's rule names; no bundled pack detects it. */
const orgValue = ['ACME', 'TOK', '7'.repeat(10)].join('');
const orgRule: Rule = {
  specVersion: 1,
  id: 'acme/internal-token',
  name: 'Internal token',
  category: 'secret',
  severity: 'high',
  matcher: { type: 'keyword', keywords: [orgValue], caseSensitive: true },
};

let base: string;
beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-tool-targets-'));
});
afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function build(bundle: () => Promise<PolicyBundle>): {
  gateway: AttachedDataGateway;
  wire: RecordAuditEventRequest[];
} {
  const wire: RecordAuditEventRequest[] = [];
  const local = {
    recordToolCalls: () => Promise.resolve(),
    markAuditEventsDelivered: () => undefined,
    getPolicyBundle: bundle,
    close: () => Promise.resolve(),
  } as unknown as AttachedDataGatewayDeps['local'];
  const client = {
    recordAuditEvents: (events: readonly RecordAuditEventRequest[]) => {
      wire.push(...events);
      return Promise.resolve({ accepted: events.length });
    },
  } as unknown as AttachedClient;
  const gateway = new AttachedDataGateway({
    dataDir: dataDirOf(base),
    local,
    client,
    readCachedBundle: () => Promise.resolve(null),
    forward: passthrough,
    attachment: { mode: 'machine', keys: new Set<string>() },
  });
  return { gateway, wire };
}

const toolCall = (toolUseId: string, target: string | undefined): ToolCallInput => ({
  sessionId: 'sess-t',
  toolUseId,
  parentId: 'sess-t',
  rootSessionId: 'sess-t',
  startedAt: '2026-10-01T10:00:00.000Z',
  attributes: { tool_name: 'Bash', ...(target === undefined ? {} : { target }) },
  inspections: [],
});

const targetOf = (event: RecordAuditEventRequest | undefined): unknown => event?.attributes?.target;

describe('attached gateway: a forwarded tool-call target', () => {
  it('redacts a secret only an organization rule detects', async () => {
    const { gateway, wire } = build(() => Promise.resolve(bundleOf([orgRule])));
    try {
      await gateway.recordToolCalls([toolCall('t-org', `curl -H "X-Key: ${orgValue}" api`)]);
    } finally {
      await gateway.close();
    }

    expect(wire).toHaveLength(1);
    expect(targetOf(wire[0])).toBe(`curl -H "X-Key: ${FAIL_CLOSED_MARKER}" api`);
    expect(JSON.stringify(wire)).not.toContain(orgValue);
  });

  it('sends the marker, never a sighting token, while a sighting key is held', async () => {
    storeSightingKey(base, keyOf(2, 3));
    const { gateway, wire } = build(() => Promise.resolve(bundleOf([orgRule])));
    try {
      await gateway.recordToolCalls([toolCall('t-key', `export K=${orgValue}`)]);
    } finally {
      await gateway.close();
    }

    expect(targetOf(wire[0])).toBe(`export K=${FAIL_CLOSED_MARKER}`);
    expect(JSON.stringify(wire)).not.toContain('[[aka:fp:');
  });

  it('redacts a bundled-rule secret the producer left in the target', async () => {
    const value = patShaped(17);
    const { gateway, wire } = build(() => Promise.resolve(bundleOf([])));
    try {
      await gateway.recordToolCalls([toolCall('t-pat', `git push https://${value}@host/r`)]);
    } finally {
      await gateway.close();
    }

    expect(targetOf(wire[0])).toBe(`git push https://${FAIL_CLOSED_MARKER}@host/r`);
  });

  it('sends a target with no secret, and a call with no target, as they are', async () => {
    const { gateway, wire } = build(() => Promise.resolve(bundleOf([orgRule])));
    try {
      await gateway.recordToolCalls([
        toolCall('t-clean', 'ls -la src'),
        toolCall('t-none', undefined),
      ]);
    } finally {
      await gateway.close();
    }

    expect(wire.map(targetOf)).toEqual(['ls -la src', undefined]);
  });

  it('drops the target, and still sends the call, when the rules cannot be loaded', async () => {
    const { gateway, wire } = build(() => Promise.reject(new Error('store unreadable')));
    try {
      await gateway.recordToolCalls([toolCall('t-fail', `k=${orgValue}`)]);
    } finally {
      await gateway.close();
    }

    expect(wire).toHaveLength(1);
    expect(targetOf(wire[0])).toBeUndefined();
    expect(wire[0]?.attributes).toMatchObject({ tool_name: 'Bash' });
    expect(JSON.stringify(wire)).not.toContain(orgValue);
  });
});
