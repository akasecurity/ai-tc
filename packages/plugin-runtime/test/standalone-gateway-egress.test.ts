import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME } from '@akasecurity/persistence';
import type { RecordProjectEgressInput, ResolvedEgressHit } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { StandaloneDataGateway } from '../src/standalone-gateway.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-standalone-egress-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** One resolved hit with recognized-provider defaults; every field is overridable. */
function hit(o: Partial<ResolvedEgressHit> = {}): ResolvedEgressHit {
  const host = o.host ?? 'api.stripe.com';
  return {
    host,
    kind: o.kind ?? 'provider',
    name: o.name ?? host,
    category: o.category ?? 'Payments',
    trust: o.trust ?? 'recognized',
    network: o.network ?? null,
    method: o.method ?? 'POST',
    transport: o.transport ?? 'https',
    url: o.url ?? `https://${host}/v1/charges`,
    template: o.template ?? false,
    dataClass: o.dataClass ?? 'pii',
    site: {
      file: o.site?.file ?? 'src/pay.ts',
      line: o.site?.line ?? 12,
      snippet: o.site?.snippet ?? `fetch('https://${host}/v1/charges')`,
      dynamic: o.site?.dynamic ?? false,
      vendored: o.site?.vendored ?? false,
    },
  };
}

function input(hits: ResolvedEgressHit[]): RecordProjectEgressInput {
  return {
    projectKey: 'git:git@github.com:acme/payments-api.git',
    project: 'payments-api',
    projectId: null,
    reconcile: { mode: 'walk', walkedPrefix: '' },
    hits,
  };
}

describe('StandaloneDataGateway.recordProjectEgress', () => {
  it('writes destinations, endpoints and call sites for one hit', async () => {
    const gw = new StandaloneDataGateway(dir);
    await gw.recordProjectEgress(input([hit()]));
    await gw.close();

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const row = raw
      .prepare(
        `SELECT d.host AS host, e.method AS method, c.project_key AS projectKey
           FROM share_call_site c
           JOIN share_endpoint e ON e.id = c.endpoint_id
           JOIN share_destination d ON d.id = e.destination_id`,
      )
      .get() as { host: string; method: string; projectKey: string } | undefined;
    raw.close();

    expect(row).toEqual({
      host: 'api.stripe.com',
      method: 'POST',
      projectKey: 'git:git@github.com:acme/payments-api.git',
    });
  });

  it('rejects rather than resolving when the store is closed', async () => {
    const gw = new StandaloneDataGateway(dir);
    await gw.close();

    await expect(async () => gw.recordProjectEgress(input([hit()]))).rejects.toThrow();
  });
});
