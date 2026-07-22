import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type {
  DataClass,
  DestinationKind,
  DestinationNetwork,
  EgressDecision,
  HttpMethod,
  ShareTrustLevel,
  Transport,
} from '@akasecurity/schema';

import { normalizeHost, shareCallSiteId, shareDestinationId, shareEndpointId } from '../ids.ts';
import { sampleProjectId } from './sample-ids.ts';

/**
 * TEST FIXTURE (see ./index.ts): the Data Shares sample dataset. trust/status/
 * network are DERIVED on read from kind/trust/transport (+ any override), so only
 * the base rows live here. Every row is tagged provenance='sample' — exactly what
 * sample-purge.ts deletes, which the shares tests exercise. `lastSeenMinAgo` is
 * materialized to an epoch-millis integer relative to seed time.
 */

interface SeedSite {
  project: string;
  file: string;
  line: number;
  snippet: string;
  dynamic?: boolean;
  vendored?: boolean;
  projectId?: string | null;
}
interface SeedEndpoint {
  method: HttpMethod;
  transport: Transport;
  url: string;
  template?: boolean;
  dataClass: DataClass;
  lastSeenMinAgo: number;
  sites: SeedSite[];
}
interface SeedDest {
  kind: DestinationKind;
  name: string;
  host: string;
  category: string;
  trust: ShareTrustLevel;
  note?: string | null;
  network?: DestinationNetwork | null;
  decision?: EgressDecision;
  lastSeenMinAgo: number;
  endpoints: SeedEndpoint[];
}

const SAMPLE_DESTS: SeedDest[] = [
  {
    kind: 'provider',
    name: 'Prometheus',
    host: 'prometheus-obs.io',
    category: 'Observability',
    trust: 'recognized',
    lastSeenMinAgo: 2,
    endpoints: [
      {
        method: 'POST',
        transport: 'https',
        url: 'https://logs.prometheus-obs.io/v1/ingest',
        dataClass: 'logs',
        lastSeenMinAgo: 2,
        sites: [
          {
            project: 'payments-api',
            file: 'src/observability/logger.ts',
            line: 34,
            snippet: 'prom.send(JSON.stringify(logBatch))',
            projectId: 'payments-api',
          },
          {
            project: 'crm-sync',
            file: 'src/log.py',
            line: 21,
            snippet: 'requests.post(PROM_LOG_URL, json=records)',
          },
        ],
      },
      {
        method: 'POST',
        transport: 'https',
        url: 'https://metrics.prometheus-obs.io/v1/traces/${projectId}',
        template: true,
        dataClass: 'telemetry',
        lastSeenMinAgo: 5,
        sites: [
          {
            project: 'payments-api',
            file: 'src/observability/metrics.ts',
            line: 58,
            snippet: 'fetch(promUrl(projectId), { method: "POST" })',
            dynamic: true,
            projectId: 'payments-api',
          },
        ],
      },
    ],
  },
  {
    kind: 'provider',
    name: 'PaymentHub',
    host: 'paymenthub.io',
    category: 'Payments',
    trust: 'recognized',
    lastSeenMinAgo: 1,
    endpoints: [
      {
        method: 'POST',
        transport: 'https',
        url: 'https://api.paymenthub.io/v2/charges',
        dataClass: 'customer',
        lastSeenMinAgo: 1,
        sites: [
          {
            project: 'payments-api',
            file: 'src/services/charge.ts',
            line: 42,
            snippet: 'paymenthub.charges.create({ amount, source, customer })',
            projectId: 'payments-api',
          },
        ],
      },
      {
        method: 'POST',
        transport: 'https',
        url: 'https://api.paymenthub.io/v2/customers',
        dataClass: 'pii',
        lastSeenMinAgo: 20,
        sites: [
          {
            project: 'payments-api',
            file: 'src/services/customer.ts',
            line: 19,
            snippet: 'paymenthub.customers.create({ email, name, phone })',
            projectId: 'payments-api',
          },
        ],
      },
    ],
  },
  {
    kind: 'internal',
    name: 'globex.com',
    host: 'globex.com',
    category: 'Internal services',
    trust: 'internal',
    note: 'Registrable domain matches your organization.',
    network: { port: null, geo: null, ptr: null },
    lastSeenMinAgo: 3,
    endpoints: [
      {
        method: 'GET',
        transport: 'https',
        url: 'https://vault.globex.com/v1/secret/data/${path}',
        template: true,
        dataClass: 'secrets',
        lastSeenMinAgo: 3,
        sites: [
          {
            project: 'payments-api',
            file: 'src/config/secrets.ts',
            line: 14,
            snippet: 'vault.read(`secret/data/${svc}/db`)',
            dynamic: true,
            projectId: 'payments-api',
          },
        ],
      },
    ],
  },
  {
    kind: 'internal',
    name: 'acme-partner.com',
    host: 'acme-partner.com',
    category: 'External partner',
    trust: 'unverified',
    note: 'Corporate-looking domain that does NOT match your organization. Ownership unverified.',
    network: { port: null, geo: null, ptr: null },
    lastSeenMinAgo: 300,
    endpoints: [
      {
        method: 'PUT',
        transport: 'sftp',
        url: 'sftp://sftp.acme-partner.com:22/uploads/${date}/settlement.csv',
        template: true,
        dataClass: 'pii',
        lastSeenMinAgo: 300,
        sites: [
          {
            project: 'payments-api',
            file: 'src/jobs/settlement.ts',
            line: 52,
            snippet: 'sftp.put(localPath, `/uploads/${date}/settlement.csv`)',
            dynamic: true,
            projectId: 'payments-api',
          },
        ],
      },
    ],
  },
  {
    kind: 'ip',
    name: '203.0.113.6',
    host: '203.0.113.6',
    category: 'Unresolved host',
    trust: 'ip',
    network: { port: 8080, geo: 'Unknown · AS63949 Akamai/Linode', ptr: null },
    decision: 'block',
    lastSeenMinAgo: 22,
    endpoints: [
      {
        method: 'POST',
        transport: 'http',
        url: 'http://203.0.113.6:8080/collect',
        dataClass: 'telemetry',
        lastSeenMinAgo: 22,
        sites: [
          {
            project: 'matching-core',
            file: 'vendor/analytics-sdk/client.rs',
            line: 210,
            snippet: 'TcpStream::connect("203.0.113.6:8080")',
            dynamic: true,
            vendored: true,
          },
        ],
      },
    ],
  },
];

/** Inserts the sample Data Shares dataset (provenance='sample'). */
export function seedSampleShares(db: DatabaseSync, now: number = Date.now()): void {
  const insDest = db.prepare(
    `INSERT OR IGNORE INTO share_destination
       (id, kind, name, host, category, trust, note, network_json, last_seen, provenance, created_at, updated_at)
     VALUES (:id, :kind, :name, :host, :category, :trust, :note, :networkJson, :lastSeen, 'sample', :now, :now)`,
  );
  const insEndpoint = db.prepare(
    `INSERT OR IGNORE INTO share_endpoint
       (id, destination_id, method, transport, url, template, data_class, last_seen, created_at, updated_at)
     VALUES (:id, :destinationId, :method, :transport, :url, :template, :dataClass, :lastSeen, :now, :now)`,
  );
  const insSite = db.prepare(
    `INSERT OR IGNORE INTO share_call_site
       (id, endpoint_id, project, file, line, snippet, dynamic, vendored, project_id, created_at, updated_at)
     VALUES (:id, :endpointId, :project, :file, :line, :snippet, :dynamic, :vendored, :projectId, :now, :now)`,
  );
  const insDecision = db.prepare(
    `INSERT OR IGNORE INTO egress_decision_override
       (id, destination_id, decision, created_at, updated_at)
     VALUES (:id, :destinationId, :decision, :now, :now)`,
  );
  const minAgo = (m: number): number => now - m * 60_000;

  for (const dest of SAMPLE_DESTS) {
    const host = normalizeHost(dest.host);
    const destId = shareDestinationId(host);
    insDest.run({
      id: destId,
      kind: dest.kind,
      name: dest.name,
      host,
      category: dest.category,
      trust: dest.trust,
      note: dest.note ?? null,
      networkJson: dest.network ? JSON.stringify(dest.network) : null,
      lastSeen: minAgo(dest.lastSeenMinAgo),
      now,
    });
    if (dest.decision) {
      insDecision.run({
        id: randomUUID(),
        destinationId: destId,
        decision: dest.decision,
        now,
      });
    }
    for (const ep of dest.endpoints) {
      const epId = shareEndpointId(destId, ep.method, ep.url);
      insEndpoint.run({
        id: epId,
        destinationId: destId,
        method: ep.method,
        transport: ep.transport,
        url: ep.url,
        template: ep.template ? 1 : 0,
        dataClass: ep.dataClass,
        lastSeen: minAgo(ep.lastSeenMinAgo),
        now,
      });
      for (const site of ep.sites) {
        insSite.run({
          id: shareCallSiteId(epId, site.project, site.file, site.line),
          endpointId: epId,
          project: site.project,
          file: site.file,
          line: site.line,
          snippet: site.snippet,
          dynamic: site.dynamic ? 1 : 0,
          vendored: site.vendored ? 1 : 0,
          // Store the Inventory sample project's source_project id (not the bare
          // slug) so a future call-site → Inventory-project drill-down resolves.
          projectId: site.projectId ? sampleProjectId(site.projectId) : null,
          now,
        });
      }
    }
  }
}
