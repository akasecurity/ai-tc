import type {
  IngestAck as IngestAckT,
  IngestBatch,
  InventoryContext,
  PluginWhoami as PluginWhoamiT,
  PolicyBundle as PolicyBundleT,
  RecordAuditEventRequest as AuditEventSubmission,
  ResolvedInventory as ResolvedInventoryT,
  StorePostureSnapshot,
} from '@akasecurity/schema';
import {
  IngestAck,
  PluginWhoami,
  PolicyBundle,
  RecordAuditEventRequest,
  ResolvedInventory,
} from '@akasecurity/schema';
import type { z } from 'zod';

import type { RemoteResponse } from './http.ts';
import { RemoteRequestError, RemoteRequestInvalid, RemoteResponseInvalid, send } from './http.ts';

// The six routes an attached machine may call, and nothing else.
//
// The set is small on purpose and is the same set a deployment scopes a
// credential to: four writes and two self-scoped reads. There is deliberately
// no way to ask this client for anything organization-wide — a credential on a
// laptop should not be able to read what other people's machines reported, and
// a client that cannot express the request is a stronger guarantee than a
// server that refuses it.
//
// Every response is PARSED, never cast. The bodies arrive from a host named in
// a settings file, so "the deployment said so" is not a type guarantee; a
// malformed answer becomes a rejection here rather than a shape that fails
// somewhere further in with no idea where it came from.

const ROUTES = {
  events: '/v1/events',
  auditEvents: '/v1/audit-events',
  inventory: '/v1/inventory',
  storePosture: '/v1/store-posture',
  policyBundle: '/v1/policy-bundle',
  whoami: '/v1/plugin/whoami',
} as const;

export interface RemoteClientOptions {
  /** Where the deployment lives, already checked with `isSafeEndpoint`. */
  endpoint: string;
  apiKey: string;
  timeoutMs?: number | undefined;
}

/**
 * The policy bundle, or a statement that the cached one is still current.
 *
 * A conditional GET is the whole reason this is a union: the bundle is fetched
 * on a schedule and rarely changes, so the ordinary answer is 304 and the
 * client should not re-parse or re-write what it already holds.
 */
export type ConditionalBundle =
  | { changed: false; etag: string | undefined }
  | { changed: true; bundle: PolicyBundleT; etag: string | undefined };

export interface RemoteClient {
  /** POST /v1/events — the capture batch. */
  ingestEvents(batch: IngestBatch): Promise<IngestAckT>;
  /** POST /v1/inventory — resolve this machine's inventory into the deployment's id space. */
  ingestInventory(context: InventoryContext): Promise<ResolvedInventoryT>;
  /** POST /v1/audit-events — one audit fact (session root, llm call, tool call, config scan). */
  recordAuditEvent(event: AuditEventSubmission): Promise<void>;
  /** POST /v1/store-posture — the hourly self-report. */
  reportStorePosture(snapshot: StorePostureSnapshot): Promise<void>;
  /** GET /v1/policy-bundle, conditional on a cached ETag. */
  getPolicyBundle(etag?: string): Promise<ConditionalBundle>;
  /** GET /v1/plugin/whoami — who this credential belongs to. */
  whoami(): Promise<PluginWhoamiT>;
}

/** Header value as a single string; Node reports repeats as an array. */
function headerValue(response: RemoteResponse, name: string): string | undefined {
  const raw = response.headers[name];
  if (raw === undefined) return undefined;
  return Array.isArray(raw) ? raw[0] : raw;
}

/**
 * Turn an answered response into a body, or throw.
 *
 * Any non-2xx becomes a `RemoteRequestError` carrying the status alone. The
 * caller never sees the body of a failure, which is what keeps a
 * server-authored string out of a log line or a status surface.
 */
function okBody(response: RemoteResponse): string {
  if (response.status < 200 || response.status >= 300) {
    throw new RemoteRequestError(response.status);
  }
  return response.body;
}

/** Parse a 2xx body with the shape the route promises. */
function parsed<T>(schema: z.ZodType<T>, body: string, route: string): T {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    throw new RemoteResponseInvalid(route, 'a body that is not JSON');
  }
  const result = schema.safeParse(json);
  if (!result.success) {
    throw new RemoteResponseInvalid(route, 'a body this client cannot read');
  }
  return result.data;
}

export function createRemoteClient(options: RemoteClientOptions): RemoteClient {
  const base = options.endpoint.replace(/\/+$/, '');
  const url = (route: string): string => `${base}${route}`;
  const common = { apiKey: options.apiKey, timeoutMs: options.timeoutMs };

  return {
    async ingestEvents(batch) {
      const response = await send({
        ...common,
        method: 'POST',
        url: url(ROUTES.events),
        body: JSON.stringify(batch),
      });
      return parsed(IngestAck, okBody(response), ROUTES.events);
    },

    async ingestInventory(context) {
      const response = await send({
        ...common,
        method: 'POST',
        url: url(ROUTES.inventory),
        body: JSON.stringify(context),
      });
      return parsed(ResolvedInventory, okBody(response), ROUTES.inventory);
    },

    async recordAuditEvent(event) {
      // Validated on the way OUT, not merely typed. This body is assembled
      // from several call sites and carries the one field a deployment refuses
      // on (`inspections[].ruleVersion` may not claim the capture namespace),
      // so catching it here names the defect instead of turning it into a 400
      // that a fail-open forwarder swallows.
      //
      // Raised as `RemoteRequestInvalid` rather than letting the ZodError
      // escape: a caller that counts failures toward a circuit breaker cannot
      // tell a raw ZodError from a transport fault, so a deterministic local
      // shape bug would open the breaker, suppress every unrelated forward, and
      // be reported as an outage the control plane never had.
      const validated = RecordAuditEventRequest.safeParse(event);
      if (!validated.success) throw new RemoteRequestInvalid(ROUTES.auditEvents, validated.error);
      const submission = validated.data;
      const response = await send({
        ...common,
        method: 'POST',
        url: url(ROUTES.auditEvents),
        body: JSON.stringify(submission),
      });
      okBody(response);
    },

    async reportStorePosture(snapshot) {
      const response = await send({
        ...common,
        method: 'POST',
        url: url(ROUTES.storePosture),
        body: JSON.stringify(snapshot),
      });
      okBody(response);
    },

    async getPolicyBundle(etag) {
      const response = await send({
        ...common,
        method: 'GET',
        url: url(ROUTES.policyBundle),
        ...(etag === undefined ? {} : { headers: { 'if-none-match': etag } }),
      });

      if (response.status === 304) {
        // Carry the presented validator forward when the 304 omits one.
        // Dropping it would send the NEXT request unconditionally, and the
        // deployment would answer with a full bundle every time — turning a
        // cheap poll into a full transfer on a schedule.
        return { changed: false, etag: headerValue(response, 'etag') ?? etag };
      }

      const bundle = parsed(PolicyBundle, okBody(response), ROUTES.policyBundle);
      return { changed: true, bundle, etag: headerValue(response, 'etag') };
    },

    async whoami() {
      const response = await send({ ...common, method: 'GET', url: url(ROUTES.whoami) });
      return parsed(PluginWhoami, okBody(response), ROUTES.whoami);
    },
  };
}
