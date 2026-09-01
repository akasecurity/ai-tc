import type {
  AttachDeviceGrant as AttachDeviceGrantT,
  AttachDeviceRequest as AttachDeviceRequestT,
  AttachTokenResponse as AttachTokenResponseT,
  AuditEventBatchAck as AuditEventBatchAckT,
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
  AttachDeviceGrant,
  AttachTokenResponse,
  AuditEventBatchAck,
  IngestAck,
  PluginWhoami,
  PolicyBundle,
  RecordAuditEventBatch,
  RecordAuditEventRequest,
  ResolvedInventory,
} from '@akasecurity/schema';
import type { z } from 'zod';

import type { RemoteResponse } from './http.ts';
import { RemoteRequestError, RemoteRequestInvalid, RemoteResponseInvalid, send } from './http.ts';

// The seven routes an attached machine may call, and nothing else.
//
// The set is small on purpose and is the same set a deployment scopes a
// credential to: five writes and two self-scoped reads. There is deliberately
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
  auditEventsBatch: '/v1/audit-events/batch',
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
  /**
   * POST /v1/audit-events/batch — the same facts, several at a time.
   *
   * Falls back to the single-event route against a deployment that does not
   * have this one, so a device and a deployment can be upgraded weeks apart.
   */
  recordAuditEvents(events: readonly AuditEventSubmission[]): Promise<AuditEventBatchAckT>;
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

/**
 * Drop trailing slashes so a route can be appended without doubling one.
 *
 * A scan rather than `replace(/\/+$/, '')`, which is quadratic on a string that
 * is all slashes: the engine retries `\/+$` from each position and every attempt
 * walks to the end. The endpoint is not attacker-supplied in the ordinary case —
 * it comes from `settings.json` or an administrator's managed overlay — but it
 * crosses a trust boundary this module does not own, and a linear scan costs
 * nothing to prefer over reasoning about who can write that file.
 */
function withoutTrailingSlashes(endpoint: string): string {
  let end = endpoint.length;
  while (end > 0 && endpoint.charCodeAt(end - 1) === SLASH) end -= 1;
  return endpoint.slice(0, end);
}

const SLASH = '/'.charCodeAt(0);

export function createRemoteClient(options: RemoteClientOptions): RemoteClient {
  const base = withoutTrailingSlashes(options.endpoint);
  const url = (route: string): string => `${base}${route}`;
  const common = { apiKey: options.apiKey, timeoutMs: options.timeoutMs };

  /**
   * One audit event, validated then sent.
   *
   * A free function rather than a method, so the batch route's 404 fallback can
   * reach it without depending on how the returned object is called — a
   * destructured `recordAuditEvents` would lose `this` and take the fallback
   * into a TypeError on the one path that exists to be forgiving.
   */
  const sendOne = async (event: AuditEventSubmission): Promise<void> => {
    // Validated on the way OUT, not merely typed. This body is assembled from
    // several call sites and carries the one field a deployment refuses on
    // (`inspections[].ruleVersion` may not claim the capture namespace), so
    // catching it here names the defect instead of turning it into a 400 that a
    // fail-open forwarder swallows.
    //
    // Raised as `RemoteRequestInvalid` rather than letting the ZodError escape:
    // a caller that counts failures toward a circuit breaker cannot tell a raw
    // ZodError from a transport fault, so a deterministic local shape bug would
    // open the breaker, suppress every unrelated forward, and be reported as an
    // outage the control plane never had.
    const validated = RecordAuditEventRequest.safeParse(event);
    if (!validated.success) throw new RemoteRequestInvalid(ROUTES.auditEvents, validated.error);
    const response = await send({
      ...common,
      method: 'POST',
      url: url(ROUTES.auditEvents),
      body: JSON.stringify(validated.data),
    });
    okBody(response);
  };

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
      await sendOne(event);
    },

    async recordAuditEvents(events) {
      // Validated on the way OUT, like the single-event route and for the same
      // reason: this body carries the one field a deployment refuses on, and
      // catching it here names the defect instead of turning it into a 400 a
      // fail-open caller swallows.
      const validated = RecordAuditEventBatch.safeParse({ events });
      if (!validated.success) {
        throw new RemoteRequestInvalid(ROUTES.auditEventsBatch, validated.error);
      }
      const response = await send({
        ...common,
        method: 'POST',
        url: url(ROUTES.auditEventsBatch),
        body: JSON.stringify(validated.data),
      });

      // A DEPLOYMENT THAT PREDATES THIS ROUTE answers 404, and that is not a
      // failure — it is an older deployment saying it only speaks the
      // single-event form. Handled here rather than above, because `okBody`
      // throws away the response before a caller could look at its status, and
      // handled here rather than in the caller because a forward policy
      // collapses every failure into one reason and could not tell 404 from an
      // outage. The fallback is the same rows, one request each: slower, and
      // exactly what this route exists to avoid, but correct.
      if (response.status === 404) {
        for (const event of validated.data.events) await sendOne(event);
        return { accepted: validated.data.events.length };
      }

      return parsed(AuditEventBatchAck, okBody(response), ROUTES.auditEventsBatch);
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

// ─── Attaching: the two routes a machine calls before it has a credential ────

const ATTACH_ROUTES = {
  device: '/v1/attach/device',
  token: '/v1/attach/token',
} as const;

/**
 * The client for a machine that has NOT been attached yet.
 *
 * Separate from `createRemoteClient` on purpose, and the separation is the
 * safety property rather than tidiness. These two routes are how a credential
 * comes into existence, so they are the only ones this package may call without
 * one — and a caller cannot reach any OTHER route through this object, because
 * it does not know how to build one. The alternative, an optional `apiKey` on
 * the main client, would mean a caller who forgot to pass a credential would
 * silently talk to a deployment unauthenticated on every route.
 *
 * The same guarantees `send` holds for the attached client hold here: no
 * redirects, a deadline on every request, a body cap, a protocol upgrade
 * refused, and plain `http` only for a loopback endpoint the caller has already
 * checked with `isSafeEndpoint`.
 */
export interface AttachClient {
  /** POST /v1/attach/device — start a grant and get the codes to display. */
  startGrant(request: AttachDeviceRequestT): Promise<AttachDeviceGrantT>;
  /** POST /v1/attach/token — ask whether anyone has decided yet. */
  poll(deviceCode: string): Promise<AttachTokenResponseT>;
  /**
   * Whether this deployment offers the flow at all.
   *
   * A 404 from `startGrant` means one of two things a caller cannot tell apart
   * and does not need to: the deployment predates the flow, or has not switched
   * it on. Both mean "fall back to the key prompt", which is why the CLI probes
   * rather than requiring a version handshake.
   */
  readonly notOfferedStatus: 404;
}

export function createAttachClient(options: {
  /** Where the deployment lives, already checked with `isSafeEndpoint`. */
  endpoint: string;
  timeoutMs?: number | undefined;
}): AttachClient {
  const base = withoutTrailingSlashes(options.endpoint);
  const common = { timeoutMs: options.timeoutMs };

  return {
    notOfferedStatus: 404,

    async startGrant(request) {
      const response = await send({
        ...common,
        method: 'POST',
        url: `${base}${ATTACH_ROUTES.device}`,
        body: JSON.stringify(request),
      });
      return parsed(AttachDeviceGrant, okBody(response), ATTACH_ROUTES.device);
    },

    async poll(deviceCode) {
      const response = await send({
        ...common,
        method: 'POST',
        url: `${base}${ATTACH_ROUTES.token}`,
        body: JSON.stringify({ deviceCode }),
      });
      // Parsed from a 2xx only. Every state this flow defines — including its
      // refusals — arrives as a 200 with a body naming it, so a non-2xx here is
      // a transport or deployment fault rather than an answer, and `okBody`
      // turning it into a status-only error is the right shape.
      return parsed(AttachTokenResponse, okBody(response), ATTACH_ROUTES.token);
    },
  };
}
