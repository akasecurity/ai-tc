import { describe, expect, it } from 'vitest';

import { RescanResponse, TrustLevel } from './inventory.ts';
import {
  CallSite,
  DATA_CLASS_ORDER,
  DataClass,
  DestinationKind,
  DestinationNetwork,
  EgressDecision,
  EgressStatus,
  EndpointSummary,
  EndpointWithSites,
  ExportSharesQuery,
  HttpMethod,
  ListShareDestinationsQuery,
  NeedsReviewResponse,
  ReviewDestination,
  ReviewInfo,
  ReviewReason,
  SetEgressDecisionBody,
  SetEgressDecisionResponse,
  ShareDestinationDetail,
  ShareDestinationGroup,
  ShareDestinationSummary,
  SharesStats,
  ShareTrustLevel,
  Transport,
} from './shares.ts';

// ─── Enums ────────────────────────────────────────────────────────────────────

describe('DestinationKind enum', () => {
  it('accepts provider, internal, ip', () => {
    for (const v of ['provider', 'internal', 'ip']) {
      expect(DestinationKind.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(DestinationKind.safeParse('saas').success).toBe(false);
  });
});

describe('Transport enum', () => {
  it('accepts https, http, sftp, grpc, smtp', () => {
    for (const v of ['https', 'http', 'sftp', 'grpc', 'smtp']) {
      expect(Transport.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(Transport.safeParse('ftp').success).toBe(false);
  });
});

describe('DataClass enum', () => {
  it('accepts all 8 values in sensitivity order', () => {
    expect(DataClass.options).toEqual([
      'secrets',
      'pii',
      'customer',
      'source',
      'telemetry',
      'logs',
      'metrics',
      'none',
    ]);
  });

  it('rejects invalid values', () => {
    expect(DataClass.safeParse('financial').success).toBe(false);
  });

  it('DATA_CLASS_ORDER mirrors the enum declaration order', () => {
    expect(DATA_CLASS_ORDER).toEqual(DataClass.options);
  });
});

describe('ShareTrustLevel enum', () => {
  it('accepts recognized, internal, unverified, ip', () => {
    for (const v of ['recognized', 'internal', 'unverified', 'ip']) {
      expect(ShareTrustLevel.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(ShareTrustLevel.safeParse('known-good').success).toBe(false);
  });

  // id-collision guard: inventory.ts already exports `TrustLevel` with a
  // distinct value set (known-good/risky/unapproved) and OpenAPI component id
  // 'TrustLevel'. ShareTrustLevel MUST carry a distinct id so gen:openapi:check
  // never collides two different component schemas under the same key.
  it('does not collide with inventory.ts TrustLevel — distinct meta id and value set', () => {
    expect(ShareTrustLevel.meta()?.id).toBe('ShareTrustLevel');
    expect(TrustLevel.meta()?.id).toBe('TrustLevel');
    expect(ShareTrustLevel.meta()?.id).not.toBe(TrustLevel.meta()?.id);
    expect(ShareTrustLevel.options).not.toEqual(TrustLevel.options);
  });
});

describe('EgressDecision enum', () => {
  it('accepts allow, block', () => {
    for (const v of ['allow', 'block']) {
      expect(EgressDecision.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(EgressDecision.safeParse('deny').success).toBe(false);
  });
});

describe('EgressStatus enum', () => {
  it('accepts allowed, blocked, review', () => {
    for (const v of ['allowed', 'blocked', 'review']) {
      expect(EgressStatus.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(EgressStatus.safeParse('pending').success).toBe(false);
  });
});

describe('ReviewReason enum', () => {
  it('accepts raw_ip, unverified_domain, plaintext_transport', () => {
    for (const v of ['raw_ip', 'unverified_domain', 'plaintext_transport']) {
      expect(ReviewReason.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(ReviewReason.safeParse('other').success).toBe(false);
  });
});

describe('HttpMethod enum', () => {
  it('accepts GET, POST, PUT, DELETE', () => {
    for (const v of ['GET', 'POST', 'PUT', 'DELETE']) {
      expect(HttpMethod.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(HttpMethod.safeParse('PATCH').success).toBe(false);
  });
});

// ─── ReviewInfo / DestinationNetwork ──────────────────────────────────────────

describe('ReviewInfo', () => {
  it('parses needsReview true with reasons', () => {
    expect(
      ReviewInfo.safeParse({ needsReview: true, reasons: ['raw_ip', 'plaintext_transport'] })
        .success,
    ).toBe(true);
  });

  it('parses needsReview false with empty reasons', () => {
    expect(ReviewInfo.safeParse({ needsReview: false, reasons: [] }).success).toBe(true);
  });

  it('rejects unknown reason values', () => {
    expect(ReviewInfo.safeParse({ needsReview: true, reasons: ['expired'] }).success).toBe(false);
  });
});

describe('DestinationNetwork', () => {
  it('parses all-null (provider-like) network', () => {
    expect(DestinationNetwork.safeParse({ port: null, geo: null, ptr: null }).success).toBe(true);
  });

  it('parses a populated network', () => {
    expect(
      DestinationNetwork.safeParse({
        port: 8080,
        geo: 'Unknown · AS63949 Akamai/Linode',
        ptr: null,
      }).success,
    ).toBe(true);
  });
});

// ─── EndpointSummary / CallSite / EndpointWithSites ───────────────────────────

const validEndpoint = {
  id: 'ep_9f2a',
  method: 'POST',
  transport: 'https',
  url: 'https://log-api.newrelic.com/log/v1',
  template: false,
  dataClass: 'logs',
  lastSeen: '2026-07-03T21:58:00Z',
  callSiteCount: 2,
};

describe('EndpointSummary', () => {
  it('parses a valid endpoint summary', () => {
    expect(EndpointSummary.safeParse(validEndpoint).success).toBe(true);
  });

  it('callSiteCount must be a non-negative integer', () => {
    expect(EndpointSummary.safeParse({ ...validEndpoint, callSiteCount: -1 }).success).toBe(false);
  });

  it('lastSeen must be an ISO datetime string', () => {
    expect(EndpointSummary.safeParse({ ...validEndpoint, lastSeen: 'not-a-date' }).success).toBe(
      false,
    );
  });
});

const validCallSite = {
  id: 'cs_0a11',
  project: 'payments-api',
  file: 'src/jobs/settlement.ts',
  line: 52,
  snippet: 'sftp.put(localPath, `/uploads/${date}/settlement.csv`)',
  dynamic: true,
  vendored: false,
  projectId: 'payments-api',
};

describe('CallSite', () => {
  it('parses a valid call site', () => {
    expect(CallSite.safeParse(validCallSite).success).toBe(true);
  });

  it('projectId accepts null', () => {
    expect(CallSite.safeParse({ ...validCallSite, projectId: null }).success).toBe(true);
  });

  it('rejects negative line numbers', () => {
    expect(CallSite.safeParse({ ...validCallSite, line: -1 }).success).toBe(false);
  });
});

describe('EndpointWithSites', () => {
  it('extends EndpointSummary with a sites array', () => {
    const result = EndpointWithSites.safeParse({ ...validEndpoint, sites: [validCallSite] });
    expect(result.success).toBe(true);
  });

  it('sites can be empty', () => {
    expect(EndpointWithSites.safeParse({ ...validEndpoint, sites: [] }).success).toBe(true);
  });
});

// ─── ShareDestinationSummary / Detail / ReviewDestination ─────────────────────

const validSummary = {
  id: 'newrelic',
  kind: 'provider',
  name: 'New Relic',
  host: 'newrelic.com',
  category: 'Observability',
  trust: 'recognized',
  status: 'allowed',
  isCustom: false,
  lastSeen: '2026-07-03T21:58:00Z',
  endpointCount: 3,
  callSiteCount: 4,
  transports: ['https'],
  dataClasses: ['logs', 'telemetry', 'metrics'],
  review: { needsReview: false, reasons: [] },
  network: null,
  endpoints: [validEndpoint],
};

describe('ShareDestinationSummary', () => {
  it('parses a valid provider destination summary with null network', () => {
    expect(ShareDestinationSummary.safeParse(validSummary).success).toBe(true);
  });

  it('parses a valid ip destination summary with a populated network', () => {
    const ipSummary = {
      ...validSummary,
      id: 'ip-45-79-142-6',
      kind: 'ip',
      name: '45.79.142.6',
      host: '45.79.142.6',
      category: 'Unresolved host',
      trust: 'ip',
      status: 'review',
      transports: ['http'],
      review: { needsReview: true, reasons: ['raw_ip', 'plaintext_transport'] },
      network: { port: 8080, geo: 'Unknown · AS63949 Akamai/Linode', ptr: null },
    };
    expect(ShareDestinationSummary.safeParse(ipSummary).success).toBe(true);
  });

  it('rejects an invalid trust value', () => {
    expect(
      ShareDestinationSummary.safeParse({ ...validSummary, trust: 'known-good' }).success,
    ).toBe(false);
  });
});

describe('ShareDestinationDetail', () => {
  it('parses a full destination detail with note and endpoints[].sites[]', () => {
    const detail = {
      ...validSummary,
      note: null,
      endpoints: [{ ...validEndpoint, sites: [validCallSite] }],
    };
    // endpointCount/callSiteCount are omitted on the detail shape
    delete (detail as { endpointCount?: number }).endpointCount;
    delete (detail as { callSiteCount?: number }).callSiteCount;
    expect(ShareDestinationDetail.safeParse(detail).success).toBe(true);
  });

  it('note accepts null', () => {
    const { endpointCount, callSiteCount, ...rest } = validSummary;
    void endpointCount;
    void callSiteCount;
    const detail = { ...rest, note: null, endpoints: [{ ...validEndpoint, sites: [] }] };
    expect(ShareDestinationDetail.safeParse(detail).success).toBe(true);
  });
});

describe('ReviewDestination', () => {
  it('parses a trimmed review-mode item', () => {
    const item = {
      id: 'ip-198-51-100-23',
      kind: 'ip',
      name: '198.51.100.23',
      trust: 'ip',
      status: 'review',
      review: { needsReview: true, reasons: ['raw_ip'] },
      topDataClass: 'customer',
      callSiteCount: 1,
      lastSeen: '2026-07-03T17:00:00Z',
    };
    expect(ReviewDestination.safeParse(item).success).toBe(true);
  });
});

describe('ShareDestinationGroup', () => {
  it('parses a group with items', () => {
    expect(
      ShareDestinationGroup.safeParse({ kind: 'provider', total: 1, items: [validSummary] })
        .success,
    ).toBe(true);
  });
});

describe('NeedsReviewResponse', () => {
  it('accepts an empty items array', () => {
    expect(NeedsReviewResponse.safeParse({ items: [] }).success).toBe(true);
  });
});

// ─── SharesStats ──────────────────────────────────────────────────────────────

describe('SharesStats', () => {
  it('parses a realistic stats payload', () => {
    const result = SharesStats.safeParse({
      destinations: 12,
      endpoints: 18,
      callSites: 23,
      needsReview: 3,
      insecure: 1,
      byKind: { provider: 8, internal: 2, ip: 2 },
      byTrust: { recognized: 8, internal: 1, unverified: 1, ip: 2 },
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing byTrust keys', () => {
    const result = SharesStats.safeParse({
      destinations: 0,
      endpoints: 0,
      callSites: 0,
      needsReview: 0,
      insecure: 0,
      byKind: { provider: 0, internal: 0, ip: 0 },
      byTrust: { recognized: 0, internal: 0 },
    });
    expect(result.success).toBe(false);
  });
});

// ─── SetEgressDecisionBody / Response ────────────────────────────────────────

describe('SetEgressDecisionBody', () => {
  it('accepts allow, block, and null (clear)', () => {
    expect(SetEgressDecisionBody.safeParse({ decision: 'allow' }).success).toBe(true);
    expect(SetEgressDecisionBody.safeParse({ decision: 'block' }).success).toBe(true);
    expect(SetEgressDecisionBody.safeParse({ decision: null }).success).toBe(true);
  });

  it('rejects an invalid decision value', () => {
    expect(SetEgressDecisionBody.safeParse({ decision: 'maybe' }).success).toBe(false);
  });

  it('rejects a missing decision key', () => {
    expect(SetEgressDecisionBody.safeParse({}).success).toBe(false);
  });
});

describe('SetEgressDecisionResponse', () => {
  it('parses a response wrapping the updated destination', () => {
    expect(SetEgressDecisionResponse.safeParse({ destination: validSummary }).success).toBe(true);
  });
});

// ─── RescanResponse reuse ─────────────────────────────────────────────────────

describe('RescanResponse (reused from inventory.ts)', () => {
  it('is re-exported and parses the shared shape', () => {
    expect(
      RescanResponse.safeParse({ jobId: 'scan_abc', startedAt: '2026-07-03T21:45:00Z' }).success,
    ).toBe(true);
  });
});

// ─── Query schemas ────────────────────────────────────────────────────────────

describe('ListShareDestinationsQuery', () => {
  it('all fields optional — empty object succeeds with defaults', () => {
    const result = ListShareDestinationsQuery.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.groupBy).toBe('destination');
      expect(result.data.review).toBe(false);
    }
  });

  it('accepts q, kind[], and review=true', () => {
    expect(
      ListShareDestinationsQuery.safeParse({ q: 'settlement', kind: ['ip'], review: true }).success,
    ).toBe(true);
  });
});

describe('ExportSharesQuery', () => {
  it('defaults format to csv', () => {
    const result = ExportSharesQuery.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.format).toBe('csv');
    }
  });

  it('accepts format=json with filters', () => {
    expect(ExportSharesQuery.safeParse({ format: 'json', kind: ['provider'] }).success).toBe(true);
  });

  it('rejects an invalid format value', () => {
    expect(ExportSharesQuery.safeParse({ format: 'xml' }).success).toBe(false);
  });
});
