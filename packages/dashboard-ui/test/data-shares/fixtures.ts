import type {
  EndpointSummary,
  EndpointWithSites,
  ReviewDestination,
  ShareDestinationDetail,
  ShareDestinationGroup,
  ShareDestinationSummary,
} from '@akasecurity/schema';

export function endpoint(overrides: Partial<EndpointSummary> = {}): EndpointSummary {
  return {
    id: 'ep-1',
    method: 'GET',
    transport: 'https',
    url: 'https://api.example.com/v1/things',
    template: false,
    dataClass: 'pii',
    lastSeen: '2026-07-01T00:00:00.000Z',
    callSiteCount: 1,
    ...overrides,
  };
}

export function destination(
  overrides: Partial<ShareDestinationSummary> = {},
): ShareDestinationSummary {
  return {
    id: 'dest-1',
    kind: 'provider',
    name: 'Okta',
    host: 'okta.com',
    providerId: 'okta',
    category: 'Identity',
    trust: 'recognized',
    status: 'allowed',
    isCustom: false,
    lastSeen: '2026-07-01T00:00:00.000Z',
    endpointCount: 1,
    callSiteCount: 1,
    transports: ['https'],
    dataClasses: ['pii'],
    review: { needsReview: false, reasons: [] },
    network: null,
    endpoints: [endpoint()],
    ...overrides,
  };
}

export function endpointWithSites(overrides: Partial<EndpointWithSites> = {}): EndpointWithSites {
  return { ...endpoint(), sites: [], ...overrides };
}

export function destinationDetail(
  overrides: Partial<ShareDestinationDetail> = {},
): ShareDestinationDetail {
  return {
    id: 'dest-1',
    kind: 'provider',
    name: 'Okta',
    host: 'okta.com',
    providerId: 'okta',
    category: 'Identity',
    trust: 'recognized',
    status: 'allowed',
    isCustom: false,
    lastSeen: '2026-07-01T00:00:00.000Z',
    transports: ['https'],
    dataClasses: ['pii'],
    review: { needsReview: false, reasons: [] },
    network: null,
    note: null,
    endpoints: [endpointWithSites()],
    ...overrides,
  };
}

export function group(overrides: Partial<ShareDestinationGroup> = {}): ShareDestinationGroup {
  return { kind: 'provider', total: 1, items: [destination()], ...overrides };
}

export function reviewDestination(overrides: Partial<ReviewDestination> = {}): ReviewDestination {
  return {
    id: 'dest-ip-1',
    kind: 'ip',
    name: '203.0.113.0',
    host: '203.0.113.0',
    providerId: null,
    trust: 'ip',
    status: 'review',
    review: { needsReview: true, reasons: ['raw_ip'] },
    topDataClass: 'none',
    callSiteCount: 2,
    lastSeen: '2026-07-01T00:00:00.000Z',
    ...overrides,
  };
}
