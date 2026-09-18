// Shared fixtures for the Data Shares client suites. Kept minimal — most cases
// build their own inline shape — but this one is used identically by both the
// static-render and the jsdom interaction suite, so a single copy is what
// keeps them from drifting apart under independent edits.

/** A single provider group carrying two hosts that share `providerId: 'github'`. */
export function twoHostProviderGroup() {
  const host = (id: string, name: string, hostname: string) => ({
    id,
    kind: 'provider' as const,
    name,
    host: hostname,
    providerId: 'github',
    category: 'Dev tools',
    trust: 'recognized' as const,
    status: 'allowed' as const,
    isCustom: false,
    lastSeen: '2026-07-01T00:00:00.000Z',
    endpointCount: 1,
    callSiteCount: 1,
    transports: ['https' as const],
    dataClasses: ['pii' as const],
    review: { needsReview: false, reasons: [] },
    network: null,
    endpoints: [],
  });
  return {
    kind: 'provider' as const,
    total: 2,
    items: [
      host('dest-github-1', 'GitHub', 'api.github.com'),
      host('dest-github-2', 'GitHub Raw', 'raw.githubusercontent.com'),
    ],
  };
}
