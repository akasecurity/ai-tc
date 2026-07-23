import { describe, expect, it } from 'vitest';

import {
  EgressCallSiteHit,
  EgressEcosystem,
  EgressReconcile,
  EgressWriteSummary,
  ProviderRegistryEntry,
  RecordProjectEgressInput,
  ResolvedEgressHit,
} from '../../src/zod/egress-extraction.ts';

// ─── EgressEcosystem ──────────────────────────────────────────────────────────

describe('EgressEcosystem enum', () => {
  it('covers every package ecosystem the manifest scan attributes SDKs to', () => {
    expect(EgressEcosystem.options).toEqual([
      'npm',
      'pypi',
      'go',
      'maven',
      'rubygems',
      'cargo',
      'composer',
      'nuget',
    ]);
  });

  it('rejects an unsupported ecosystem', () => {
    expect(EgressEcosystem.safeParse('cpan').success).toBe(false);
  });
});

// ─── ProviderRegistryEntry ────────────────────────────────────────────────────

const validEntry = {
  id: 'newrelic',
  name: 'New Relic',
  category: 'Observability',
  hostSuffixes: ['newrelic.com'],
  apiBase: 'https://log-api.newrelic.com',
  defaultDataClasses: ['logs', 'telemetry'],
  sdks: { npm: ['newrelic'], pypi: ['newrelic'] },
};

describe('ProviderRegistryEntry', () => {
  it('parses a full registry entry', () => {
    expect(ProviderRegistryEntry.safeParse(validEntry).success).toBe(true);
  });

  it('allows a partial sdks map — an entry need not cover every ecosystem', () => {
    expect(ProviderRegistryEntry.safeParse({ ...validEntry, sdks: {} }).success).toBe(true);
  });

  it('rejects an unknown ecosystem key in sdks', () => {
    const result = ProviderRegistryEntry.safeParse({
      ...validEntry,
      sdks: { cpan: ['NewRelic'] },
    });
    expect(result.success).toBe(false);
  });

  it('requires at least one host suffix and one default data class', () => {
    expect(ProviderRegistryEntry.safeParse({ ...validEntry, hostSuffixes: [] }).success).toBe(
      false,
    );
    expect(ProviderRegistryEntry.safeParse({ ...validEntry, defaultDataClasses: [] }).success).toBe(
      false,
    );
  });

  it('rejects a data class outside the DataClass enum', () => {
    expect(
      ProviderRegistryEntry.safeParse({ ...validEntry, defaultDataClasses: ['financial'] }).success,
    ).toBe(false);
  });
});

// ─── EgressCallSiteHit ────────────────────────────────────────────────────────

const validSite = {
  file: 'src/clients/billing.ts',
  line: 42,
  snippet: "await fetch('https://api.stripe.com/v1/charges')",
  dynamic: false,
  vendored: false,
};

describe('EgressCallSiteHit', () => {
  it('parses a valid call-site hit', () => {
    expect(EgressCallSiteHit.safeParse(validSite).success).toBe(true);
  });

  it('requires a positive line number — line 0 is not a source location', () => {
    expect(EgressCallSiteHit.safeParse({ ...validSite, line: 0 }).success).toBe(false);
  });
});

// ─── ResolvedEgressHit ────────────────────────────────────────────────────────

const validHit = {
  host: 'api.stripe.com',
  kind: 'provider',
  name: 'Stripe',
  category: 'Payments',
  trust: 'recognized',
  network: null,
  method: 'POST',
  transport: 'https',
  url: 'https://api.stripe.com/v1/charges',
  template: false,
  dataClass: 'pii',
  site: validSite,
};

describe('ResolvedEgressHit', () => {
  it('parses a resolved provider hit with a null network', () => {
    expect(ResolvedEgressHit.safeParse(validHit).success).toBe(true);
  });

  it('parses an external hit carrying unverified trust', () => {
    const external = {
      ...validHit,
      host: 'api.acme-partner.com',
      kind: 'external',
      name: 'api.acme-partner.com',
      category: 'External domain',
      trust: 'unverified',
      dataClass: 'none',
    };
    expect(ResolvedEgressHit.safeParse(external).success).toBe(true);
  });

  it('parses a manifest-derived SDK hit', () => {
    expect(ResolvedEgressHit.safeParse({ ...validHit, method: 'SDK' }).success).toBe(true);
  });

  it('parses a websocket hit', () => {
    expect(
      ResolvedEgressHit.safeParse({
        ...validHit,
        method: 'REF',
        transport: 'wss',
        url: 'wss://stream.stripe.com/v1/events',
      }).success,
    ).toBe(true);
  });

  it('parses an IP hit with a populated network', () => {
    const ipHit = {
      ...validHit,
      host: '203.0.113.6',
      kind: 'ip',
      name: '203.0.113.6',
      category: 'Unresolved host',
      trust: 'ip',
      network: { port: 8080, geo: null, ptr: null },
    };
    expect(ResolvedEgressHit.safeParse(ipHit).success).toBe(true);
  });

  it('rejects a kind outside DestinationKind', () => {
    expect(ResolvedEgressHit.safeParse({ ...validHit, kind: 'saas' }).success).toBe(false);
  });
});

// ─── EgressReconcile ──────────────────────────────────────────────────────────

describe('EgressReconcile', () => {
  it("parses walk mode, including the whole-project '' prefix", () => {
    expect(EgressReconcile.safeParse({ mode: 'walk', walkedPrefix: '' }).success).toBe(true);
    expect(EgressReconcile.safeParse({ mode: 'walk', walkedPrefix: 'src/api' }).success).toBe(true);
  });

  it('parses ledger mode with scanned and deleted file lists', () => {
    expect(
      EgressReconcile.safeParse({
        mode: 'ledger',
        scannedFiles: ['src/a.ts'],
        deletedFiles: ['src/b.ts'],
      }).success,
    ).toBe(true);
  });

  it('parses ledger mode with both lists empty', () => {
    expect(
      EgressReconcile.safeParse({ mode: 'ledger', scannedFiles: [], deletedFiles: [] }).success,
    ).toBe(true);
  });

  it('discriminates on mode — walk fields do not satisfy ledger and vice versa', () => {
    expect(EgressReconcile.safeParse({ mode: 'walk', scannedFiles: [] }).success).toBe(false);
    expect(EgressReconcile.safeParse({ mode: 'ledger', walkedPrefix: '' }).success).toBe(false);
    expect(EgressReconcile.safeParse({ mode: 'project' }).success).toBe(false);
  });
});

// ─── RecordProjectEgressInput ─────────────────────────────────────────────────

const validInput = {
  projectKey: 'git:git@github.com:acme/payments-api.git',
  project: 'payments-api',
  projectId: null,
  reconcile: { mode: 'walk', walkedPrefix: '' },
  hits: [validHit],
};

describe('RecordProjectEgressInput', () => {
  it('parses a walk-mode recording unit with a null projectId', () => {
    expect(RecordProjectEgressInput.safeParse(validInput).success).toBe(true);
  });

  it('accepts an empty hits array — a clean project still reconciles', () => {
    expect(RecordProjectEgressInput.safeParse({ ...validInput, hits: [] }).success).toBe(true);
  });

  it('rejects an empty projectKey — reconciliation has no key to group on', () => {
    expect(RecordProjectEgressInput.safeParse({ ...validInput, projectKey: '' }).success).toBe(
      false,
    );
  });

  it('requires projectId to be present as an explicit null rather than omitted', () => {
    const withoutProjectId = {
      projectKey: validInput.projectKey,
      project: validInput.project,
      reconcile: validInput.reconcile,
      hits: validInput.hits,
    };
    expect(RecordProjectEgressInput.safeParse(withoutProjectId).success).toBe(false);
  });
});

// ─── EgressWriteSummary ───────────────────────────────────────────────────────

describe('EgressWriteSummary', () => {
  it('parses a write summary', () => {
    expect(
      EgressWriteSummary.safeParse({
        destinations: 3,
        endpoints: 7,
        callSites: 12,
        truncated: false,
      }).success,
    ).toBe(true);
  });

  it('surfaces truncation explicitly rather than silently capping', () => {
    const parsed = EgressWriteSummary.parse({
      destinations: 1,
      endpoints: 1,
      callSites: 5000,
      truncated: true,
    });
    expect(parsed.truncated).toBe(true);
  });

  it('rejects negative counts', () => {
    expect(
      EgressWriteSummary.safeParse({
        destinations: -1,
        endpoints: 0,
        callSites: 0,
        truncated: false,
      }).success,
    ).toBe(false);
  });
});
