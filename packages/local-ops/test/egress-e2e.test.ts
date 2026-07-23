import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import type {
  DataClass,
  DestinationKind,
  ReviewReason,
  ShareDestinationSummary,
  ShareTrustLevel,
  Transport,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { recordProjectEgress } from '../src/egress-record.ts';
import { scanPathIntoStore } from '../src/fs-scan.ts';

// End-to-end acceptance for the CLI/web egress pipeline: walk a planted corpus
// with `scanPathIntoStore`, record it with `recordProjectEgress`, then read the
// store back through the Data Shares read port the dashboard uses.
//
// The corpus under fixtures/egress-corpus/ covers all eight supported
// ecosystems across nine manifest formats — package.json (npm),
// requirements.txt (PyPI), go.mod (Go), pom.xml and build.gradle (both Maven),
// Gemfile (RubyGems), Cargo.toml (Cargo), composer.json (Composer) and
// Api.csproj (NuGet) — plus URL and bare-IP literals in five languages, and a
// planted
// look-alike negative beside almost every positive: a provider SDK in
// devDependencies, a plugin coordinate in pom.xml's <build> block, a
// commented-out gem and PackageReference, a provider in Cargo's
// [dev-dependencies] and Composer's require-dev, provider hosts inside a
// lockfile, and a non-excluded host in a Markdown file. go.mod's `exclude`
// directive is the one negative that cannot sit in EXPECTED_ABSENT — it names
// the same provider as its `require` sibling — so it is guarded instead by the
// s3.amazonaws.com SDK endpoint staying at x1.
//
// EXPECTED_LEDGER below is asserted as an EXACT equality, not a subset. A
// missing provider is a recall failure and an extra host is a precision
// failure, and one assertion catches both.

const CORPUS = join(import.meta.dirname, 'fixtures', 'egress-corpus');
const REMOTE_URL = 'https://github.com/acme/settlement.git';

// Every destination the corpus must produce, and nothing else. `endpoints`
// entries are `<method> <transport> <url> x<call sites>`.
interface ExpectedDestination {
  host: string;
  kind: DestinationKind;
  trust: ShareTrustLevel;
  name: string;
  category: string;
  transports: Transport[];
  dataClasses: DataClass[];
  endpoints: string[];
}

const EXPECTED_LEDGER: ExpectedDestination[] = [
  {
    // src/transfer.rb — a bare public IPv4 named by an SFTP host constant.
    host: '198.51.100.23',
    kind: 'ip',
    trust: 'ip',
    name: '198.51.100.23',
    category: 'Unresolved host',
    transports: ['sftp'],
    dataClasses: ['none'],
    endpoints: ['REF sftp sftp://198.51.100.23:22 x1'],
  },
  {
    // src/partner.ts — the corpus's only plaintext destination, carrying both
    // an http endpoint and a ws one.
    host: 'api.acme-partner.com',
    kind: 'external',
    trust: 'unverified',
    name: 'api.acme-partner.com',
    category: 'External domain',
    transports: ['http', 'ws'],
    dataClasses: ['none'],
    endpoints: [
      // Both are bare `const` literals; the fetch below them uses the binding,
      // not the literal, so no verb is proven at either site.
      'REF http http://api.acme-partner.com/upload x1',
      'REF ws ws://api.acme-partner.com/status x1',
    ],
  },
  {
    // requirements.txt (PyPI).
    host: 'api.datadoghq.com',
    kind: 'provider',
    trust: 'recognized',
    name: 'Datadog',
    category: 'Observability',
    transports: ['https'],
    dataClasses: ['telemetry'],
    endpoints: ['SDK https https://api.datadoghq.com x1'],
  },
  {
    // src/pay.py — verb-first client API, the method is the first argument.
    host: 'api.segment.io',
    kind: 'provider',
    trust: 'recognized',
    name: 'Segment',
    category: 'Analytics',
    transports: ['https'],
    dataClasses: ['customer'],
    endpoints: ['POST https https://api.segment.io/v1/track x1'],
  },
  {
    // src/app.ts (multi-line fetch) plus four manifests: package.json (npm),
    // pom.xml (Maven), composer.json (Composer), Api.csproj (NuGet).
    host: 'api.stripe.com',
    kind: 'provider',
    trust: 'recognized',
    name: 'Stripe',
    category: 'Payments',
    transports: ['https'],
    dataClasses: ['pii'],
    endpoints: [
      'POST https https://api.stripe.com/v1/charges x1',
      'SDK https https://api.stripe.com x4',
    ],
  },
  {
    // services/go/main.go — verb-first client API, the Go spelling.
    host: 'api.twilio.com',
    kind: 'provider',
    trust: 'recognized',
    name: 'Twilio',
    category: 'Communications',
    transports: ['https'],
    dataClasses: ['pii'],
    endpoints: ['POST https https://api.twilio.com/2010-04-01/Messages.json x1'],
  },
  {
    // src/intra.ts — an internal TLD, and a bare client call with the URL as
    // its only argument, which is the one shape that proves a GET.
    host: 'db.internal',
    kind: 'internal',
    trust: 'internal',
    name: 'db.internal',
    category: 'Internal services',
    transports: ['https'],
    dataClasses: ['none'],
    endpoints: ['GET https https://db.internal/health x1'],
  },
  {
    // go.mod (Go) — matched by module-path prefix.
    host: 's3.amazonaws.com',
    kind: 'provider',
    trust: 'recognized',
    name: 'Amazon Web Services',
    category: 'Cloud platform',
    transports: ['https'],
    dataClasses: ['secrets'],
    endpoints: ['SDK https https://s3.amazonaws.com x1'],
  },
  {
    // build.gradle x2 (a platform() BOM and a plain coordinate), Gemfile,
    // Cargo.toml — plus a URL literal in the vendored client.
    host: 'sentry.io',
    kind: 'provider',
    trust: 'recognized',
    name: 'Sentry',
    category: 'Error tracking',
    transports: ['https'],
    dataClasses: ['source'],
    endpoints: ['REF https https://sentry.io/api/1/store/ x1', 'SDK https https://sentry.io x4'],
  },
  {
    // src/app.ts — an encrypted websocket to an unrecognized host.
    host: 'stream.acme-telemetry-live.com',
    kind: 'external',
    trust: 'unverified',
    name: 'stream.acme-telemetry-live.com',
    category: 'External domain',
    transports: ['wss'],
    dataClasses: ['none'],
    endpoints: ['REF wss wss://stream.acme-telemetry-live.com/v1/events x1'],
  },
  {
    // packages/nested/package.json — a manifest below the corpus root.
    host: 'us.i.posthog.com',
    kind: 'provider',
    trust: 'recognized',
    name: 'PostHog',
    category: 'Analytics',
    transports: ['https'],
    dataClasses: ['customer'],
    endpoints: ['SDK https https://us.i.posthog.com x1'],
  },
];

// Hosts planted in the corpus that must never reach the store. Each one is
// reachable only through a rule the extractor is required to apply: a scope
// exclusion (devDependencies, require-dev, [dev-dependencies], pom <build>), a
// comment, a lockfile, or the doc-extension gate.
const EXPECTED_ABSENT: Record<string, string> = {
  'api.openai.com': 'package.json devDependencies',
  'storage.googleapis.com': "pom.xml <build> plugin group id 'com.google.cloud.tools'",
  'api.mixpanel.com': 'a commented-out line in the Gemfile',
  'cloud.mongodb.com': 'Cargo.toml [dev-dependencies]',
  'login.auth0.com': 'composer.json require-dev',
  'login.okta.com': 'a commented-out PackageReference in Api.csproj',
  'registry.npmjs.org': 'resolved URLs in package-lock.json',
  'api.acme-docs-example-live.com': 'a non-excluded host in README.md',
};

// A minimal on-disk git repo: a `.git` DIRECTORY (what the identity resolver
// detects) whose `config` carries the remote the identity is derived from.
// Nothing on this path ever spawns git, so the config file is the whole repo
// as far as the pipeline is concerned.
function initRepo(root: string): void {
  mkdirSync(join(root, '.git'));
  writeFileSync(join(root, '.git', 'config'), `[remote "origin"]\n\turl = ${REMOTE_URL}\n`);
}

// Walk `target` and record whatever egress the walk produced — the exact
// two-call sequence the CLI and the web-ui Scan action perform.
function scanAndRecord(db: LocalDatabase, target: string, base: string) {
  const result = scanPathIntoStore(db, target, { rules: [] });
  return recordProjectEgress(db, target, result.egress, base);
}

// Flatten the grouped listing into the comparable ledger shape. Transports are
// sorted because their stored order follows endpoint insertion, which is walk
// order rather than anything the contract fixes.
function toLedger(items: ShareDestinationSummary[]): ExpectedDestination[] {
  return items
    .map((d) => ({
      host: d.host,
      kind: d.kind,
      trust: d.trust,
      name: d.name,
      category: d.category,
      transports: [...d.transports].sort(),
      dataClasses: d.dataClasses,
      endpoints: d.endpoints
        .map((e) => `${e.method} ${e.transport} ${e.url} x${String(e.callSiteCount)}`)
        .sort(),
    }))
    .sort((a, b) => a.host.localeCompare(b.host));
}

async function readLedger(db: LocalDatabase): Promise<ExpectedDestination[]> {
  const { groups } = await db.shares.listDestinations({ groupBy: 'destination', review: false });
  return toLedger(groups.flatMap((g) => g.items));
}

let root: string;
let store: string;
let base: string;
let db: LocalDatabase;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-corpus-'));
  store = mkdtempSync(join(tmpdir(), 'aka-corpus-db-'));
  base = mkdtempSync(join(tmpdir(), 'aka-corpus-home-'));
  cpSync(CORPUS, root, { recursive: true });
  initRepo(root);
  db = openLocalDatabase(store);
});

afterEach(() => {
  db.close();
  rmSync(root, { recursive: true, force: true });
  rmSync(store, { recursive: true, force: true });
  rmSync(base, { recursive: true, force: true });
});

describe('egress acceptance corpus — destination ledger', () => {
  it('records exactly the expected destinations across eight ecosystems', async () => {
    const recorded = scanAndRecord(db, root, base);

    expect(recorded).toEqual({
      project: 'settlement',
      destinations: EXPECTED_LEDGER.length,
      endpoints: 14,
      callSites: 20,
      truncated: false,
      droppedFiles: [],
    });
    expect(await readLedger(db)).toEqual(EXPECTED_LEDGER);
  });

  it('groups the ledger provider → internal → external → ip', async () => {
    scanAndRecord(db, root, base);

    const { groups } = await db.shares.listDestinations({ groupBy: 'destination', review: false });
    // KIND_ORDER filters the grouped response, so a kind missing from it is
    // dropped from the listing entirely while still counting in stats(). Both
    // are asserted so a filter regression cannot hide behind the other.
    expect(groups.map((g) => [g.kind, g.total])).toEqual([
      ['provider', 7],
      ['internal', 1],
      ['external', 2],
      ['ip', 1],
    ]);

    const stats = await db.shares.stats();
    expect(stats.destinations).toBe(EXPECTED_LEDGER.length);
    expect(stats.byKind).toEqual({ provider: 7, internal: 1, external: 2, ip: 1 });
    expect(stats.byTrust).toEqual({ recognized: 7, internal: 1, unverified: 2, ip: 1 });
    expect(stats.endpoints).toBe(14);
    expect(stats.callSites).toBe(20);
  });

  it('records none of the planted look-alike hosts', async () => {
    scanAndRecord(db, root, base);

    const hosts = new Set((await readLedger(db)).map((d) => d.host));
    for (const [host, why] of Object.entries(EXPECTED_ABSENT)) {
      expect(hosts.has(host), `${host} must not be recorded — it appears only in ${why}`).toBe(
        false,
      );
    }
  });

  it('marks the vendored call site and relativizes every path to the repo root', async () => {
    scanAndRecord(db, root, base);

    const { groups } = await db.shares.listDestinations({ groupBy: 'destination', review: false });
    const sentry = groups.flatMap((g) => g.items).find((d) => d.host === 'sentry.io')?.id;
    expect(sentry).toBeDefined();

    const detail = await db.shares.getDestination(sentry ?? '');
    const sites = (detail?.endpoints ?? []).flatMap((e) => e.sites);
    expect(sites.map((s) => `${s.file}:${String(s.vendored)}`).sort()).toEqual([
      'Cargo.toml:false',
      'Gemfile:false',
      'build.gradle:false',
      'build.gradle:false',
      'vendor/lib/client.rb:true',
    ]);
  });
});

describe('egress acceptance corpus — review posture', () => {
  it('agrees between the review read port and the stats counters', async () => {
    scanAndRecord(db, root, base);

    // needsReview() runs the SQL review pre-filter AND the schema's
    // buildReviewInfo; stats() counts the same posture through independent raw
    // SQL. Asserting both catches the two mirrors drifting apart.
    const { items } = await db.shares.needsReview();
    const byHost = new Map(items.map((i) => [i.host, i.review.reasons]));
    expect(new Set(byHost.keys())).toEqual(
      new Set(['198.51.100.23', 'api.acme-partner.com', 'stream.acme-telemetry-live.com']),
    );
    expect(byHost.get('198.51.100.23')).toEqual<ReviewReason[]>(['raw_ip']);
    expect(byHost.get('stream.acme-telemetry-live.com')).toEqual<ReviewReason[]>([
      'unverified_domain',
    ]);
    expect(byHost.get('api.acme-partner.com')).toEqual<ReviewReason[]>([
      'unverified_domain',
      'plaintext_transport',
    ]);

    const stats = await db.shares.stats();
    expect(stats.needsReview).toBe(items.length);
    // The wss stream is secure and the IP's endpoint is sftp; only the partner
    // host carries a plaintext endpoint.
    expect(stats.insecure).toBe(1);
  });
});

describe('egress acceptance corpus — reconciliation', () => {
  it('is idempotent across a re-run of the unchanged corpus', async () => {
    const first = scanAndRecord(db, root, base);
    const before = await readLedger(db);

    const second = scanAndRecord(db, root, base);

    expect(second).toEqual(first);
    expect(await readLedger(db)).toEqual(before);
    expect((await db.shares.stats()).destinations).toBe(EXPECTED_LEDGER.length);
  });

  it('drops the partner destination when its only source file is deleted', async () => {
    scanAndRecord(db, root, base);
    expect((await readLedger(db)).map((d) => d.host)).toContain('api.acme-partner.com');

    rmSync(join(root, 'src', 'partner.ts'));
    const recorded = scanAndRecord(db, root, base);

    const hosts = (await readLedger(db)).map((d) => d.host);
    expect(hosts).not.toContain('api.acme-partner.com');
    expect(hosts).toEqual(
      EXPECTED_LEDGER.map((d) => d.host).filter((h) => h !== 'api.acme-partner.com'),
    );
    expect(recorded?.destinations).toBe(EXPECTED_LEDGER.length - 1);

    const stats = await db.shares.stats();
    expect(stats.destinations).toBe(EXPECTED_LEDGER.length - 1);
    expect(stats.byKind.external).toBe(1);
    // The partner host was the only plaintext one, and the only source of two
    // of the three review reasons it carried.
    expect(stats.insecure).toBe(0);
  });
});

describe('egress acceptance corpus — plaintext posture covers ws', () => {
  // The corpus's ws endpoint shares a destination with an http one, so it
  // cannot on its own prove that 'ws' is in the plaintext predicate. This case
  // isolates it: a destination whose ONLY transport is ws.
  it('flags a destination reached over ws with no other plaintext evidence', async () => {
    const solo = mkdtempSync(join(tmpdir(), 'aka-ws-'));
    try {
      mkdirSync(join(solo, 'src'));
      writeFileSync(
        join(solo, 'src', 'feed.ts'),
        "export const FEED = 'ws://feed.acme-quotes-live.com/v1/ticks';\n",
      );

      scanAndRecord(db, solo, base);

      const ledger = await readLedger(db);
      expect(ledger.map((d) => [d.host, d.transports])).toEqual([
        ['feed.acme-quotes-live.com', ['ws']],
      ]);

      const { items } = await db.shares.needsReview();
      expect(items.map((i) => i.review.reasons)).toEqual<ReviewReason[][]>([
        ['unverified_domain', 'plaintext_transport'],
      ]);
      expect((await db.shares.stats()).insecure).toBe(1);
    } finally {
      rmSync(solo, { recursive: true, force: true });
    }
  });
});
