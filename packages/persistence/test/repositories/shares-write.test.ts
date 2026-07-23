import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import type {
  DataClass,
  DestinationKind,
  DestinationNetwork,
  EgressWriteSummary,
  HttpMethod,
  ResolvedEgressHit,
  ShareTrustLevel,
  Transport,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { applyMigrations } from '../../src/migrations.ts';
import {
  MAX_EGRESS_CALL_SITES_PER_PROJECT,
  SqliteSharesRepository,
} from '../../src/repositories/shares.ts';

let db: DatabaseSync;
let shares: SqliteSharesRepository;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  applyMigrations(db);
  shares = new SqliteSharesRepository(db);
});

afterEach(() => {
  db.close();
});

// ─── Builders ────────────────────────────────────────────────────────────────

interface HitOptions {
  host?: string;
  kind?: DestinationKind;
  name?: string;
  category?: string;
  trust?: ShareTrustLevel;
  network?: DestinationNetwork | null;
  method?: HttpMethod;
  transport?: Transport;
  url?: string;
  template?: boolean;
  dataClass?: DataClass;
  file?: string;
  line?: number;
  snippet?: string;
  dynamic?: boolean;
  vendored?: boolean;
}

/** One resolved hit with recognized-provider defaults; every field is overridable. */
function hit(o: HitOptions = {}): ResolvedEgressHit {
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
      file: o.file ?? 'src/pay.ts',
      line: o.line ?? 12,
      snippet: o.snippet ?? `fetch('https://${host}/v1/charges')`,
      dynamic: o.dynamic ?? false,
      vendored: o.vendored ?? false,
    },
  };
}

/** A walk-mode write for one project; `walkedPrefix` defaults to the whole project. */
function walk(
  projectKey: string,
  hits: ResolvedEgressHit[],
  walkedPrefix = '',
  projectId: string | null = null,
): EgressWriteSummary {
  return shares.recordProjectEgress({
    projectKey,
    project: projectKey,
    projectId,
    reconcile: { mode: 'walk', walkedPrefix },
    hits,
  });
}

/** A ledger-mode write for one project. */
function ledger(
  projectKey: string,
  hits: ResolvedEgressHit[],
  scannedFiles: string[],
  deletedFiles: string[] = [],
): EgressWriteSummary {
  return shares.recordProjectEgress({
    projectKey,
    project: projectKey,
    projectId: null,
    reconcile: { mode: 'ledger', scannedFiles, deletedFiles },
    hits,
  });
}

// ─── Raw store readers (assertions state the stored rows, not a view) ────────

function callSites(projectKey?: string): { projectKey: string; file: string; line: number }[] {
  const sql =
    projectKey === undefined
      ? `SELECT project_key AS projectKey, file, line FROM share_call_site
         ORDER BY project_key, file, line`
      : `SELECT project_key AS projectKey, file, line FROM share_call_site
         WHERE project_key = ? ORDER BY file, line`;
  const stmt = db.prepare(sql);
  const rows = projectKey === undefined ? stmt.all() : stmt.all(projectKey);
  return rows as unknown as { projectKey: string; file: string; line: number }[];
}

function hosts(): string[] {
  const rows = db.prepare('SELECT host FROM share_destination ORDER BY host').all();
  return (rows as unknown as { host: string }[]).map((r) => r.host);
}

function urls(): string[] {
  const rows = db.prepare('SELECT url FROM share_endpoint ORDER BY url').all();
  return (rows as unknown as { url: string }[]).map((r) => r.url);
}

function destinationId(host: string): string {
  const row = db.prepare('SELECT id FROM share_destination WHERE host = ?').get(host);
  return (row as unknown as { id: string } | undefined)?.id ?? '';
}

function overrides(): { destinationId: string | null; host: string | null; decision: string }[] {
  const rows = db
    .prepare(
      `SELECT destination_id AS destinationId, host, decision FROM egress_decision_override
       ORDER BY coalesce(host, ''), decision`,
    )
    .all();
  return rows as unknown as {
    destinationId: string | null;
    host: string | null;
    decision: string;
  }[];
}

function lastSeen(table: 'share_destination' | 'share_endpoint'): number[] {
  const rows = db.prepare(`SELECT last_seen AS lastSeen FROM ${table} ORDER BY id`).all();
  return (rows as unknown as { lastSeen: number }[]).map((r) => r.lastSeen);
}

// ─── Fresh writes ────────────────────────────────────────────────────────────

describe('recordProjectEgress — fresh write', () => {
  it('inserts destinations, endpoints and call sites and summarizes them', () => {
    const summary = walk('git:alpha', [
      hit({ file: 'src/pay.ts', line: 12 }),
      hit({
        method: 'GET',
        url: 'https://api.stripe.com/v1/customers',
        file: 'src/cust.ts',
        line: 4,
      }),
    ]);

    expect(summary).toEqual({ destinations: 1, endpoints: 2, callSites: 2, truncated: false });
    expect(hosts()).toEqual(['api.stripe.com']);
    expect(urls()).toEqual([
      'https://api.stripe.com/v1/charges',
      'https://api.stripe.com/v1/customers',
    ]);
    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'src/cust.ts', line: 4 },
      { projectKey: 'git:alpha', file: 'src/pay.ts', line: 12 },
    ]);
  });

  it('round-trips the destination payload through the read view', async () => {
    walk('git:alpha', [
      hit({
        host: '10.1.2.3',
        kind: 'ip',
        name: '10.1.2.3',
        category: 'Unresolved host',
        trust: 'ip',
        network: { port: 8080, geo: null, ptr: null },
        method: 'REF',
        transport: 'http',
        url: 'http://10.1.2.3:8080/ingest',
        template: true,
        dataClass: 'logs',
        file: 'src/ship.ts',
        line: 9,
        snippet: 'post("http://10.1.2.3:8080/ingest")',
        dynamic: true,
        vendored: true,
      }),
    ]);

    const detail = await shares.getDestination(destinationId('10.1.2.3'));
    expect(detail?.kind).toBe('ip');
    expect(detail?.trust).toBe('ip');
    expect(detail?.network).toEqual({ port: 8080, geo: null, ptr: null });
    expect(detail?.endpoints[0]?.method).toBe('REF');
    expect(detail?.endpoints[0]?.transport).toBe('http');
    expect(detail?.endpoints[0]?.template).toBe(true);
    expect(detail?.endpoints[0]?.dataClass).toBe('logs');
    const site = detail?.endpoints[0]?.sites[0];
    expect(site?.file).toBe('src/ship.ts');
    expect(site?.line).toBe(9);
    expect(site?.dynamic).toBe(true);
    expect(site?.vendored).toBe(true);
    expect(site?.project).toBe('git:alpha');
  });

  it('records nothing and reports zeroes for an empty hit list', () => {
    const summary = walk('git:alpha', []);
    expect(summary).toEqual({ destinations: 0, endpoints: 0, callSites: 0, truncated: false });
    expect(hosts()).toEqual([]);
  });
});

// ─── Idempotency ─────────────────────────────────────────────────────────────

describe('recordProjectEgress — idempotency', () => {
  it('produces the same rows and summary when the same input is written twice', () => {
    const hits = [
      hit({ file: 'src/pay.ts', line: 12 }),
      hit({ host: 'api.openai.com', category: 'LLM provider', file: 'src/ai.ts', line: 3 }),
    ];
    const first = walk('git:alpha', hits);
    const second = walk('git:alpha', hits);

    expect(second).toEqual(first);
    expect(hosts()).toEqual(['api.openai.com', 'api.stripe.com']);
    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'src/ai.ts', line: 3 },
      { projectKey: 'git:alpha', file: 'src/pay.ts', line: 12 },
    ]);
  });

  it('keeps destination ids stable across writes so decisions and deep links survive', () => {
    walk('git:alpha', [hit()]);
    const before = destinationId('api.stripe.com');
    walk('git:alpha', [hit()]);
    expect(destinationId('api.stripe.com')).toBe(before);
  });

  it('tolerates duplicate hits for the same endpoint, file and line in one batch', () => {
    const summary = walk('git:alpha', [hit({ line: 12 }), hit({ line: 12 })]);
    expect(summary.callSites).toBe(1);
  });
});

// ─── Walk-mode reconciliation ────────────────────────────────────────────────

describe('recordProjectEgress — walk mode', () => {
  it('prunes the dropped endpoint and its now-empty destination on a root re-scan', () => {
    walk('git:alpha', [
      hit({ file: 'src/pay.ts', line: 12 }),
      hit({ host: 'api.openai.com', category: 'LLM provider', file: 'src/ai.ts', line: 3 }),
    ]);
    expect(hosts()).toEqual(['api.openai.com', 'api.stripe.com']);

    const summary = walk('git:alpha', [hit({ file: 'src/pay.ts', line: 12 })]);

    expect(summary).toEqual({ destinations: 1, endpoints: 1, callSites: 1, truncated: false });
    expect(hosts()).toEqual(['api.stripe.com']);
    expect(urls()).toEqual(['https://api.stripe.com/v1/charges']);
    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'src/pay.ts', line: 12 },
    ]);
  });

  it('replaces only the walked subtree', () => {
    walk('git:alpha', [
      hit({ file: 'src/a.ts', line: 1 }),
      hit({ host: 'api.openai.com', file: 'lib/b.ts', line: 2 }),
    ]);

    walk('git:alpha', [], 'src');

    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'lib/b.ts', line: 2 },
    ]);
    expect(hosts()).toEqual(['api.openai.com']);
  });

  it('replaces exactly the file a single-file walk targeted', () => {
    walk('git:alpha', [
      hit({ file: 'src/a.ts', line: 1 }),
      hit({ host: 'api.openai.com', file: 'src/b.ts', line: 2 }),
    ]);

    walk('git:alpha', [], 'src/a.ts');

    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'src/b.ts', line: 2 },
    ]);
  });

  it('treats the walked prefix literally, not as a LIKE pattern', () => {
    // `_` is a LIKE single-character wildcard: an unescaped prefix would delete
    // the sibling directory's rows too.
    walk('git:alpha', [
      hit({ file: 'src_a/x.ts', line: 1 }),
      hit({ host: 'api.openai.com', file: 'srcXa/y.ts', line: 2 }),
    ]);

    walk('git:alpha', [], 'src_a');

    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'srcXa/y.ts', line: 2 },
    ]);
  });

  it('leaves dot-path rows alone — only the ledger walker can re-create them', () => {
    walk('git:alpha', [
      hit({ file: '.github/scripts/deploy.ts', line: 7 }),
      hit({ host: 'api.openai.com', file: 'src/ai.ts', line: 3 }),
    ]);

    walk('git:alpha', [], '');

    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: '.github/scripts/deploy.ts', line: 7 },
    ]);
    expect(hosts()).toEqual(['api.stripe.com']);
  });

  it('leaves a dot-file at the project root alone', () => {
    walk('git:alpha', [hit({ file: '.eslintrc.js', line: 2 })]);
    walk('git:alpha', [], '');
    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: '.eslintrc.js', line: 2 },
    ]);
  });

  it('leaves a nested dot-directory under the walked prefix alone', () => {
    walk('git:alpha', [
      hit({ file: 'src/.generated/client.ts', line: 5 }),
      hit({ host: 'api.openai.com', file: 'src/ai.ts', line: 3 }),
    ]);

    walk('git:alpha', [], 'src');

    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'src/.generated/client.ts', line: 5 },
    ]);
  });

  it('does not clear stale rows under a dot-path prefix — ledger mode owns them', () => {
    // Accepted gap of the walker-universe rule: the exclusion is by stored path,
    // so even a walk aimed straight at a dot-directory leaves its rows for the
    // pipeline that can see the whole subtree.
    walk('git:alpha', [hit({ file: '.github/deploy.ts', line: 7 })]);

    walk('git:alpha', [], '.github');

    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: '.github/deploy.ts', line: 7 },
    ]);
  });

  it('still updates a dot-path row the walker did reach', () => {
    walk('git:alpha', [hit({ file: '.github/deploy.ts', line: 7, snippet: 'old' })]);
    walk('git:alpha', [hit({ file: '.github/deploy.ts', line: 7, snippet: 'new' })]);

    const row = db
      .prepare('SELECT snippet FROM share_call_site WHERE file = ?')
      .get('.github/deploy.ts');
    expect((row as unknown as { snippet: string }).snippet).toBe('new');
    expect(callSites('git:alpha')).toHaveLength(1);
  });
});

// ─── Ledger-mode reconciliation ──────────────────────────────────────────────

describe('recordProjectEgress — ledger mode', () => {
  it('replaces exactly the scanned and deleted files, preserving the rest', () => {
    walk('git:alpha', [
      hit({ file: 'a.ts', line: 1 }),
      hit({ host: 'api.openai.com', file: 'b.ts', line: 2 }),
      hit({ host: 'api.anthropic.com', file: 'c.ts', line: 3 }),
    ]);

    ledger('git:alpha', [hit({ file: 'a.ts', line: 9 })], ['a.ts'], ['b.ts']);

    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'a.ts', line: 9 },
      { projectKey: 'git:alpha', file: 'c.ts', line: 3 },
    ]);
    expect(hosts()).toEqual(['api.anthropic.com', 'api.stripe.com']);
  });

  it('never mass-deletes: rows outside the ledger lists survive an empty run', () => {
    walk('git:alpha', [
      hit({ file: 'vendor/dep.ts', line: 1 }),
      hit({ host: 'api.openai.com', file: 'huge.ts', line: 2 }),
    ]);

    const summary = ledger('git:alpha', [], [], []);

    expect(summary).toEqual({ destinations: 2, endpoints: 2, callSites: 2, truncated: false });
    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'huge.ts', line: 2 },
      { projectKey: 'git:alpha', file: 'vendor/dep.ts', line: 1 },
    ]);
  });

  it('removes a dot-path row when the ledger names it', () => {
    walk('git:alpha', [hit({ file: '.github/deploy.ts', line: 7 })]);

    ledger('git:alpha', [], [], ['.github/deploy.ts']);

    expect(callSites('git:alpha')).toEqual([]);
    expect(hosts()).toEqual([]);
  });

  it('chunks large ledger file lists', () => {
    const many = Array.from({ length: 1200 }, (_, i) => `src/f${String(i)}.ts`);
    walk(
      'git:alpha',
      many.map((file, i) => hit({ file, line: i + 1 })),
    );
    expect(callSites('git:alpha')).toHaveLength(1200);

    ledger('git:alpha', [], [], many);

    expect(callSites('git:alpha')).toEqual([]);
  });
});

// ─── Override survival ───────────────────────────────────────────────────────

describe('recordProjectEgress — decision overrides', () => {
  it('re-attaches a host-keyed block decision after the destination is pruned', async () => {
    walk('git:alpha', [hit()]);
    const firstId = destinationId('api.stripe.com');
    expect(shares.setEgressDecision(firstId, 'block')).toBe(true);

    // Prune: a root re-scan that no longer sees the host.
    walk('git:alpha', []);
    expect(hosts()).toEqual([]);

    // The host-keyed row survives the prune, with its destination link released.
    expect(overrides()).toEqual([
      { destinationId: null, host: 'api.stripe.com', decision: 'block' },
    ]);

    walk('git:alpha', [hit()]);
    const secondId = destinationId('api.stripe.com');
    expect(secondId).not.toBe(firstId);

    const detail = await shares.getDestination(secondId);
    expect(detail?.status).toBe('blocked');
    expect(detail?.isCustom).toBe(true);
  });

  it('removes legacy host-NULL override rows when their destination is pruned', () => {
    walk('git:alpha', [hit()]);
    const id = destinationId('api.stripe.com');
    db.prepare(
      `INSERT INTO egress_decision_override (id, destination_id, host, decision, created_at, updated_at)
       VALUES (?, ?, NULL, 'block', ?, ?)`,
    ).run(randomUUID(), id, Date.now(), Date.now());

    walk('git:alpha', []);

    expect(hosts()).toEqual([]);
    expect(overrides()).toEqual([]);
  });

  it('keeps override rows for destinations that survive the write', () => {
    walk('git:alpha', [hit(), hit({ host: 'api.openai.com', file: 'src/ai.ts', line: 3 })]);
    shares.setEgressDecision(destinationId('api.openai.com'), 'allow');

    walk('git:alpha', [hit()]);

    expect(hosts()).toEqual(['api.stripe.com']);
    expect(overrides()).toEqual([
      { destinationId: null, host: 'api.openai.com', decision: 'allow' },
    ]);
  });
});

// ─── Cross-project isolation ─────────────────────────────────────────────────

describe('recordProjectEgress — project isolation', () => {
  it('a walk-mode wipe of one project leaves the other project and the shared destination', () => {
    walk('git:alpha', [hit({ file: 'src/a.ts', line: 1 })]);
    walk('git:beta', [hit({ file: 'src/b.ts', line: 2 })]);
    expect(callSites()).toHaveLength(2);

    const summary = walk('git:alpha', []);

    expect(summary).toEqual({ destinations: 0, endpoints: 0, callSites: 0, truncated: false });
    expect(callSites()).toEqual([{ projectKey: 'git:beta', file: 'src/b.ts', line: 2 }]);
    expect(hosts()).toEqual(['api.stripe.com']);
    expect(urls()).toEqual(['https://api.stripe.com/v1/charges']);
  });

  it('summarizes only the written project', () => {
    walk('git:beta', [
      hit({ file: 'src/b.ts', line: 2 }),
      hit({ host: 'api.openai.com', file: 'src/c.ts', line: 3 }),
    ]);

    const summary = walk('git:alpha', [hit({ file: 'src/a.ts', line: 1 })]);

    expect(summary).toEqual({ destinations: 1, endpoints: 1, callSites: 1, truncated: false });
  });

  it('two projects on the same file path keep separate call sites', () => {
    walk('git:alpha', [hit({ file: 'src/a.ts', line: 1 })]);
    walk('git:beta', [hit({ file: 'src/a.ts', line: 1 })]);

    expect(callSites()).toEqual([
      { projectKey: 'git:alpha', file: 'src/a.ts', line: 1 },
      { projectKey: 'git:beta', file: 'src/a.ts', line: 1 },
    ]);
  });

  it('a ledger write for one project never touches the other project’s same-named file', () => {
    walk('git:alpha', [hit({ file: 'src/a.ts', line: 1 })]);
    walk('git:beta', [hit({ file: 'src/a.ts', line: 1 })]);

    ledger('git:alpha', [], [], ['src/a.ts']);

    expect(callSites()).toEqual([{ projectKey: 'git:beta', file: 'src/a.ts', line: 1 }]);
  });
});

// ─── lastSeen confirmation ───────────────────────────────────────────────────

describe('recordProjectEgress — lastSeen', () => {
  it('bumps last_seen for every surviving endpoint and destination', () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
      walk('git:alpha', [
        hit({ file: 'a.ts', line: 1 }),
        hit({ host: 'api.openai.com', file: 'b.ts', line: 2 }),
      ]);
      const first = Date.now();
      expect(lastSeen('share_endpoint')).toEqual([first, first]);

      // A ledger run that re-confirms nothing still confirms what it preserved.
      vi.setSystemTime(new Date('2026-02-02T00:00:00.000Z'));
      ledger('git:alpha', [], [], []);
      const second = Date.now();

      expect(lastSeen('share_endpoint')).toEqual([second, second]);
      expect(lastSeen('share_destination')).toEqual([second, second]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not bump another project’s untouched rows', () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
      walk('git:beta', [hit({ host: 'api.openai.com', file: 'b.ts', line: 2 })]);
      const betaStamp = Date.now();

      vi.setSystemTime(new Date('2026-02-02T00:00:00.000Z'));
      walk('git:alpha', [hit({ file: 'a.ts', line: 1 })]);

      const row = db
        .prepare('SELECT last_seen AS lastSeen FROM share_destination WHERE host = ?')
        .get('api.openai.com');
      expect((row as unknown as { lastSeen: number }).lastSeen).toBe(betaStamp);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ─── Mutable payload refresh ─────────────────────────────────────────────────

describe('recordProjectEgress — payload refresh', () => {
  it('refreshes destination classification and endpoint transport on re-record', async () => {
    walk('git:alpha', [
      hit({
        host: 'egress.acme.io',
        kind: 'external',
        name: 'egress.acme.io',
        category: 'External domain',
        trust: 'unverified',
        transport: 'http',
        url: 'http://egress.acme.io/v1',
      }),
    ]);

    walk('git:alpha', [
      hit({
        host: 'egress.acme.io',
        kind: 'internal',
        name: 'Acme egress',
        category: 'Internal services',
        trust: 'internal',
        transport: 'http',
        url: 'http://egress.acme.io/v1',
      }),
    ]);

    const detail = await shares.getDestination(destinationId('egress.acme.io'));
    expect(detail?.kind).toBe('internal');
    expect(detail?.name).toBe('Acme egress');
    expect(detail?.category).toBe('Internal services');
    expect(detail?.trust).toBe('internal');
  });

  it('refreshes the call-site display payload without changing the reconcile key', () => {
    walk('git:alpha', [hit({ file: 'a.ts', line: 1, snippet: 'old', vendored: false })], '', 'p1');
    walk('git:alpha', [hit({ file: 'a.ts', line: 1, snippet: 'new', vendored: true })], '', 'p2');

    const row = db
      .prepare(
        `SELECT project, project_id AS projectId, snippet, vendored
         FROM share_call_site WHERE project_key = ?`,
      )
      .get('git:alpha');
    expect(row).toMatchObject({ projectId: 'p2', snippet: 'new', vendored: 1 });
    expect(callSites('git:alpha')).toHaveLength(1);
  });
});

// ─── Cap ─────────────────────────────────────────────────────────────────────

describe('recordProjectEgress — cap', () => {
  it('keeps the first MAX call sites in input order and reports truncation', () => {
    const many = Array.from({ length: MAX_EGRESS_CALL_SITES_PER_PROJECT + 1 }, (_, i) =>
      hit({ file: 'src/big.ts', line: i + 1 }),
    );

    const summary = walk('git:alpha', many);

    expect(summary.truncated).toBe(true);
    expect(summary.callSites).toBe(MAX_EGRESS_CALL_SITES_PER_PROJECT);
    expect(callSites('git:alpha')).toHaveLength(MAX_EGRESS_CALL_SITES_PER_PROJECT);
    const dropped = db
      .prepare('SELECT count(*) AS n FROM share_call_site WHERE line = ?')
      .get(MAX_EGRESS_CALL_SITES_PER_PROJECT + 1);
    expect((dropped as unknown as { n: number }).n).toBe(0);
  });

  it('does not report truncation at exactly the cap', () => {
    const many = Array.from({ length: MAX_EGRESS_CALL_SITES_PER_PROJECT }, (_, i) =>
      hit({ file: 'src/big.ts', line: i + 1 }),
    );
    expect(walk('git:alpha', many).truncated).toBe(false);
  });
});

// ─── Atomicity ───────────────────────────────────────────────────────────────

describe('recordProjectEgress — failure handling', () => {
  it('throws and rolls the whole write back, leaving the prior inventory intact', () => {
    walk('git:alpha', [hit({ file: 'src/a.ts', line: 1 })]);

    // A hit the driver cannot bind: it fails after the reconcile delete has run,
    // so a non-atomic writer would leave the project with no rows at all.
    const broken = hit({ file: 'src/b.ts', line: 2 });
    (broken.site as { snippet: unknown }).snippet = undefined;

    expect(() =>
      walk('git:alpha', [
        hit({ file: 'src/a.ts', line: 1 }),
        hit({ host: 'api.openai.com', file: 'src/ai.ts', line: 3 }),
        broken,
      ]),
    ).toThrow();

    // The reconcile delete and the two good hits are both rolled back: the
    // project keeps exactly the rows it had, and nothing new is left behind.
    expect(callSites('git:alpha')).toEqual([
      { projectKey: 'git:alpha', file: 'src/a.ts', line: 1 },
    ]);
    expect(hosts()).toEqual(['api.stripe.com']);
  });
});
