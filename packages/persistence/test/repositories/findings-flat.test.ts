import { randomUUID } from 'node:crypto';

import type {
  ActionTaken,
  DetectedFinding,
  DetectionCategory,
  EventMetadata,
  IngestEvent,
  Severity,
} from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { captureId } from '../../src/ids.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// The instance-level reads: listFindingInstances (flat, keyset-paged) and
// listFindingLocations (folded by repo → file). Both run against a real store,
// like every other repository suite here.

const store = useTempStore('aka-findings-flat-', { migrated: true });
let db: LocalDatabase;

beforeEach(() => {
  db = store.open();
});

function record(opts: {
  occurredAt: string;
  sourceTool: IngestEvent['sourceTool'];
  ruleId: string;
  category?: DetectionCategory;
  severity?: Severity;
  actionTaken?: ActionTaken;
  repo?: string;
  filePath?: string;
  toolName?: string;
  sessionId?: string;
  kind?: IngestEvent['kind'];
}): string {
  const id = randomUUID();
  const contentHash = randomUUID();
  const metadata: EventMetadata = {
    ...(opts.repo === undefined ? {} : { repo: opts.repo }),
    ...(opts.filePath === undefined ? {} : { filePath: opts.filePath }),
    ...(opts.toolName === undefined ? {} : { toolName: opts.toolName }),
    ...(opts.sessionId === undefined ? {} : { sessionId: opts.sessionId }),
  };
  const event: IngestEvent = {
    id,
    sourceTool: opts.sourceTool,
    kind: opts.kind ?? 'prompt',
    occurredAt: opts.occurredAt,
    contentHash,
    content: 'x',
    metadata,
  };
  const finding: DetectedFinding = {
    id: randomUUID(),
    eventId: id,
    ruleId: opts.ruleId,
    category: opts.category ?? 'secret',
    severity: opts.severity ?? 'critical',
    span: { start: 0, end: 1 },
    maskedMatch: 'masked',
    actionTaken: opts.actionTaken ?? 'block',
    confidence: 0.9,
  };
  db.recordCapture(event, [finding]);
  // The store derives the audit-event id rather than taking the ingest id (see
  // captureId), so a caller asserting on the linkage needs the derived one.
  return captureId(opts.sessionId ?? null, contentHash, opts.filePath ?? null);
}

function seed(): void {
  record({
    occurredAt: '2026-01-03T00:00:00.000Z',
    sourceTool: 'claude-code',
    ruleId: 'aws-key',
    severity: 'critical',
    repo: 'acme/api',
    filePath: 'a.ts',
    toolName: 'Read',
    sessionId: 's1',
  });
  record({
    occurredAt: '2026-01-02T00:00:00.000Z',
    sourceTool: 'cursor',
    ruleId: 'aws-key',
    severity: 'critical',
    actionTaken: 'warn',
    repo: 'acme/web',
    filePath: 'b.ts',
    toolName: 'Bash',
  });
  record({
    occurredAt: '2026-01-01T00:00:00.000Z',
    sourceTool: 'claude-code',
    ruleId: 'email',
    category: 'code_context',
    severity: 'low',
    actionTaken: 'redact',
    repo: 'acme/api',
    filePath: 'c.ts',
  });
}

describe('SqliteFindingsRepository.listFindingInstances', () => {
  it('returns one row per finding, newest first', async () => {
    seed();
    const res = await db.findings.listFindingInstances({});

    expect(res.totals.findings).toBe(3);
    expect(res.items.map((i) => i.detectedAt)).toEqual([
      '2026-01-03T00:00:00.000Z',
      '2026-01-02T00:00:00.000Z',
      '2026-01-01T00:00:00.000Z',
    ]);
    // Where the grouped list would fold both aws-key rows into one group.
    expect(res.items.map((i) => i.subtype)).toEqual(['aws-key', 'aws-key', 'email']);
    expect(res.nextCursor).toBeNull();
  });

  it('carries each row event and session linkage', async () => {
    const eventId = record({
      occurredAt: '2026-01-03T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      repo: 'acme/api',
      sessionId: 'sess-1',
    });
    const res = await db.findings.listFindingInstances({});

    expect(res.items[0]?.eventId).toBe(eventId);
    expect(res.items[0]?.sessionId).toBe('sess-1');
  });

  it('omits sessionId for an event outside a session', async () => {
    record({ occurredAt: '2026-01-03T00:00:00.000Z', sourceTool: 'claude-code', ruleId: 'r' });
    const res = await db.findings.listFindingInstances({});

    expect(res.items[0]?.eventId).toBeDefined();
    expect(res.items[0]?.sessionId).toBeUndefined();
  });

  it('is empty with a null cursor on an empty store', async () => {
    const res = await db.findings.listFindingInstances({});
    expect(res.items).toEqual([]);
    expect(res.totals.findings).toBe(0);
    expect(res.nextCursor).toBeNull();
  });

  describe('pagination', () => {
    // More rows than one page, all sharing a timestamp for part of the run so
    // the id tie-break in the keyset is actually exercised.
    function seedMany(n: number): void {
      for (let i = 0; i < n; i += 1) {
        record({
          // Two rows per millisecond: the (started_at, id) tuple is what
          // separates them, not the timestamp alone.
          occurredAt: new Date(Date.UTC(2026, 0, 1) + Math.floor(i / 2) * 1000).toISOString(),
          sourceTool: 'claude-code',
          ruleId: `rule-${String(i % 3)}`,
          repo: 'acme/api',
        });
      }
    }

    it('walks every row exactly once across pages', async () => {
      seedMany(25);
      const seen: string[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 20; page += 1) {
        const res: Awaited<ReturnType<typeof db.findings.listFindingInstances>> =
          await db.findings.listFindingInstances({
            limit: 10,
            ...(cursor === undefined ? {} : { cursor }),
          });
        seen.push(...res.items.map((i) => i.id));
        if (res.nextCursor === null) break;
        cursor = res.nextCursor;
      }

      expect(seen).toHaveLength(25);
      expect(new Set(seen).size).toBe(25);
    });

    it('reports totals and facets over the whole scope, not the page', async () => {
      seedMany(25);
      const first = await db.findings.listFindingInstances({ limit: 10 });
      expect(first.items).toHaveLength(10);
      expect(first.totals.findings).toBe(25);

      const second = await db.findings.listFindingInstances({
        limit: 10,
        cursor: first.nextCursor ?? '',
      });
      // The numbers describe the query, so paging must not move them.
      expect(second.totals).toEqual(first.totals);
      expect(second.facets).toEqual(first.facets);
    });

    it('restarts from the top on an undecodable cursor', async () => {
      seedMany(6);
      const fresh = await db.findings.listFindingInstances({ limit: 3 });
      const restarted = await db.findings.listFindingInstances({
        limit: 3,
        cursor: 'not-a-cursor',
      });
      expect(restarted.items.map((i) => i.id)).toEqual(fresh.items.map((i) => i.id));
    });

    it('keeps a filtered page full across scan batches', async () => {
      // One rare match per 40 rows, so filling a page of 3 requires the scan to
      // keep pulling batches rather than returning what the first one held.
      for (let i = 0; i < 120; i += 1) {
        record({
          occurredAt: new Date(Date.UTC(2026, 0, 1) + i * 1000).toISOString(),
          sourceTool: 'claude-code',
          ruleId: i % 40 === 0 ? 'rare' : 'common',
          repo: 'acme/api',
        });
      }
      const res = await db.findings.listFindingInstances({ subtype: ['rare'], limit: 3 });
      expect(res.items).toHaveLength(3);
      expect(res.totals.findings).toBe(3);
      expect(res.items.every((i) => i.subtype === 'rare')).toBe(true);
    });

    it('does not skip a match sitting past the page end', async () => {
      seedMany(12);
      const first = await db.findings.listFindingInstances({ limit: 5 });
      expect(first.nextCursor).not.toBeNull();
      const second = await db.findings.listFindingInstances({
        limit: 5,
        cursor: first.nextCursor ?? '',
      });
      const third = await db.findings.listFindingInstances({
        limit: 5,
        cursor: second.nextCursor ?? '',
      });
      const all = [...first.items, ...second.items, ...third.items].map((i) => i.id);
      expect(new Set(all).size).toBe(12);
    });
  });

  describe('filters', () => {
    it('matches an instance own status, not its group fold', async () => {
      seed();
      // Every seeded row is in-flight, so each derives 'handled'.
      const handled = await db.findings.listFindingInstances({ status: ['handled'] });
      expect(handled.totals.findings).toBe(3);
      const open = await db.findings.listFindingInstances({ status: ['open'] });
      expect(open.totals.findings).toBe(0);
    });

    it('filters by exact tool name', async () => {
      seed();
      const res = await db.findings.listFindingInstances({ tool: ['Bash'] });
      expect(res.totals.findings).toBe(1);
      expect(res.items[0]?.toolName).toBe('Bash');
    });

    it('filters by exact repo and file', async () => {
      seed();
      const byRepo = await db.findings.listFindingInstances({ repo: 'acme/api' });
      expect(byRepo.totals.findings).toBe(2);
      const byFile = await db.findings.listFindingInstances({ file: 'a.ts' });
      expect(byFile.totals.findings).toBe(1);
    });

    it('matches provider api as the unknown-tool catch-all', async () => {
      // 'api' is what an unmapped source tool reads as, so it cannot be a SQL
      // IN-list over known tools — this is the case that would return zero.
      // 'unknown' is a real SourceTool that TOOL_TO_HARNESS does not name, so
      // toApiProvider falls back to 'api' for it.
      record({
        occurredAt: '2026-01-04T00:00:00.000Z',
        sourceTool: 'unknown',
        ruleId: 'aws-key',
        repo: 'acme/api',
      });
      seed();
      const res = await db.findings.listFindingInstances({ provider: ['api'] });
      expect(res.totals.findings).toBe(1);
      expect(res.items[0]?.provider).toBe('api');
    });

    it('scopes to a session and to a time bound', async () => {
      seed();
      const bySession = await db.findings.listFindingInstances({ sessionId: 's1' });
      expect(bySession.totals.findings).toBe(1);

      const byFrom = await db.findings.listFindingInstances({
        from: '2026-01-02T00:00:00.000Z',
      });
      expect(byFrom.totals.findings).toBe(2);
    });

    it('matches q against the rendered via-tool label', async () => {
      seed();
      const res = await db.findings.listFindingInstances({ q: 'via Bash' });
      expect(res.totals.findings).toBe(1);
      expect(res.items[0]?.toolName).toBe('Bash');
    });
  });

  describe('facets', () => {
    it('counts instances and excludes each dimension own filter', async () => {
      seed();
      const res = await db.findings.listFindingInstances({ severity: ['critical'] });

      // Filtered: only the two critical rows.
      expect(res.totals.findings).toBe(2);
      // The severity facet excludes its own filter, so 'low' is still counted —
      // that is what makes "how many if I also pick low?" answerable.
      const low = res.facets.severity.find((f) => f.value === 'low');
      expect(low?.count).toBe(1);
      // Every other dimension DOES honor the severity filter.
      const providers = Object.fromEntries(res.facets.provider.map((f) => [f.value, f.count]));
      expect(providers).toEqual({ claudecode: 1, cursor: 1 });
    });

    it('counts tools, and counts no bucket for a row without one', async () => {
      seed();
      const res = await db.findings.listFindingInstances({});
      const tools = Object.fromEntries((res.facets.tool ?? []).map((f) => [f.value, f.count]));
      // Three rows, two of which carry a tool.
      expect(tools).toEqual({ Read: 1, Bash: 1 });
    });
  });
});

describe('SqliteFindingsRepository.listFindingLocations', () => {
  it('folds findings by repo then file', async () => {
    seed();
    const res = await db.findings.listFindingLocations({});

    expect(res.totals).toEqual({ findings: 3, repos: 2, files: 3 });
    // Worst severity first: acme/api holds the critical row.
    expect(res.items.map((r) => r.repo)).toEqual(['acme/api', 'acme/web']);

    const api = res.items[0];
    expect(api?.instanceCount).toBe(2);
    expect(api?.maxSeverity).toBe('critical');
    expect(api?.files.map((f) => f.file)).toEqual(['a.ts', 'c.ts']);
    expect(api?.files[0]?.ruleIds).toEqual(['aws-key']);
  });

  it('buckets a finding whose event recorded no repo or file under the empty key', async () => {
    record({ occurredAt: '2026-01-03T00:00:00.000Z', sourceTool: 'claude-code', ruleId: 'r' });
    const res = await db.findings.listFindingLocations({});

    expect(res.items).toHaveLength(1);
    expect(res.items[0]?.repo).toBe('');
    expect(res.items[0]?.files[0]?.file).toBe('');
  });

  it('folds a location status from its instances', async () => {
    seed();
    const res = await db.findings.listFindingLocations({});
    // Every seeded row is in-flight, so each location folds to 'handled'.
    expect(res.items[0]?.status).toBe('handled');
    expect(res.items[0]?.files[0]?.status).toBe('handled');
  });

  it('honors the same filters as the flat list', async () => {
    seed();
    const res = await db.findings.listFindingLocations({ severity: ['low'] });
    expect(res.totals).toEqual({ findings: 1, repos: 1, files: 1 });
    expect(res.items[0]?.files[0]?.file).toBe('c.ts');
  });

  it('reports hasMore when the limit truncates the repo list', async () => {
    for (let i = 0; i < 5; i += 1) {
      record({
        occurredAt: new Date(Date.UTC(2026, 0, 1) + i * 1000).toISOString(),
        sourceTool: 'claude-code',
        ruleId: 'r',
        repo: `acme/repo-${String(i)}`,
      });
    }
    const res = await db.findings.listFindingLocations({ limit: 2 });
    expect(res.items).toHaveLength(2);
    expect(res.totals.repos).toBe(5);
    expect(res.hasMore).toBe(true);
  });

  it('is empty on an empty store', async () => {
    const res = await db.findings.listFindingLocations({});
    expect(res.items).toEqual([]);
    expect(res.totals).toEqual({ findings: 0, repos: 0, files: 0 });
    expect(res.hasMore).toBe(false);
  });
});

// The read the `?finding=` deep link resolves through. It is a primary-key seek
// rather than anything derived from a list page, which is the whole point: the
// id a link carries can name a finding far older than any page a reader would
// otherwise have to walk to.
describe('SqliteFindingsRepository.findingInstance', () => {
  it('resolves an id to a detail whose groupId is the rule id', async () => {
    record({
      occurredAt: '2026-01-03T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      repo: 'acme/api',
      filePath: 'a.ts',
      sessionId: 'sess-1',
    });
    const listed = (await db.findings.listFindingInstances({})).items[0];
    expect(listed).toBeDefined();

    const found = await db.findings.findingInstance(listed?.id ?? '');
    expect(found?.groupId).toBe('aws-key');
    expect(found?.subtype).toBe('aws-key');
    expect(found?.file).toBe('a.ts');
    expect(found?.sessionId).toBe('sess-1');
  });

  it('returns null for an unknown id', async () => {
    expect(await db.findings.findingInstance('no-such-finding')).toBeNull();
  });

  // The non-vacuous one: the OLDEST finding of a large type, which the read this
  // replaced could only see if it fell inside a fixed 200-row preview. Seek it
  // directly and it resolves regardless of how many newer findings bury it.
  it('resolves the oldest finding of a large type, which no page bound reaches', async () => {
    const BURIED = 250;
    await db.transaction(() => {
      for (let i = 0; i < BURIED; i += 1) {
        record({
          occurredAt: new Date(Date.UTC(2026, 1, 1) + i * 1000).toISOString(),
          sourceTool: 'claude-code',
          ruleId: 'buried-rule',
          repo: 'acme/api',
          filePath: `deep/f${String(i)}.ts`,
        });
      }
    });

    // Walk to the end to learn the oldest one's id, then seek it cold.
    let cursor: string | null = null;
    let oldest: { id: string; file: string } | undefined;
    do {
      const page = await db.findings.listFindingInstances({
        subtype: ['buried-rule'],
        limit: 50,
        ...(cursor === null ? {} : { cursor }),
      });
      oldest = page.items.at(-1) ?? oldest;
      cursor = page.nextCursor;
    } while (cursor !== null);
    expect(oldest?.file).toBe('deep/f0.ts');

    const found = await db.findings.findingInstance(oldest?.id ?? '');
    expect(found?.file).toBe('deep/f0.ts');
    expect(found?.groupId).toBe('buried-rule');
  });

  // It RESOLVES an id; whether the row would survive the list's filters is a
  // different question, and hiding the target because a filter excludes it is
  // worse than showing it.
  it('ignores the filters a list would apply', async () => {
    record({
      occurredAt: '2026-01-03T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      severity: 'critical',
      repo: 'acme/api',
      filePath: 'a.ts',
    });
    const listed = (await db.findings.listFindingInstances({})).items[0];
    // A filter that excludes it from every list still leaves it resolvable.
    expect((await db.findings.listFindingInstances({ severity: ['low'] })).items).toHaveLength(0);
    expect((await db.findings.findingInstance(listed?.id ?? ''))?.id).toBe(listed?.id);
  });
});

describe('SqliteFindingsRepository.listFindingTypes pagination', () => {
  // Distinct rules so each becomes its own type; this list pages TYPES.
  function seedGroups(n: number): void {
    for (let i = 0; i < n; i += 1) {
      record({
        occurredAt: new Date(Date.UTC(2026, 0, 1) + i * 1000).toISOString(),
        sourceTool: 'claude-code',
        ruleId: `rule-${String(i).padStart(3, '0')}`,
        repo: 'acme/api',
        filePath: `f${String(i)}.ts`,
      });
    }
  }

  it('walks every group exactly once across pages', async () => {
    seedGroups(12);
    const seen: string[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 10; page += 1) {
      const res: Awaited<ReturnType<typeof db.findings.listFindingTypes>> =
        await db.findings.listFindingTypes({
          limit: 5,
          ...(cursor === undefined ? {} : { cursor }),
        });
      seen.push(...res.items.map((g) => g.id));
      if (res.nextCursor === null) break;
      cursor = res.nextCursor;
    }

    expect(seen).toHaveLength(12);
    expect(new Set(seen).size).toBe(12);
  });

  it('reports a null cursor at exhaustion', async () => {
    seedGroups(3);
    const res = await db.findings.listFindingTypes({ limit: 5 });
    expect(res.items).toHaveLength(3);
    expect(res.nextCursor).toBeNull();
  });

  it('keeps totals and facets page-independent', async () => {
    seedGroups(12);
    const first = await db.findings.listFindingTypes({ limit: 5 });
    const second = await db.findings.listFindingTypes({
      limit: 5,
      cursor: first.nextCursor ?? '',
    });
    expect(second.totals).toEqual(first.totals);
    expect(second.facets).toEqual(first.facets);
  });

  it('restarts from the top on an undecodable cursor', async () => {
    seedGroups(6);
    const fresh = await db.findings.listFindingTypes({ limit: 3 });
    const restarted = await db.findings.listFindingTypes({ limit: 3, cursor: 'garbage' });
    expect(restarted.items.map((g) => g.id)).toEqual(fresh.items.map((g) => g.id));
  });

  it('restarts from the top on a decodable cursor carrying an unknown severity', async () => {
    // Decodes fine but names no real severity. That ranks below every known one,
    // so it sorts before the whole list and degrades to a restart rather than
    // silently paging past rows.
    seedGroups(6);
    const bogus = Buffer.from(
      JSON.stringify({ sev: 'not-a-severity', t: '2026-01-01T00:00:00.000Z', id: 'x' }),
    ).toString('base64url');
    const fresh = await db.findings.listFindingTypes({ limit: 3 });
    const restarted = await db.findings.listFindingTypes({ limit: 3, cursor: bogus });
    expect(restarted.items.map((g) => g.id)).toEqual(fresh.items.map((g) => g.id));
  });

  it('appends an includeId group that sorts past the page', async () => {
    seedGroups(12);
    const first = await db.findings.listFindingTypes({ limit: 3 });
    const onPage = new Set(first.items.map((g) => g.id));
    const all = await db.findings.listFindingTypes({ limit: 100 });
    const offPage = all.items.find((g) => !onPage.has(g.id));
    expect(offPage).toBeDefined();

    const withDeepLink = await db.findings.listFindingTypes({
      limit: 3,
      includeId: offPage?.id ?? '',
    });
    expect(withDeepLink.items).toHaveLength(4);
    expect(withDeepLink.items.at(-1)?.id).toBe(offPage?.id);
    // The append is presentation only: it must not shift the page boundary.
    expect(withDeepLink.nextCursor).toBe(first.nextCursor);
    expect(withDeepLink.totals).toEqual(first.totals);
  });

  it('does not duplicate an includeId group already on the page', async () => {
    seedGroups(12);
    const first = await db.findings.listFindingTypes({ limit: 3 });
    const onPageId = first.items[0]?.id ?? '';
    const res = await db.findings.listFindingTypes({ limit: 3, includeId: onPageId });
    expect(res.items).toHaveLength(3);
    expect(res.items.filter((g) => g.id === onPageId)).toHaveLength(1);
  });

  // `includeId` names a RULE only. An instance id is resolved by
  // findingInstance instead — a primary-key seek, so unlike the old preview
  // scan it reaches a finding of any age (see its own cases below).
  it('ignores an includeId naming an instance rather than a type', async () => {
    seedGroups(12);
    const all = await db.findings.listFindingTypes({ limit: 100 });
    const offPage = all.items.at(-1)?.id ?? '';
    const instanceId =
      (await db.findings.listFindingInstances({ subtype: [offPage] })).items[0]?.id ?? '';
    expect(instanceId).not.toBe('');

    const plain = await db.findings.listFindingTypes({ limit: 3 });
    const res = await db.findings.listFindingTypes({ limit: 3, includeId: instanceId });
    expect(res.items.map((g) => g.id)).toEqual(plain.items.map((g) => g.id));
  });

  it('ignores an unknown includeId', async () => {
    seedGroups(6);
    const plain = await db.findings.listFindingTypes({ limit: 3 });
    const res = await db.findings.listFindingTypes({ limit: 3, includeId: 'no-such-id' });
    expect(res.items.map((g) => g.id)).toEqual(plain.items.map((g) => g.id));
  });

  it('scopes the type read and the findings read to the from bound alike', async () => {
    seed();
    const from = '2026-01-02T00:00:00.000Z';
    const res = await db.findings.listFindingTypes({ from });

    // The 2026-01-01 'email' row falls outside the window entirely.
    expect(res.totals).toEqual({ findings: 2, types: 1 });
    expect(res.items[0]?.instanceCount).toBe(2);
    // The two panels read the same window, or the count on the left disagrees
    // with the rows on the right.
    expect((await db.findings.listFindingInstances({ from })).totals.findings).toBe(2);
  });

  it('carries event and session linkage on each finding', async () => {
    const eventId = record({
      occurredAt: '2026-01-03T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      repo: 'acme/api',
      sessionId: 'sess-9',
    });
    const found = await db.findings.listFindingInstances({ subtype: ['aws-key'] });
    expect(found.items[0]?.eventId).toBe(eventId);
    expect(found.items[0]?.sessionId).toBe('sess-9');
  });
});
