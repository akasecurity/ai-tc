import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, IngestEvent, InstalledPackInput, Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../database.ts';
import { DB_FILENAME } from '../paths.ts';
import { SqliteDetectionsRepository } from './detections.ts';

const DAY_MS = 86_400_000;
// A fixed clock so the 30-day findings window is deterministic.
const NOW = Date.parse('2026-06-29T12:00:00.000Z');

let dir: string;
let db: ReturnType<typeof openLocalDatabase>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-detections-'));
  db = openLocalDatabase(dir);
});

// Raw second connections handed to repos under test — closed before rmSync
// (Windows cannot delete a directory while a DB handle is open).
const rawConnections: DatabaseSync[] = [];

afterEach(() => {
  for (const raw of rawConnections.splice(0)) raw.close();
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

function regexRule(id: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'x', flags: 'g' },
  };
}

function keywordRule(id: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'pii',
    severity: 'low',
    matcher: { type: 'keyword', keywords: ['a'], caseSensitive: false },
  };
}

function pack(packId: string, rules: Rule[], version = '2.0.0'): InstalledPackInput {
  return { namespace: 'aka', packId, version, name: packId, rules };
}

// Record one event + finding with the given ruleId, `daysAgo` relative to NOW.
function recordFinding(ruleId: string, daysAgo: number): void {
  const id = randomUUID();
  const event: IngestEvent = {
    id,
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date(NOW - daysAgo * DAY_MS).toISOString(),
    contentHash: id,
    content: 'x',
  };
  const finding: DetectedFinding = {
    id: randomUUID(),
    eventId: id,
    ruleId,
    category: 'secret',
    severity: 'high',
    span: { start: 0, end: 1 },
    maskedMatch: 'x',
    actionTaken: 'block',
    confidence: 0.9,
  };
  db.recordCapture(event, [finding]);
}

// A detections repo on a second read connection with the fixed clock.
function detections(): SqliteDetectionsRepository {
  const raw = new DatabaseSync(join(dir, DB_FILENAME));
  rawConnections.push(raw);
  return new SqliteDetectionsRepository(raw, () => NOW);
}

describe('SqliteDetectionsRepository.getDetectionStats', () => {
  it('rolls up detections/rules/active and counts findings in the last 30 days', async () => {
    db.installedPacks.recordInventory([
      pack('secrets', [regexRule('secrets/aws'), regexRule('secrets/gh')]),
      pack('core-pii', [regexRule('core-pii/email')]),
    ]);
    recordFinding('secrets/aws', 5); // in window
    recordFinding('secrets/gh', 10); // in window
    recordFinding('core-pii/email', 3); // in window
    recordFinding('secrets/aws', 40); // outside 30d — excluded
    recordFinding('other/x', 1); // not a pack rule — excluded

    const stats = await detections().getDetectionStats();
    expect(stats).toEqual({ detections: 2, rules: 3, active: 2, findingsLast30d: 3 });
  });

  it('reports zero findings for a fresh store', async () => {
    db.installedPacks.recordInventory([pack('secrets', [regexRule('secrets/aws')])]);
    const stats = await detections().getDetectionStats();
    expect(stats).toEqual({ detections: 1, rules: 1, active: 1, findingsLast30d: 0 });
  });
});

describe('SqliteDetectionsRepository.listDetections', () => {
  beforeEach(() => {
    db.installedPacks.recordInventory([
      pack('secrets', [regexRule('secrets/aws'), regexRule('secrets/gh')]),
      pack('core-pii', [regexRule('core-pii/email')]),
    ]);
  });

  it('computes counts over the unfiltered set and returns library items', async () => {
    const res = await detections().listDetections({ filter: 'all' });
    expect(res.counts).toEqual({ all: 2, library: 2, custom: 0, customized: 0, updates: 0 });
    expect(res.items.map((d) => d.id)).toEqual(['core-pii', 'secrets'].map((p) => `aka/${p}`));
    expect(res.items[0]?.ruleCount).toBe(1);
  });

  it('sorts enabled first, then by name', async () => {
    db.installedPacks.setEnabled('aka', 'core-pii', false);
    const res = await detections().listDetections({ filter: 'all' });
    // secrets (enabled) before core-pii (disabled), despite the name order.
    expect(res.items.map((d) => d.id)).toEqual(['aka/secrets', 'aka/core-pii']);
  });

  it('filters by search term over name/packId/namespace', async () => {
    const res = await detections().listDetections({ filter: 'all', q: 'pii' });
    expect(res.items.map((d) => d.id)).toEqual(['aka/core-pii']);
  });

  it('returns no items for the updates filter (no registry in OSS) but keeps counts', async () => {
    const res = await detections().listDetections({ filter: 'updates' });
    expect(res.items).toEqual([]);
    expect(res.counts.all).toBe(2);
  });

  it('surfaces the assigned policyId on list items', async () => {
    db.installedPacks.setPolicy('aka', 'secrets', 'block');
    const res = await detections().listDetections({ filter: 'all' });
    const secrets = res.items.find((d) => d.id === 'aka/secrets');
    expect(secrets?.policyId).toBe('block');
  });
});

describe('SqliteDetectionsRepository.getDetectionDetail', () => {
  it('returns detail exposing all matcher-type rules, the 30d count, and up-to-date status', async () => {
    db.installedPacks.recordInventory([
      pack('secrets', [regexRule('secrets/aws'), keywordRule('secrets/kw')]),
    ]);
    recordFinding('secrets/aws', 2);

    const detail = await detections().getDetectionDetail('aka/secrets');
    expect(detail).not.toBeNull();
    expect(detail?.ruleCount).toBe(2); // full pack rule count
    // Both the regex AND the keyword rule are exposed — ruleCount matches the list.
    expect(detail?.rules.map((r) => r.id)).toEqual(['secrets/aws', 'secrets/kw']);
    expect(detail?.rules.map((r) => r.matcher.type)).toEqual(['regex', 'keyword']);
    expect(detail?.findingsLast30d).toBe(1);
    // Installed snapshot matches the available mirror → explicitly up to date.
    expect(detail?.update).toEqual({ available: false, latestVersion: '2.0.0' });
    expect(detail?.modified).toBe(false);
    expect(detail?.origin).toBe('library');
  });

  it('reports an available update when the mirror moved ahead (version bump)', async () => {
    db.installedPacks.recordInventory([pack('secrets', [regexRule('secrets/aws')])]);
    // Binary upgrade: mirror at 2.5.0 with more rules; install stays at 2.0.0.
    db.installedPacks.recordInventory([
      pack('secrets', [regexRule('secrets/aws'), regexRule('secrets/gh')], '2.5.0'),
    ]);

    const detail = await detections().getDetectionDetail('aka/secrets');
    expect(detail?.version).toBe('2.0.0');
    expect(detail?.update).toEqual({
      available: true,
      latestVersion: '2.5.0',
      latestRuleCount: 2,
    });
    expect(detail?.latestVersion).toBe('2.5.0');
  });

  it('reports an available update for a rules-only change at the same version', async () => {
    db.installedPacks.recordInventory([pack('secrets', [regexRule('secrets/aws')])]);
    db.installedPacks.recordInventory([
      pack('secrets', [regexRule('secrets/aws'), regexRule('secrets/gh')]), // same 2.0.0
    ]);

    const detail = await detections().getDetectionDetail('aka/secrets');
    expect(detail?.update?.available).toBe(true);
    expect(detail?.update?.latestVersion).toBe('2.0.0'); // version did not change…
    expect(detail?.update?.latestRuleCount).toBe(2); // …but the rule count did
  });

  it('reports update=null for an installed pack with no available mirror row', async () => {
    // A foreign/custom pack recorded outside the bundled inventory.
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES ('z', 'me', 'custom', '1.0.0', 'Custom', '[]', 1, 0, 0)`,
      )
      .run();
    raw.close();

    const detail = await detections().getDetectionDetail('me/custom');
    expect(detail?.update).toBeNull();
    expect(detail?.latestVersion).toBeNull();
  });

  it('surfaces latestVersion on list items and counts them under the updates filter', async () => {
    db.installedPacks.recordInventory([
      pack('secrets', [regexRule('secrets/aws')]),
      pack('core-pii', [regexRule('core-pii/email')]),
    ]);
    // Only secrets moves ahead.
    db.installedPacks.recordInventory([
      pack('secrets', [regexRule('secrets/aws'), regexRule('secrets/gh')], '2.5.0'),
      pack('core-pii', [regexRule('core-pii/email')]),
    ]);

    const repo = detections();
    const all = await repo.listDetections({ filter: 'all' });
    expect(all.counts.updates).toBe(1);
    const secrets = all.items.find((i) => i.id === 'aka/secrets');
    expect(secrets?.latestVersion).toBe('2.5.0');
    expect(all.items.find((i) => i.id === 'aka/core-pii')?.latestVersion).toBeUndefined();

    const updates = await repo.listDetections({ filter: 'updates' });
    expect(updates.items.map((i) => i.id)).toEqual(['aka/secrets']);
  });

  it('includes the assigned policyId', async () => {
    db.installedPacks.recordInventory([pack('secrets', [regexRule('secrets/aws')])]);
    db.installedPacks.setPolicy('aka', 'secrets', 'redact');
    const detail = await detections().getDetectionDetail('aka/secrets');
    expect(detail?.policyId).toBe('redact');
  });

  it('returns null for a missing pack and a malformed id', async () => {
    db.installedPacks.recordInventory([pack('secrets', [regexRule('secrets/aws')])]);
    expect(await detections().getDetectionDetail('aka/nope')).toBeNull();
    expect(await detections().getDetectionDetail('no-slash')).toBeNull();
  });
});

describe('SqliteDetectionsRepository malformed-row tolerance', () => {
  // Insert a foreign/corrupt installed_packs row whose rules_json is NOT valid
  // JSON, bypassing the validated write path. SQL json_array_length() would throw
  // "malformed JSON" on this row; the reads parse in JS instead and must survive.
  function insertBrokenPack(): void {
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs
           (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES (?, 'aka', 'broken', '1.0.0', 'Broken', 'not valid json', 1, ?, ?)`,
      )
      .run(randomUUID(), NOW, NOW);
    raw.close();
  }

  it('does not let a malformed rules_json crash listDetections or getDetectionStats', async () => {
    db.installedPacks.recordInventory([pack('secrets', [regexRule('secrets/aws')])]);
    insertBrokenPack();

    const repo = detections();
    const list = await repo.listDetections({ filter: 'all' });
    // Both packs are listed; the broken one reports a 0 rule count, not a throw.
    expect(list.items.map((d) => d.id).sort()).toEqual(['aka/broken', 'aka/secrets']);
    expect(list.items.find((d) => d.id === 'aka/broken')?.ruleCount).toBe(0);

    const stats = await repo.getDetectionStats();
    expect(stats.detections).toBe(2);
    expect(stats.rules).toBe(1); // only the healthy pack's single rule counts
  });

  it('does not let a malformed rules_json crash getDetectionDetail', async () => {
    insertBrokenPack();
    const detail = await detections().getDetectionDetail('aka/broken');
    expect(detail?.rules).toEqual([]);
    expect(detail?.ruleCount).toBe(0);
  });

  // A foreign/partial row can be valid JSON yet carry a rule object with no `id`.
  // The 30-day findings count must skip it, not bind `undefined` into the SQL
  // IN (…) list (node:sqlite throws on an undefined bind, crashing the read).
  it('tolerates a valid rules_json whose rule has no id in getDetectionDetail', async () => {
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs
           (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES (?, 'aka', 'noid', '1.0.0', 'NoId', '[{"name":"orphan"}]', 1, ?, ?)`,
      )
      .run(randomUUID(), NOW, NOW);
    raw.close();

    const detail = await detections().getDetectionDetail('aka/noid');
    expect(detail?.ruleCount).toBe(1); // the id-less rule still counts toward the pack
    expect(detail?.rules).toEqual([]); // …but has no valid matcher to expose
    expect(detail?.findingsLast30d).toBe(0);
  });
});

describe('SqliteInstalledPacksRepository write facade', () => {
  beforeEach(() => {
    db.installedPacks.recordInventory([pack('secrets', [regexRule('secrets/aws')])]);
  });

  it('sets and clears the enforcement policy', async () => {
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'warn')).toBe(true);
    expect((await detections().getDetectionDetail('aka/secrets'))?.policyId).toBe('warn');

    expect(db.installedPacks.setPolicy('aka', 'secrets', null)).toBe(true);
    expect((await detections().getDetectionDetail('aka/secrets'))?.policyId).toBeUndefined();
  });

  it('rejects an unknown policy id', () => {
    expect(() => db.installedPacks.setPolicy('aka', 'secrets', 'bogus')).toThrow();
  });

  it('toggles enabled and reports no-match for an unknown pack', async () => {
    expect(db.installedPacks.setEnabled('aka', 'secrets', false)).toBe(true);
    expect((await detections().getDetectionStats()).active).toBe(0);
    expect(db.installedPacks.setEnabled('aka', 'missing', false)).toBe(false);
  });
});
