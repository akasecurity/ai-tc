import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME } from '@akasecurity/persistence';
import { loadOrCreateFingerprintKey } from '@akasecurity/plugin-sdk';
import type { DetectedFinding, IngestEvent, InstalledPackInput } from '@akasecurity/schema';
import { DEFAULT_ACTIONS } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { StandaloneDataGateway } from './standalone-gateway.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-standalone-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function event(overrides: Partial<IngestEvent> = {}): IngestEvent {
  return {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date().toISOString(),
    contentHash: 'hash',
    content: 'redacted content',
    ...overrides,
  };
}

function finding(eventId: string, overrides: Partial<DetectedFinding> = {}): DetectedFinding {
  return {
    id: randomUUID(),
    eventId,
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 0, end: 4 },
    maskedMatch: 'AKIA…MPLE',
    actionTaken: 'block',
    confidence: 0.9,
    ...overrides,
  };
}

describe('StandaloneDataGateway', () => {
  it('records a capture and reads it back', async () => {
    const gw = new StandaloneDataGateway(dir);
    const ev = event();
    await gw.recordCapture({ event: ev, findings: [finding(ev.id)] });

    const findings = await gw.recentFindings();
    expect(findings).toHaveLength(1);
    expect(findings[0]?.maskedMatch).toBe('AKIA…MPLE');
    expect(findings[0]?.occurredAt).toBe(ev.occurredAt);
    await gw.close();
  });

  it('synthesizes a local policy bundle from the seeded policies (empty store → bundled fallback)', async () => {
    const gw = new StandaloneDataGateway(dir);
    const bundle = await gw.getPolicyBundle();
    expect(bundle.version).toBe('local');
    // No installed packs at all (nothing seeded): the snapshot is not
    // authoritative, so rules stays empty WITHOUT rulesComplete — the runtime
    // falls back to its compiled-in bundled packs.
    expect(bundle.rules).toEqual([]);
    expect(bundle.rulesComplete).toBeUndefined();
    // One seeded policy per default category.
    const categories = bundle.policies
      .map((p) => ('category' in p.target ? p.target.category : null))
      .filter(Boolean);
    // Derived from DEFAULT_ACTIONS so a new category extends the seed without
    // a hand-maintained duplicate here.
    expect(new Set(categories)).toEqual(new Set(Object.keys(DEFAULT_ACTIONS)));
    await gw.close();
  });

  it('serves the installed snapshot as the COMPLETE ruleset once packs are recorded', async () => {
    const gw = new StandaloneDataGateway(dir, [
      {
        namespace: 'aka',
        packId: 'secrets',
        version: '2.0.0',
        name: 'Secrets',
        rules: [
          {
            specVersion: 1,
            id: 'secrets/aws',
            name: 'aws',
            category: 'secret',
            severity: 'high',
            matcher: { type: 'regex', pattern: 'x', flags: 'g' },
          },
        ],
      },
    ]);
    const bundle = await gw.getPolicyBundle();
    expect(bundle.rulesComplete).toBe(true);
    expect(bundle.rules?.map((r) => r.id)).toEqual(['secrets/aws']);
    await gw.close();
  });

  it('respects a fully-disabled inventory (complete empty ruleset, not a fallback)', async () => {
    const gw = new StandaloneDataGateway(dir, [
      {
        namespace: 'aka',
        packId: 'secrets',
        version: '2.0.0',
        name: 'Secrets',
        rules: [
          {
            specVersion: 1,
            id: 'secrets/aws',
            name: 'aws',
            category: 'secret',
            severity: 'high',
            matcher: { type: 'regex', pattern: 'x', flags: 'g' },
          },
        ],
      },
    ]);
    // The user turns the only pack off.
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw.exec('UPDATE installed_packs SET enabled = 0');
    raw.close();

    const bundle = await gw.getPolicyBundle();
    // Disabled-by-choice is authoritative: complete + empty, NOT bundled fallback.
    expect(bundle.rulesComplete).toBe(true);
    expect(bundle.rules).toEqual([]);
    await gw.close();
  });

  it('falls back to bundled packs when every enabled rule is invalid (corrupt snapshot)', async () => {
    const gw = new StandaloneDataGateway(dir);
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES ('c', 'aka', 'corrupt', '1.0.0', 'Corrupt', '[{"nope":true}]', 1, 0, 0)`,
      )
      .run();
    raw.close();

    const bundle = await gw.getPolicyBundle();
    // Packs exist and are enabled, but no rule parses: the snapshot is
    // unusable — fail open to the runtime's bundled packs.
    expect(bundle.rulesComplete).toBeUndefined();
    expect(bundle.rules).toEqual([]);
    await gw.close();
  });

  it('falls back to bundled packs on JSON-level corruption (malformed / non-array rules_json)', async () => {
    // Nastier than a bad rule object: the whole rules_json fails to parse. The
    // display-tolerant reads render this as "0 rules"; the SCAN path must not —
    // an authoritative empty ruleset here would silently disable all detection.
    const gw = new StandaloneDataGateway(dir);
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES ('t', 'aka', 'truncated', '1.0.0', 'Truncated', '[{"id":', 1, 0, 0)`,
      )
      .run();
    raw.close();

    const bundle = await gw.getPolicyBundle();
    expect(bundle.rulesComplete).toBeUndefined(); // not authoritative → bundled fallback
    expect(bundle.rules).toEqual([]);
    await gw.close();
  });

  it('falls back to bundled packs when an ENABLED pack contributes zero rules (empty-but-enabled)', async () => {
    // rules_json = '[]' on an enabled pack: 0 rules, 0 invalid. This is NOT a
    // legitimate "detect nothing" (that is expressed by DISABLING packs) — an
    // enabled pack that produces nothing is untrustworthy, so it must fall back
    // to the bundled packs rather than be served as an authoritative empty set.
    const gw = new StandaloneDataGateway(dir);
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES ('e', 'aka', 'empty', '1.0.0', 'Empty', '[]', 1, 0, 0)`,
      )
      .run();
    raw.close();

    const bundle = await gw.getPolicyBundle();
    expect(bundle.rulesComplete).toBeUndefined();
    expect(bundle.rules).toEqual([]);
    await gw.close();
  });

  it('falls back to bundled packs on PARTIAL corruption (one bad rule among valid ones)', async () => {
    // An enabled pack with some valid + one malformed rule: rules.length > 0, so
    // the old ladder would have served the valid SUBSET as complete — silently
    // dropping the corrupted rule with no fallback. Any invalid rule now taints
    // the snapshot, so it falls back to the bundled superset instead.
    const gw = new StandaloneDataGateway(dir);
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES ('p', 'aka', 'partial', '1.0.0', 'Partial',
                 '[{"specVersion":1,"id":"partial/ok","name":"ok","category":"secret","severity":"high","matcher":{"type":"regex","pattern":"x","flags":"g"}},{"nope":true}]',
                 1, 0, 0)`,
      )
      .run();
    raw.close();

    const bundle = await gw.getPolicyBundle();
    expect(bundle.rulesComplete).toBeUndefined();
    expect(bundle.rules).toEqual([]);
    await gw.close();
  });

  it('records the detections inventory into installed_packs on open', async () => {
    const detections: InstalledPackInput[] = [
      {
        namespace: 'aka',
        packId: 'secrets',
        version: '2.0.0',
        name: 'Secrets & Credentials',
        rules: [
          {
            specVersion: 1,
            id: 'secrets/aws',
            name: 'aws',
            category: 'secret',
            severity: 'high',
            matcher: { type: 'regex', pattern: 'x', flags: 'g' },
          },
        ],
      },
    ];
    const gw = new StandaloneDataGateway(dir, detections);
    await gw.close();

    // Verify it landed in the shared store (the gateway exposes no pack reads).
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const row = raw.prepare('SELECT count(*) AS c FROM installed_packs').get() as { c: number };
    raw.close();
    expect(row.c).toBe(1);
  });

  it('ensures inventory and serves facets from the local dimension', async () => {
    const gw = new StandaloneDataGateway(dir);
    const resolved = await gw.ensureInventory({
      host: {
        objectType: 'host',
        identityKey: 'machine-1',
        title: 'laptop',
        attributes: { host_name: 'laptop', os_version: '25.5.0' },
      },
      harness: {
        objectType: 'harness',
        identityKey: 'claude-code',
        title: 'Claude Code',
        attributes: { harness_version: '1.2.3' },
      },
      project: { url: 'git@github.com:org/repo.git', name: 'repo', attributes: {} },
    });
    expect(resolved.hostId).toBeTypeOf('string');

    const facets = await gw.facets();
    expect(facets.hosts).toEqual(['laptop']);
    expect(facets.harnesses).toEqual(['Claude Code']);
    expect(facets.osVersions).toEqual(['25.5.0']);
    expect(facets.projects).toEqual(['repo']);
    await gw.close();
  });

  it('reports health and daily activity from the local store', async () => {
    const gw = new StandaloneDataGateway(dir);
    const ev = event();
    await gw.recordCapture({ event: ev, findings: [finding(ev.id, { actionTaken: 'block' })] });

    const health = await gw.healthSummary();
    expect(health.findings).toBe(1);
    expect(health.byAction.block).toBe(1);
    expect(health.coverage).toBe(1);

    const days = await gw.activityByDay(7);
    expect(days).toHaveLength(7);
    const today = new Date().toISOString().slice(0, 10);
    expect(days.find((d) => d.day === today)?.blocked).toBe(1);
    await gw.close();
  });
});

describe('StandaloneDataGateway — detection exceptions', () => {
  it('rides active grants on the bundle, consumes atomically, and records blocked detections', async () => {
    const gw = new StandaloneDataGateway(dir);
    // The gateway is read-only over the key: with no key file yet, the cold
    // bundle omits `exceptions` and — decisive for upgrade footprint — no key
    // is minted by merely pulling a bundle.
    const cold = await gw.getPolicyBundle();
    expect(cold.exceptions).toBeUndefined();
    expect(existsSync(join(dir, 'exception.key'))).toBe(false);
    // Mint the key the way the write paths do (ledger/CLI), then grants ride.
    const key = loadOrCreateFingerprintKey(dir);
    expect(key.version).toBe(1);

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const now = Date.now();
    raw
      .prepare(
        `INSERT INTO exceptions (
           id, rule_id, category, value_fingerprint, key_version, masked_value,
           scope, expires_at, max_uses, use_count, justification, created_by,
           created_via, created_at, updated_at
         ) VALUES (?, 'secrets/aws-access-key', 'secret', '0000000000000000000000000000000000000000000000000000000000000001', 1, 'AK…Q',
           'once', NULL, 1, 0, 'temp deploy', 'tester', 'cli-add', ?, ?)`,
      )
      .run(randomUUID(), now, now);
    raw.close();

    const bundle = await gw.getPolicyBundle();
    expect(bundle.exceptions).toHaveLength(1);
    const grant = bundle.exceptions?.[0];
    expect(grant?.valueFingerprint).toBe(
      '0000000000000000000000000000000000000000000000000000000000000001',
    );

    // First consume claims the single use; the second fails secure.
    expect(await gw.consumeException(grant?.id ?? '')).toBe(true);
    expect(await gw.consumeException(grant?.id ?? '')).toBe(false);
    // The exhausted grant no longer rides the bundle.
    expect((await gw.getPolicyBundle()).exceptions).toEqual([]);

    await gw.recordBlockedDetection({
      reference: 'abc123',
      ruleId: 'secrets/aws-access-key',
      category: 'secret',
      valueFingerprint: '0000000000000000000000000000000000000000000000000000000000000002',
      keyVersion: 1,
      maskedValue: 'AK…Q',
      sessionId: null,
      repo: null,
    });
    const check = new DatabaseSync(join(dir, DB_FILENAME));
    const row = check.prepare('SELECT count(*) AS c FROM blocked_detections').get() as {
      c: number;
    };
    check.close();
    expect(row.c).toBe(1);
    await gw.close();
  });
});

describe('StandaloneDataGateway — scan ledger', () => {
  it('round-trips scanned entries and filters by ruleset hash', async () => {
    const gw = new StandaloneDataGateway(dir);
    await gw.recordScanned([
      {
        path: '/repo/a.ts',
        mtime: '2026-07-02T10:00:00.000Z',
        contentHash: 'h1',
        rulesetHash: 'rs1',
      },
    ]);

    const sameRuleset = await gw.scanLedger('rs1');
    expect(sameRuleset.get('/repo/a.ts')).toEqual({
      mtime: '2026-07-02T10:00:00.000Z',
      contentHash: 'h1',
    });
    expect((await gw.scanLedger('rs2')).size).toBe(0);
    await gw.close();
  });
});

describe('staleBinaryNotice (prevention P2)', () => {
  const secretsPack: InstalledPackInput = {
    namespace: 'aka',
    packId: 'secrets',
    version: '2.0.0',
    name: 'Secrets & Credentials',
    rules: [
      {
        specVersion: 1,
        id: 'secrets/aws',
        name: 'aws',
        category: 'secret',
        severity: 'high',
        matcher: { type: 'regex', pattern: 'x', flags: 'g' },
      },
    ],
  };

  it('fires when a newer binary recorded the mirror, quoting both versions', async () => {
    // A newer CLI recorded the inventory…
    const newer = new StandaloneDataGateway(dir, [secretsPack], {
      recordedBy: 'aka-cli@0.0.2-alpha.7',
    });
    await newer.close();
    // …and a session running an older plugin generation asks.
    const gateway = new StandaloneDataGateway(dir);
    const notice = gateway.staleBinaryNotice('0.0.2-alpha.5');
    await gateway.close();
    expect(notice).toContain('v0.0.2-alpha.5');
    expect(notice).toContain('aka-cli v0.0.2-alpha.7');
    expect(notice).toContain('restart the session');
  });

  it('stays silent when this session IS the newest generation, or nothing was recorded', async () => {
    const first = new StandaloneDataGateway(dir, [secretsPack], {
      recordedBy: 'plugin@0.0.2-alpha.6',
    });
    expect(first.staleBinaryNotice('0.0.2-alpha.6')).toBeNull(); // same generation
    expect(first.staleBinaryNotice('0.0.2-alpha.7')).toBeNull(); // even newer
    await first.close();

    const fresh = mkdtempSync(join(tmpdir(), 'aka-standalone-fresh-'));
    try {
      const bare = new StandaloneDataGateway(fresh, [secretsPack]);
      expect(bare.staleBinaryNotice('0.0.2-alpha.5')).toBeNull(); // no recorded_by anywhere
      await bare.close();
    } finally {
      rmSync(fresh, { recursive: true, force: true });
    }
  });
});
