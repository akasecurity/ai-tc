import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME } from '@akasecurity/persistence';
import { loadOrCreateFingerprintKey } from '@akasecurity/plugin-sdk';
import type { DetectedFinding, IngestEvent, InstalledPackInput } from '@akasecurity/schema';
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

  it('synthesizes a local policy bundle from the seeded policies (no rules)', async () => {
    const gw = new StandaloneDataGateway(dir);
    const bundle = await gw.getPolicyBundle();
    expect(bundle.version).toBe('local');
    expect(bundle.rules).toEqual([]);
    // One seeded policy per default category.
    const categories = bundle.policies
      .map((p) => ('category' in p.target ? p.target.category : null))
      .filter(Boolean);
    expect(new Set(categories)).toEqual(
      new Set(['secret', 'pii', 'financial', 'phi', 'code_context', 'code_flaw', 'custom']),
    );
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
