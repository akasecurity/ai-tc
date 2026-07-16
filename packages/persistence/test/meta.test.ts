import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { AuditEventInput, InventoryInput, SourceProjectInput } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { type InventoryContext, openLocalDatabase } from '../src/database.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-meta-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const host: InventoryInput = {
  objectType: 'host',
  identityKey: 'machine-abc-123',
  title: 'my-laptop',
  location: 'office',
  attributes: { host_name: 'my-laptop', os: 'darwin', os_version: '25.5.0', arch: 'arm64' },
};
const harness: InventoryInput = {
  objectType: 'harness',
  identityKey: 'claude-code',
  title: 'Claude Code',
  attributes: { harness_version: '1.2.3', interface: 'cli' },
};
const project: SourceProjectInput = {
  url: 'https://github.com/org/repo.git',
  name: 'repo',
  attributes: {},
};
// The account (User/Account) dimension is NOT in the context — ensureInventory
// derives it from the store's local identity.
const context: InventoryContext = { host, harness, project };

// A second read connection to the same WAL file, for COUNT / EXPLAIN that the
// repository surface doesn't expose.
function raw(): DatabaseSync {
  return new DatabaseSync(join(dir, 'aka.db'));
}
function count(db: DatabaseSync, table: string): number {
  return (db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;
}

describe('ensureInventory', () => {
  it('upserts one host/harness/account/project row and resolves their ids', () => {
    const db = openLocalDatabase(dir);
    const resolved = db.ensureInventory(context);

    expect(resolved.hostId).toBeTypeOf('string');
    expect(resolved.harnessId).toBeTypeOf('string');
    expect(resolved.accountId).toBeTypeOf('string');
    expect(resolved.sourceProjectId).toBeTypeOf('string');

    const r = raw();
    expect(count(r, 'inventory')).toBe(3); // host + harness + account
    expect(count(r, 'source_project')).toBe(1);
    // harness/account rows link to the host row (the intra-inventory edge).
    const harnessRow = db.inventory.findById(resolved.harnessId ?? '');
    expect(harnessRow?.host_id).toBe(resolved.hostId);
    r.close();
    db.close();
  });

  it('is idempotent: a second session no-ops the inserts and advances last_seen', () => {
    const db = openLocalDatabase(dir);
    const first = db.ensureInventory(context);
    const second = db.ensureInventory(context);

    // Same content-addressed ids — no duplicate rows.
    expect(second).toEqual(first);
    const r = raw();
    expect(count(r, 'inventory')).toBe(3);
    expect(count(r, 'source_project')).toBe(1);
    r.close();

    // last_seen advances on the repeat upsert; first_seen is pinned to the first.
    const hostRow1 = db.inventory.findById(first.hostId ?? '');
    expect(hostRow1).toBeDefined();
    const firstSeen = hostRow1?.first_seen ?? 0;
    const lastSeen = hostRow1?.last_seen ?? 0;
    db.inventory.upsert(host, lastSeen + 5000);
    const hostRow2 = db.inventory.findById(first.hostId ?? '');
    expect(hostRow2?.first_seen).toBe(firstSeen);
    expect(hostRow2?.last_seen).toBe(lastSeen + 5000);
    db.close();
  });

  it('overwrites volatile attributes to latest while pinning first_seen (Type-1)', () => {
    const db = openLocalDatabase(dir);
    const id = db.inventory.upsert(host, 1000);
    const before = db.inventory.findById(id);
    expect(before?.os_version).toBe('25.5.0');

    // Same identity key (stable id), upgraded OS — the dimension reflects latest.
    const upgraded = { ...host, attributes: { ...host.attributes, os_version: '26.0.0' } };
    db.inventory.upsert(upgraded, 2000);
    const after = db.inventory.findById(id);
    expect(after?.os_version).toBe('26.0.0'); // generated column tracks the bag
    expect(after?.first_seen).toBe(1000); // pinned to the first sighting
    expect(after?.last_seen).toBe(2000); // advanced
    db.close();
  });

  it('produces stable ids across separate opens of the same store', () => {
    const d1 = openLocalDatabase(dir);
    const r1 = d1.ensureInventory(context);
    d1.close();

    const d2 = openLocalDatabase(dir);
    const r2 = d2.ensureInventory(context);
    const r = raw();
    expect(r2).toEqual(r1);
    expect(count(r, 'inventory')).toBe(3); // still one row each, not six
    r.close();
    d2.close();
  });
});

describe('audit events + inspection findings', () => {
  it('stamps the resolved inventory FKs onto a Session audit row and its children', () => {
    const db = openLocalDatabase(dir);
    const resolved = db.ensureInventory(context);

    const sessionId = randomUUID();
    const session: AuditEventInput = {
      id: sessionId,
      eventType: 'session',
      startedAt: new Date().toISOString(),
      hostId: resolved.hostId,
      harnessId: resolved.harnessId,
      sourceProjectId: resolved.sourceProjectId,
      // Volatile attrs snapshotted onto the fact (true at capture).
      attributes: { os_version: '25.5.0', harness_version: '1.2.3' },
    };
    db.auditEvents.insertAuditEvent(session);

    // A child event under the session resolves its dimensions via root_session_id.
    const child: AuditEventInput = {
      id: randomUUID(),
      eventType: 'prompt',
      startedAt: new Date().toISOString(),
      parentId: sessionId,
      rootSessionId: sessionId,
      content: 'here is a key <redacted>',
      contentHash: 'abc123',
    };
    db.auditEvents.insertAuditEvent(child);

    const sessionRow = db.auditEvents.findById(sessionId);
    expect(sessionRow?.host_id).toBe(resolved.hostId);
    expect(sessionRow?.harness_id).toBe(resolved.harnessId);
    expect(sessionRow?.source_project_id).toBe(resolved.sourceProjectId);

    const childRow = db.auditEvents.findById(child.id);
    expect(childRow?.parent_id).toBe(sessionId);
    expect(childRow?.root_session_id).toBe(sessionId);
    db.close();
  });

  it('insertLlmCall mints a deterministic id from the natural key and is idempotent', () => {
    const db = openLocalDatabase(dir);
    db.ensureInventory(context);
    const sessionId = randomUUID();
    db.auditEvents.insertAuditEvent({
      id: sessionId,
      eventType: 'session',
      startedAt: new Date().toISOString(),
      attributes: { provider: 'bedrock' },
    });

    const input = {
      sessionId,
      messageId: 'msg_xyz',
      parentId: sessionId,
      rootSessionId: sessionId,
      startedAt: '2026-06-20T10:00:00.000Z',
      attributes: { model: 'm', provider: 'bedrock', input_tokens: 1, output_tokens: 2 },
    };
    db.auditEvents.insertLlmCall(input);
    // Re-inserting the same natural key is a no-op (deterministic id + INSERT OR IGNORE).
    db.auditEvents.insertLlmCall(input);

    const raw = new DatabaseSync(join(dir, 'aka.db'));
    const n = raw
      .prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = 'llm_call'")
      .get() as { n: number };
    expect(n.n).toBe(1);
    raw.close();

    // The provider snapshotted on the root reads back for the reconciler.
    expect(db.auditEvents.sessionProvider(sessionId)).toBe('bedrock');
    db.close();
  });

  it('insertLlmCall takes MAX(output_tokens) on conflict — converges up, never down', () => {
    const db = openLocalDatabase(dir);
    db.ensureInventory(context);
    const sessionId = randomUUID();
    db.auditEvents.insertAuditEvent({
      id: sessionId,
      eventType: 'session',
      startedAt: new Date().toISOString(),
    });

    const leaf = (outputTokens: number) => ({
      sessionId,
      messageId: 'msg_stream',
      parentId: sessionId,
      rootSessionId: sessionId,
      startedAt: '2026-06-20T10:00:00.000Z',
      attributes: {
        model: 'm',
        provider: 'anthropic',
        input_tokens: 100,
        output_tokens: outputTokens,
      },
    });

    const raw = new DatabaseSync(join(dir, 'aka.db'));
    const readOutput = (): number =>
      (
        raw
          .prepare("SELECT output_tokens AS o FROM audit_events WHERE event_type = 'llm_call'")
          .get() as { o: number }
      ).o;
    const count = (): number =>
      (
        raw
          .prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = 'llm_call'")
          .get() as { n: number }
      ).n;

    // Partial (1) then terminal (338) → converges UP to 338, still one row.
    db.auditEvents.insertLlmCall(leaf(1));
    expect(readOutput()).toBe(1);
    db.auditEvents.insertLlmCall(leaf(338));
    expect(count()).toBe(1);
    expect(readOutput()).toBe(338); // generated column recomputed from the new bag

    // A stale, smaller write afterward is ignored by the MAX guard (never decreases).
    db.auditEvents.insertLlmCall(leaf(1));
    expect(readOutput()).toBe(338);

    raw.close();
    db.close();
  });

  it('records a finding referencing its audit event, definition version and class', () => {
    const db = openLocalDatabase(dir);
    db.ensureInventory(context);

    const auditEventId = randomUUID();
    db.auditEvents.insertAuditEvent({
      id: auditEventId,
      eventType: 'prompt',
      startedAt: new Date().toISOString(),
    });

    const definitionId = db.inspectionDefinitions.upsert({
      ruleId: 'secrets/aws-access-key',
      version: '1.0.0',
      name: 'AWS access key',
      category: 'secret',
      severity: 'critical',
      definition: '{"matcher":"regex"}',
    });
    const classId = db.classifiedData.upsert({ class: 'aws_key', label: 'AWS key' });

    db.inspectionFindings.insertFinding({
      id: randomUUID(),
      auditEventId,
      inspectionDefinitionId: definitionId,
      classifiedDataId: classId,
      span: { start: 14, end: 34 },
      maskedMatch: 'AKIA…MPLE',
      actionTaken: 'block',
      confidence: 0.9,
    });

    const r = raw();
    expect(count(r, 'inspection_findings')).toBe(1);
    expect(count(r, 'inspection_definitions')).toBe(1);
    expect(count(r, 'classified_data')).toBe(1);
    // Editing the rule version mints a new definition id; re-upserting the same
    // version no-ops.
    expect(
      db.inspectionDefinitions.upsert({
        ruleId: 'secrets/aws-access-key',
        version: '1.0.0',
        name: 'AWS access key',
        category: 'secret',
        severity: 'critical',
        definition: '{"matcher":"regex"}',
      }),
    ).toBe(definitionId);
    expect(count(r, 'inspection_definitions')).toBe(1);
    r.close();
    db.close();
  });
});

describe('facets (read from the dimension, not the fact)', () => {
  it('returns distinct hosts/os_versions from inventory', () => {
    const db = openLocalDatabase(dir);
    db.ensureInventory(context);
    db.ensureInventory({
      host: {
        objectType: 'host',
        identityKey: 'machine-xyz-789',
        title: 'other-laptop',
        attributes: { host_name: 'other-laptop', os: 'linux', os_version: '6.1.0' },
      },
    });

    expect(db.inventory.distinctTitles('host')).toEqual(['my-laptop', 'other-laptop']);
    expect(db.inventory.osVersions()).toEqual(['25.5.0', '6.1.0']);
    db.close();
  });

  it('serves the os_version facet from an inventory index, not a scan of the fact', () => {
    const db = openLocalDatabase(dir);
    db.ensureInventory(context);
    db.close();

    const r = raw();
    // Mirror osVersions()'s actual (tenant-free) query.
    const plan = r
      .prepare(
        `EXPLAIN QUERY PLAN SELECT DISTINCT os_version AS value FROM inventory
         WHERE object_type = 'host' AND os_version IS NOT NULL
         ORDER BY value`,
      )
      .all() as { detail: string }[];
    const detail = plan.map((p) => p.detail).join(' | ');
    // Resolved through an inventory index (one of the generated-column facet
    // indexes), and never by scanning the audit fact table.
    expect(detail).toMatch(/USING (COVERING )?INDEX idx_inventory/);
    expect(detail).not.toMatch(/audit_events/);
    r.close();
  });
});
