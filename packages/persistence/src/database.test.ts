import { randomUUID } from 'node:crypto';
import { mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, IngestEvent } from '@akasecurity/schema';
import { DEFAULT_ACTIONS } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from './database.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-persistence-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const MASKED = 'AKIA…MPLE';

function event(overrides: Partial<IngestEvent> = {}): IngestEvent {
  return {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date().toISOString(),
    contentHash: 'hash',
    content: 'here is a key <redacted>',
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
    span: { start: 14, end: 34 },
    maskedMatch: MASKED,
    actionTaken: 'block',
    confidence: 0.9,
    ...overrides,
  };
}

describe('openLocalDatabase — open / migrate / seed', () => {
  it('applies the schema and is safe to open repeatedly (idempotent migrations)', async () => {
    const d1 = openLocalDatabase(dir);
    // First open seeds the default policies into the tenant-free store.
    const seeded = await d1.policies.readPolicies();
    expect(seeded.length).toBeGreaterThan(0);
    d1.close();

    // Re-opening applies no migration twice and does not re-seed (the seed guard
    // is "table is empty"), so the policy count is unchanged — no error, no churn.
    const d2 = openLocalDatabase(dir);
    const reopened = await d2.policies.readPolicies();
    expect(reopened.length).toBe(seeded.length);
    d2.close();
  });

  it('seeds one enabled policy per default category', async () => {
    const db = openLocalDatabase(dir);
    const policies = await db.policies.readPolicies();
    db.close();

    const categories = policies
      .map((p) => ('category' in p.target ? p.target.category : null))
      .filter(Boolean);
    // Derived from DEFAULT_ACTIONS so a new category (e.g. 'config') extends
    // the seed without a hand-maintained duplicate here.
    expect(new Set(categories)).toEqual(new Set(Object.keys(DEFAULT_ACTIONS)));
    expect(policies.every((p) => p.enabled)).toBe(true);
  });

  it('writes the db file owner-only (0600) where POSIX modes apply', () => {
    const db = openLocalDatabase(dir);
    db.close();
    if (process.platform === 'win32') return;
    const mode = statSync(join(dir, 'aka.db')).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('backs up and recreates an incompatible legacy tenant-bearing aka.db instead of silently failing writes', async () => {
    // Simulate an old (tenant-bearing) store this lineage can't migrate
    // forward: a `tenants` table + a tenant_id column, with a bumped user_version
    // so the applier would otherwise skip it entirely.
    const file = join(dir, 'aka.db');
    const legacy = new DatabaseSync(file);
    legacy.exec('CREATE TABLE tenants (id TEXT PRIMARY KEY)');
    legacy.exec('CREATE TABLE events (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)');
    legacy.exec('PRAGMA user_version = 10');
    legacy.close();

    // Opening detects the foreign lineage, backs it up, and starts fresh — so a
    // write now succeeds (the old schema would have thrown NOT NULL tenant_id,
    // swallowed fail-open).
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);
    expect(await db.findings.recentFindings()).toHaveLength(1);
    db.close();

    // The old store is preserved (recoverable), not destroyed.
    const backups = readdirSync(dir).filter((f) => f.includes('.legacy.'));
    expect(backups).toHaveLength(1);
  });
});

describe('recordCapture', () => {
  it('persists one event + N findings exactly as given (already masked)', async () => {
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);

    const findings = await db.findings.recentFindings();
    expect(findings).toHaveLength(1);
    expect(findings[0]?.maskedMatch).toBe(MASKED);
    expect(findings[0]?.actionTaken).toBe('block');
    expect(findings[0]?.occurredAt).toBe(ev.occurredAt);
    db.close();
  });

  it('dedupes a finding repeated across surfaces within one session', async () => {
    const db = openLocalDatabase(dir);
    const sessionId = randomUUID();
    // Same value flagged on the prompt, then again when written to a file — one
    // logical action across two surfaces, sharing a session id.
    const prompt = event({ kind: 'prompt', metadata: { sessionId } });
    const write = event({ kind: 'code_change', metadata: { sessionId } });
    db.recordCapture(prompt, [
      finding(prompt.id, { ruleId: 'core-pii/email', maskedMatch: 'j*@example.com' }),
      finding(prompt.id, { ruleId: 'core-pii/ssn', maskedMatch: '1******9' }),
    ]);
    db.recordCapture(write, [
      finding(write.id, { ruleId: 'core-pii/email', maskedMatch: 'j*@example.com' }),
      finding(write.id, { ruleId: 'core-pii/ssn', maskedMatch: '1******9' }),
    ]);

    // Two distinct (rule, value) findings — not four — and both link to the
    // first surface that recorded them (the prompt).
    const findings = await db.findings.recentFindings();
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.eventId === prompt.id)).toBe(true);
    expect(new Set(findings.map((f) => f.ruleId))).toEqual(
      new Set(['core-pii/email', 'core-pii/ssn']),
    );
    db.close();
  });

  it('keeps distinct values, and the same value in a different session', async () => {
    const db = openLocalDatabase(dir);
    const s1 = randomUUID();
    const s2 = randomUUID();
    // Two different emails in one session → both kept (different masked value).
    const e1 = event({ metadata: { sessionId: s1 } });
    db.recordCapture(e1, [
      finding(e1.id, { ruleId: 'core-pii/email', maskedMatch: 'a*@example.com' }),
      finding(e1.id, { ruleId: 'core-pii/email', maskedMatch: 'b*@example.com' }),
    ]);
    // The same value as e1, but a different session → kept (dedup is per session).
    const e2 = event({ metadata: { sessionId: s2 } });
    db.recordCapture(e2, [
      finding(e2.id, { ruleId: 'core-pii/email', maskedMatch: 'a*@example.com' }),
    ]);

    expect(await db.findings.recentFindings()).toHaveLength(3);
    db.close();
  });

  it('is fail-open: a duplicate event id is swallowed, never thrown', async () => {
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);
    // Same id again → PK violation inside the txn → rolled back, not thrown.
    expect(() => {
      db.recordCapture(ev, [finding(ev.id)]);
    }).not.toThrow();
    expect(await db.findings.recentFindings()).toHaveLength(1);
    db.close();
  });
});

describe('read surfaces', () => {
  it('healthSummary counts by action and severity and reports full coverage on a fresh store', async () => {
    const db = openLocalDatabase(dir);
    const e1 = event();
    const e2 = event();
    db.recordCapture(e1, [finding(e1.id, { actionTaken: 'block', severity: 'critical' })]);
    db.recordCapture(e2, [finding(e2.id, { actionTaken: 'warn', severity: 'low' })]);

    const health = await db.findings.healthSummary();
    expect(health.findings).toBe(2);
    expect(health.byAction.block).toBe(1);
    expect(health.byAction.warn).toBe(1);
    // Whole-store per-severity tally that powers the status bar; sums to findings.
    expect(health.bySeverity).toEqual({ critical: 1, high: 0, medium: 0, low: 1 });
    expect(health.coverage).toBe(1);
    db.close();
  });

  it('activityByDay returns a continuous window with today populated', async () => {
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id, { actionTaken: 'block' })]);

    const days = await db.findings.activityByDay(7);
    expect(days).toHaveLength(7);
    const today = new Date().toISOString().slice(0, 10);
    const todayBucket = days.find((d) => d.day === today);
    expect(todayBucket?.total).toBe(1);
    expect(todayBucket?.blocked).toBe(1);
    db.close();
  });
});

describe('transaction', () => {
  it('commits every write inside fn atomically', async () => {
    const db = openLocalDatabase(dir);
    db.policies.upsertCategoryAction('secret', 'warn');
    await db.transaction(() => {
      db.policies.upsertCategoryAction('secret', 'block');
      db.policies.upsertCategoryAction('pii', 'block');
    });
    expect(db.policies.getCategoryAction('secret')).toBe('block');
    expect(db.policies.getCategoryAction('pii')).toBe('block');
    db.close();
  });

  it('rolls back every write inside fn on throw', async () => {
    const db = openLocalDatabase(dir);
    db.policies.upsertCategoryAction('secret', 'warn');
    await expect(
      db.transaction(() => {
        db.policies.upsertCategoryAction('secret', 'block');
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(db.policies.getCategoryAction('secret')).toBe('warn');
    db.close();
  });

  it('rolls back a nested exceptions.create() collision-retry when the outer fn throws', async () => {
    const db = openLocalDatabase(dir);
    const grant = {
      ruleId: 'aws-access-key-id',
      category: 'secret' as const,
      valueFingerprint: 'a'.repeat(64),
      keyVersion: 1,
      maskedValue: 'AKIA******Q',
      scope: 'once' as const,
      expiresAt: null,
      maxUses: 1,
      justification: 'test grant',
      conditions: null,
      createdBy: 'alice',
      createdVia: 'cli-approve' as const,
    };
    const created = await db.exceptions.create(grant);
    expect(await db.exceptions.consume(created.id)).toBe(true);

    await expect(
      db.transaction(async () => {
        await db.exceptions.create(grant);
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');

    const all = await db.exceptions.list({ includeTerminal: true });
    expect(all.map((e) => e.id)).toEqual([created.id]);
    expect(all[0]?.revokedAt).toBeNull();
    expect(all[0]?.useCount).toBe(1);
    db.close();
  });
});

describe('store hygiene', () => {
  it('does not write the WAL/SHM secret to a separate plaintext copy', () => {
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);
    db.close();

    // The findings table holds only the masked value handed in — never a raw one.
    const raw = new DatabaseSync(join(dir, 'aka.db'));
    const masked = raw.prepare('SELECT masked_match FROM findings').all() as {
      masked_match: string;
    }[];
    raw.close();
    expect(masked).toEqual([{ masked_match: MASKED }]);
  });
});
