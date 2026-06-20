import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DetectedFinding, IngestEvent } from '@aka/schema';
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
      new Set(['secret', 'pii', 'financial', 'phi', 'code_context', 'custom']),
    );
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
