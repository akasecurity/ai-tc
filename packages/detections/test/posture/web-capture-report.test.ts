import type { StoredCaptureStatus, WebCaptureStatus } from '@akasecurity/schema';
import { WebCaptureStatus as WebCaptureStatusSchema, WebSourceTool } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  WEB_CAPTURE_DRIFT_RULE,
  WEB_CAPTURE_DRIFT_STATES,
  webCaptureReport,
  type WebCaptureState,
} from '../../src/posture/web-capture-posture.ts';

function status(over: Partial<WebCaptureStatus> = {}): WebCaptureStatus {
  return WebCaptureStatusSchema.parse({
    patched: true,
    live: false,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    conversationEndpoints: 1,
    enforcement: 'watching',
    ...over,
  });
}

function record(
  tool: StoredCaptureStatus['tool'],
  over: Partial<WebCaptureStatus> = {},
  observedAt = '2026-01-01T00:00:00.000Z',
): StoredCaptureStatus {
  return { tool, observedAt, status: status(over) };
}

describe('webCaptureReport — shape', () => {
  it('reports one row per registered site, in registry order', () => {
    const rows = webCaptureReport([]);
    expect(rows.map((r) => r.tool)).toEqual(WebSourceTool.options);
  });

  it('a site nothing reported is unreported, not absent', () => {
    const rows = webCaptureReport([record('chatgpt')]);
    const claudeAi = rows.find((r) => r.tool === 'claude-ai');
    expect(claudeAi).toBeDefined();
    expect(claudeAi?.state).toBe('unreported');
    expect('observedAt' in (claudeAi as object)).toBe(false);
  });

  it('drift agrees with WEB_CAPTURE_DRIFT_STATES across the whole state table', () => {
    const base = status();
    const STATES: Record<WebCaptureState, WebCaptureStatus | undefined> = {
      unreported: undefined,
      standby: status({ conversationEndpoints: 0 }),
      unpatched: status({ patched: false }),
      blind: status({ blind: true }),
      degraded: status({ shapeMisses: ['x'] }),
      idle: base,
      active: status({ live: true }),
    };

    let driftCount = 0;
    for (const [state, s] of Object.entries(STATES) as [
      WebCaptureState,
      WebCaptureStatus | undefined,
    ][]) {
      const records: StoredCaptureStatus[] =
        s === undefined
          ? []
          : [{ tool: 'chatgpt', observedAt: '2026-01-01T00:00:00.000Z', status: s }];
      const row = webCaptureReport(records).find((r) => r.tool === 'chatgpt');
      expect(row?.state).toBe(state);
      expect(row?.drift).toBe(WEB_CAPTURE_DRIFT_STATES.has(state));
      if (row?.drift === true) driftCount++;
    }
    expect(driftCount).toBe(2);
  });

  it('is quiet when nothing has reported at all', () => {
    const rows = webCaptureReport([]);
    expect(rows.some((r) => r.drift)).toBe(false);
    expect(rows.every((r) => r.state === 'unreported')).toBe(true);
    expect(rows.every((r) => !('remediation' in r))).toBe(true);
  });

  it('is quiet on a build that declares nothing, however loud the rest of the report is', () => {
    const rows = webCaptureReport([
      record('chatgpt', {
        conversationEndpoints: 0,
        patched: true,
        blind: true,
        parseFailures: 5,
        shapeMisses: ['message.id'],
        sendsSeenDom: 9,
      }),
    ]);
    const chatgpt = rows.find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.state).toBe('standby');
    expect(chatgpt?.drift).toBe(false);
    expect(chatgpt !== undefined && 'remediation' in chatgpt).toBe(false);
  });

  it('a drifting row carries remediation; a non-drifting one carries none', () => {
    const rows = webCaptureReport([
      record('chatgpt', { blind: true }),
      record('claude-ai', { live: true }),
    ]);
    const chatgpt = rows.find((r) => r.tool === 'chatgpt');
    const claudeAi = rows.find((r) => r.tool === 'claude-ai');
    expect(chatgpt?.remediation).toBeTruthy();
    expect(claudeAi !== undefined && 'remediation' in claudeAi).toBe(false);
  });

  it('derives each site from its own record', () => {
    const rows = webCaptureReport([
      record('chatgpt', { blind: true }),
      record('claude-ai', { live: true }),
    ]);
    const drifting = rows.filter((r) => r.drift);
    expect(drifting).toHaveLength(1);
    expect(drifting[0]?.tool).toBe('chatgpt');
    const claudeAi = rows.find((r) => r.tool === 'claude-ai');
    expect(claudeAi?.headline).toContain('turn');
  });

  it('carries the record observedAt through', () => {
    const rows = webCaptureReport([record('chatgpt', {}, '2026-03-04T05:06:07.000Z')]);
    const chatgpt = rows.find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.observedAt).toBe('2026-03-04T05:06:07.000Z');
  });

  it('the rule carries the id and severity every surface cites it by', () => {
    expect(WEB_CAPTURE_DRIFT_RULE.ruleId).toBe('web-capture-drift');
    expect(WEB_CAPTURE_DRIFT_RULE.severity).toBe('medium');
  });
});
