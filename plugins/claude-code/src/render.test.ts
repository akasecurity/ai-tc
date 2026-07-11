import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { handleCapture, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { FindingView, HealthSummary, PluginConfig } from '@akasecurity/plugin-sdk';
import type { DetectionException } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { paint } from './present.ts';
import {
  buildHealthReport,
  buildRecommendations,
  healthScore,
  renderAudit,
  renderExceptions,
  renderFindings,
  renderFirstRun,
  renderHealth,
  renderRecommend,
  renderSetupIntro,
  renderStatusLine,
  runQuery,
  topFindings,
} from './render.ts';

// In standalone mode the effective ruleset is the store's INSTALLED snapshot
// (seeded from bundledDetections() by resolveDataGateway), not ad-hoc packs
// registered into the engine — so the gateway-backed tests detect with REAL
// bundled rules: secrets/aws-access-key (critical secret) and core-pii/email
// (medium pii). The canonical AWS example key id is composed at runtime so the
// repo's own secret scanning doesn't flag this file.
const AWS_EXAMPLE_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
// Composed for the same reason — a literal address would be redacted on write.
const PII_EMAIL = ['jane.doe', 'example.com'].join('@');

// Strip ANSI so assertions match on the visible text, not the color codes.
// Built without a literal control char to keep clear of no-control-regex.
const ANSI = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g');
const strip = (s: string): string => s.replace(ANSI, '');

function finding(overrides: Partial<FindingView> = {}): FindingView {
  return {
    id: randomUUID(),
    eventId: randomUUID(),
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    maskedMatch: 'AKIA…MPLE',
    actionTaken: 'block',
    confidence: 0.9,
    occurredAt: '2026-06-19T11:14:53.000Z',
    sourceTool: 'claude-code',
    kind: 'prompt',
    ...overrides,
  };
}

function exception(overrides: Partial<DetectionException> = {}): DetectionException {
  return {
    id: randomUUID(),
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: 'f'.repeat(64),
    keyVersion: 1,
    maskedValue: 'AKIA…MPLE',
    scope: 'temporary',
    expiresAt: '2026-07-06T13:00:00.000Z',
    maxUses: null,
    useCount: 3,
    lastUsedAt: null,
    justification: 'temp deploy creds, rotating after infra apply',
    conditions: null,
    createdBy: 'alice (local)',
    createdVia: 'cli-approve',
    createdAt: '2026-07-06T11:00:00.000Z',
    updatedAt: '2026-07-06T11:00:00.000Z',
    revokedAt: null,
    revokedBy: null,
    revokeReason: null,
    ...overrides,
  };
}

describe('pure renderers', () => {
  it('findings: empty state vs populated table', () => {
    const status = {
      score: 72,
      unreviewed: { critical: 1, high: 0, medium: 0, low: 1 },
      openFindings: 2,
    };
    expect(strip(renderFindings([], status))).toContain('No findings recorded yet');

    const out = strip(
      renderFindings([finding(), finding({ category: 'pii', severity: 'low' })], status),
    );
    expect(out).toContain('Recent findings (2)');
    expect(out).toContain('secrets/aws-access-key');
    expect(out).toContain('AKIA…MPLE');
    // Severity is encoded by shade glyph, not color: critical solid, low light.
    expect(out).toContain('█ critical');
    expect(out).toContain('░ low');
    expect(out).toContain('open findings'); // status bar present
  });

  it('health: real gauges, summary line, 7-day chart from activity, footer', () => {
    const summary: HealthSummary = {
      findings: 3,
      byAction: { block: 2, redact: 1, warn: 0, allow: 0, log: 0 },
      bySeverity: { critical: 2, high: 0, medium: 0, low: 1 },
      coverage: 1,
    };
    const findings = [finding(), finding({ category: 'pii', severity: 'low' })];
    const activity = [
      { day: '2026-06-20', total: 0, redacted: 0, warned: 0, blocked: 0 },
      { day: '2026-06-21', total: 3, redacted: 1, warned: 0, blocked: 2 },
    ];
    const out = strip(renderHealth(buildHealthReport(summary, findings, activity)));
    expect(out).toContain('Setup health — local Claude Code deployment');
    expect(out).toContain('Overall');
    expect(out).toContain('/ 100');
    expect(out).toContain('Scan coverage');
    expect(out).toContain('100%');
    expect(out).toContain('Detections & actions — last 7 days');
    expect(out).toContain('allowed');
    // The chart is built from the supplied activity, not hardcoded.
    expect(out).toContain('Sat'); // 2026-06-20 is a Saturday (UTC)
    expect(out).toContain('3 findings in the last 7 days');
    expect(out).toContain('open findings');
    // No fabricated gauges/metrics remain.
    expect(out).not.toContain('Tokens saved');
    expect(out).not.toContain('MCP servers');
  });

  it('recommend: ranks by severity, numbered list with severity badges', () => {
    const recs = buildRecommendations([
      finding({ category: 'pii', severity: 'low', ruleId: 'pii/email' }),
      finding({ category: 'pii', severity: 'low', ruleId: 'pii/email' }),
      finding({ category: 'secret', severity: 'critical' }),
    ]);
    const status = {
      score: 72,
      unreviewed: { critical: 1, high: 0, medium: 0, low: 2 },
      openFindings: 2,
    };
    const out = strip(renderRecommend(recs, status));
    expect(out).toContain('2 recommendations for your setup, ordered by severity');
    expect(out).toContain('CRITICAL');
    expect(out).toContain('Exposed secret detected');
    // Critical secret is ranked above the more-frequent low-severity pii.
    expect(out.indexOf('CRITICAL')).toBeLessThan(out.indexOf('LOW'));
    expect(out).toContain('Rotate the exposed credentials');
    expect(out).toContain('1. █ CRITICAL'); // numbered list with a severity badge
    expect(out).toContain('→ Rotate'); // the action verb on the meta line
    expect(out).toContain('open findings'); // status bar present
    expect(strip(renderRecommend([], status))).toContain('No recommendations yet');

    // Singular is grammatical with a single recommendation.
    const one = strip(
      renderRecommend(buildRecommendations([finding({ category: 'secret' })]), status),
    );
    expect(one).toContain('1 recommendation for your setup');
  });

  it('audit: decision log with action and source', () => {
    const out = strip(renderAudit([finding({ actionTaken: 'redact' })]));
    expect(out).toContain('Recent decisions (1)');
    expect(out).toContain('redact');
    expect(out).toContain('claude-code/prompt');
  });

  it('exceptions: masked rows, relative expiry, use budget, CLI how-to footer', () => {
    const NOW = Date.parse('2026-07-06T12:00:00.000Z');
    const out = strip(
      renderExceptions(
        [
          exception({
            id: '3f2a91ab-0000-4000-8000-000000000000',
            expiresAt: new Date(NOW + 42 * 60_000).toISOString(),
          }),
          exception({
            ruleId: 'core-pii/email',
            category: 'pii',
            maskedValue: 'v*******@gmail.com',
            scope: 'permanent',
            expiresAt: null,
            useCount: 118,
          }),
          exception({ scope: 'once', maxUses: 1, useCount: 0 }),
        ],
        NOW,
      ),
    );
    expect(out).toContain('Active exceptions (3)');
    expect(out).toContain('3f2a91ab'); // short id, enough for `aka exception revoke`
    expect(out).toContain('AKIA…MPLE'); // masked preview only — never a raw value
    expect(out).toContain('secrets/aws-access-key');
    expect(out).toContain('in 42m'); // relative expiry
    expect(out).toContain('—'); // permanent grant has no expiry
    expect(out).toContain('118');
    expect(out).toContain('0/1'); // once scope shows its use budget
    expect(out).toContain('alice (local)');
    // Read-only surface: the footer points at the CLI for approve/revoke.
    expect(out).toContain('aka exception approve');
    expect(out).toContain('aka exception revoke <id>');
  });

  it('exceptions: empty state explains how a grant comes to exist', () => {
    const out = strip(renderExceptions([], Date.parse('2026-07-06T12:00:00.000Z')));
    expect(out).toContain('No active exceptions.');
    expect(out).toContain('block message');
  });

  it('audit/findings: guard findings missing time/source', () => {
    // A finding can lack occurredAt/sourceTool/kind — render a placeholder
    // timestamp and avoid a bare "/" source rather than reading as broken.
    const partial = finding({ occurredAt: '', sourceTool: '', kind: '' });
    const audit = strip(renderAudit([partial]));
    expect(audit).toContain('—'); // placeholder timestamp
    expect(audit).not.toContain('/prompt');
    expect(audit).not.toMatch(/\s\/\s/); // no bare slash source cell
    const status = {
      score: 0,
      unreviewed: { critical: 0, high: 0, medium: 0, low: 0 },
      openFindings: 0,
    };
    expect(strip(renderFindings([partial], status))).toContain('—');
  });

  it('setup intro: card with manifest facts', () => {
    const out = strip(
      renderSetupIntro({
        name: 'AKA Security',
        tagline: 'Agent Harness Security for Claude Code.',
        repository: 'github.com/akasecurity/ai-tc',
        version: '0.0.1',
        publisher: 'AKA',
        adds: 'Secures your local environment to prevent secret leakage and vulnerabilities.',
      }),
    );
    expect(out).toContain('Found AKA Security');
    expect(out).toContain('github.com/akasecurity/ai-tc');
    expect(out).toContain('0.0.1 · AKA');
    expect(out).toContain('two quick questions');
  });

  it('healthScore: blends coverage and handled ratio into 0–100', () => {
    // Full coverage, every finding handled → 100.
    expect(
      healthScore({
        findings: 4,
        byAction: { block: 2, redact: 2, warn: 0, allow: 0, log: 0 },
        bySeverity: { critical: 2, high: 0, medium: 0, low: 2 },
        coverage: 1,
      }),
    ).toBe(100);
    // No findings → handled ratio defaults to 1, score tracks coverage.
    expect(
      healthScore({
        findings: 0,
        byAction: { block: 0, redact: 0, warn: 0, allow: 0, log: 0 },
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        coverage: 0.5,
      }),
    ).toBe(70);
  });

  it('first run: install-complete summary with real-ish stats', () => {
    const out = strip(
      renderFirstRun({
        commands: ['/health', '/recommend', '/findings', '/audit'],
        handling: 'Active redaction enabled',
        health: 72,
        findings: 142,
        recommendations: 6,
      }),
    );
    expect(out).toContain('AKA Security installed');
    expect(out).toContain('/health · /recommend · /findings · /audit');
    expect(out).toContain('Health 72/100');
    expect(out).toContain('Findings 142');
    expect(out).toContain('Recommendations 6');
    expect(out).toContain('run /health anytime');
  });

  it('first run: clean scan hides the Top findings section', () => {
    const out = strip(
      renderFirstRun({
        commands: ['/health'],
        handling: 'Active redaction enabled',
        health: 100,
        findings: 0,
        recommendations: 0,
        topFindings: [],
      }),
    );
    expect(out).not.toContain('Top findings');
  });

  it('first run: lists the top findings table when the scan caught something', () => {
    const out = strip(
      renderFirstRun({
        commands: ['/health'],
        handling: 'Active redaction enabled',
        health: 80,
        findings: 2,
        recommendations: 2,
        topFindings: [
          finding({ ruleId: 'secrets/aws-access-key', category: 'secret', severity: 'critical' }),
          finding({ ruleId: 'pii/email', category: 'pii', severity: 'low' }),
        ],
      }),
    );
    expect(out).toContain('Top findings (2)');
    expect(out).toContain('secrets/aws-access-key');
    expect(out).toContain('pii/email');
    // The masked match shows; the raw secret never does (finding() masks it).
    expect(out).toContain('AKIA…MPLE');
  });

  it('topFindings: ranks by severity then recency, capped to the limit', () => {
    const ranked = topFindings(
      [
        finding({ ruleId: 'low-old', severity: 'low', occurredAt: '2026-06-19T08:00:00.000Z' }),
        finding({ ruleId: 'crit', severity: 'critical', occurredAt: '2026-06-19T09:00:00.000Z' }),
        finding({ ruleId: 'high-old', severity: 'high', occurredAt: '2026-06-19T08:00:00.000Z' }),
        finding({ ruleId: 'high-new', severity: 'high', occurredAt: '2026-06-19T10:00:00.000Z' }),
      ],
      3,
    );
    expect(ranked.map((f) => f.ruleId)).toEqual(['crit', 'high-new', 'high-old']);
  });

  it('status line: colour layout, with the flag red only when findings are open', () => {
    const summary: HealthSummary = {
      findings: 2,
      byAction: { block: 1, redact: 1, warn: 0, allow: 0, log: 0 },
      bySeverity: { critical: 1, high: 0, medium: 0, low: 1 },
      coverage: 1,
    };
    // The summary reports 2 open findings → the flag takes the critical hue.
    const withOpen = renderStatusLine(summary);
    expect(strip(withOpen)).not.toBe(withOpen); // colour mode emits ANSI
    expect(strip(withOpen)).toContain('⚑ 2 open findings');
    expect(withOpen).toContain(paint.critical('⚑')); // the flag itself is red

    // Nothing open → the flag is dim, not red (no alert). The severity legend still
    // carries colour, so the line isn't ANSI-free — only the flag changes.
    const clean = renderStatusLine({
      findings: 0,
      byAction: { block: 0, redact: 0, warn: 0, allow: 0, log: 0 },
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      coverage: 1,
    });
    expect(clean).not.toContain(paint.critical('⚑'));
    expect(clean).toContain(paint.dim('⚑'));
    expect(strip(clean)).toContain('⚑ 0 open findings');
  });

  it('transcript footers stay monochrome — no ANSI even with open findings', () => {
    const status = {
      score: 100,
      unreviewed: { critical: 1, high: 0, medium: 0, low: 0 },
      openFindings: 1,
    };
    const out = renderFindings([finding()], status);
    expect(strip(out)).toBe(out); // status bar on a read surface is plain
  });
});

describe('runQuery — against a seeded standalone gateway', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-query-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const SECRET = AWS_EXAMPLE_KEY;

  function config(dataDir: string): PluginConfig {
    return {
      settings: {
        specVersion: 1,
        runMode: 'standalone',
        policy: 'redact',
        historicalAccess: 'session-only',
      },
      dataDir,
      dbPath: join(dataDir, 'aka.db'),
      settingsDir: dataDir,
      onboarded: true,
      provider: { provider: 'anthropic' },
    };
  }

  it('renders each subcommand from real data and never leaks the raw secret', async () => {
    // Seed through the real write path (detect → mask → standalone gateway).
    await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text: `here is a key ${SECRET}` },
      config(dir),
    );

    const gateway = resolveDataGateway(config(dir));
    try {
      const findings = strip(await runQuery('findings', gateway));
      expect(findings).toContain('Recent findings (1)');
      expect(findings).toContain('secrets/aws-access-key');
      expect(findings).not.toContain(SECRET);

      expect(strip(await runQuery('health', gateway))).toContain('Setup health');
      // The bundled secrets pack is unassigned → Monitor by default, so the
      // decision renders as 'log' (the finding is still recorded and masked).
      expect(strip(await runQuery('audit', gateway))).toContain('log');
      expect(strip(await runQuery('recommend', gateway))).toContain(
        'Rotate the exposed credentials',
      );
      expect(strip(await runQuery('bogus', gateway))).toContain('Usage:');
    } finally {
      await gateway.close();
    }
  });

  it('status bar stays stable across surfaces even when /findings truncates its page', async () => {
    // Seed more findings than the /findings page limit (25) so the listed rows
    // are a truncated slice while /health and /recommend read a wider window.
    const cfg = config(dir);
    for (let i = 0; i < 30; i++) {
      await handleCapture(
        { kind: 'prompt', sourceTool: 'claude-code', text: `key ${String(i)} ${SECRET}` },
        cfg,
      );
    }

    const gateway = resolveDataGateway(cfg);
    try {
      const footer = (surface: string): string => {
        const line = strip(surface)
          .split('\n')
          .find((l) => l.includes('open findings'));
        if (line === undefined) throw new Error('no status bar on surface');
        return line;
      };

      const findings = strip(await runQuery('findings', gateway));
      // The page is capped at 25 rows, but the footer reports the whole store.
      expect(findings).toContain('Recent findings (25)');
      const findingsFooter = footer(findings);
      expect(findingsFooter).toContain('⚑ 30 open findings');

      // Same footer on /health and /recommend — derived from the summary, not the
      // page — so the count no longer drifts with each command's row limit.
      expect(footer(await runQuery('health', gateway))).toBe(findingsFooter);
      expect(footer(await runQuery('recommend', gateway))).toBe(findingsFooter);
    } finally {
      await gateway.close();
    }
  });

  it('findings --severity narrows the listed rows and tailors the heading', async () => {
    const cfg = config(dir);
    // One critical (secret) and one medium (pii) finding through the real path.
    await handleCapture({ kind: 'prompt', sourceTool: 'claude-code', text: `key ${SECRET}` }, cfg);
    await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text: `contact ${PII_EMAIL}` },
      cfg,
    );

    const gateway = resolveDataGateway(cfg);
    try {
      // Filtering to 'critical' lists only the critical row and says so.
      const critical = strip(await runQuery('findings', gateway, { severity: 'critical' }));
      expect(critical).toContain('Recent critical findings (1)');
      expect(critical).toContain('secrets/aws-access-key');
      expect(critical).not.toContain('core-pii/email');

      // A level with no matches shows the filtered empty state, not every row.
      const high = strip(await runQuery('findings', gateway, { severity: 'high' }));
      expect(high).toContain('No high findings recorded yet');
      expect(high).not.toContain('secrets/aws-access-key');

      // No filter still lists every severity.
      const all = strip(await runQuery('findings', gateway));
      expect(all).toContain('secrets/aws-access-key');
      expect(all).toContain('core-pii/email');
    } finally {
      await gateway.close();
    }
  });
});
