import { randomUUID } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { handleCapture, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { FindingView, HealthSummary, PluginConfig } from '@akasecurity/plugin-sdk';
import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId, DetectionCategory, DetectionException } from '@akasecurity/schema';
import { SetupHandoffOffer } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { readRegisteredCommands } from '../src/command-registry.ts';
import { NAME, ONE_LINER, TAGLINE } from '../src/identity.ts';
import { buildIntroCard, buildVerifiedIntroCard, type Manifest } from '../src/intro-card.ts';
import { paint } from '../src/present.ts';
import type { NpmRunner } from '../src/provenance.ts';
import { EXPECTED_REPOSITORY, EXPECTED_WORKFLOW_PATH } from '../src/provenance.ts';
import {
  buildHandoffOffer,
  buildHealthReport,
  buildRecommendations,
  healthScore,
  RE_TUNE_HINT,
  renderAdjustConfirm,
  renderApplied,
  renderAudit,
  renderCategoriesTuned,
  renderExceptions,
  renderFindings,
  renderFirstRun,
  renderHealth,
  renderPosture,
  renderPostureGrid,
  renderRecommend,
  renderRecommendedPosture,
  renderStartLight,
  renderStatusLine,
  runQuery,
  topFindings,
} from '../src/render.ts';

// The real shipped plugin manifest — the same plugin.json the intro adapter
// reads at runtime. Read here so the provenance assertions track the actual
// installed version, not a literal that silently rots on a version bump.
const PLUGIN_MANIFEST = JSON.parse(
  readFileSync(fileURLToPath(new URL('../.claude-plugin/plugin.json', import.meta.url)), 'utf8'),
) as Manifest;

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
    expect(out).toContain('redacted');
    expect(out).toContain('claude-code/prompt');
  });

  it('audit: action column shows past-tense labels, never the raw DB action', () => {
    const out = strip(
      renderAudit([finding({ actionTaken: 'log' }), finding({ actionTaken: 'redact' })]),
    );
    expect(out).toContain('monitored');
    expect(out).toContain('redacted');
    expect(out).not.toMatch(/\blog\b/);
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

  it('identity: exports the canonical name, tagline, and one-liner', () => {
    expect(NAME).toBe('AKA Security');
    expect(TAGLINE).toBe('We secure agent harnesses at the source.');
    expect(ONE_LINER).toBe(
      'I watch out for Claude as it codes — catching secrets and customer data before they slip out.',
    );
  });

  it('setup intro: the merged card builds from the real manifest, sourced from identity.ts', () => {
    // Exercises the shipped intro adapter (manifest → card) end to end: the
    // identity name can only appear if intro-card.ts sources it from the shared
    // identity constant, and the provenance version comes from the real plugin
    // manifest — so a stale local copy or a version drift fails here.
    const out = strip(buildIntroCard(PLUGIN_MANIFEST, /* verified */ false));
    expect(out).toContain(NAME);
    // The "what I do" body, merged into the same card — no duplicated one-liner.
    expect(out).toContain("I'm a security harness for Claude.");
    expect(out).toContain(
      'While it codes, I keep the sensitive information — secrets, keys, regulated data — safely on your machine.',
    );
    expect(out).toContain(
      "Most of it I handle quietly; I only notify you when it's worth your call.",
    );
    // Provenance line: the real installed version + canonical repo, no 'verified' badge
    // when the caller passes verified: false.
    expect(out).toContain(`v${PLUGIN_MANIFEST.version ?? ''} · github.com/akasecurity/ai-tc`);
    expect(out).not.toContain('verified');
    // The tagline, the one-liner and the handoff line are gone — the scan-offer
    // question carries the handoff instead — and the old copy never leaks back in.
    expect(out).not.toContain(TAGLINE);
    expect(out).not.toContain(ONE_LINER);
    expect(out).not.toContain("let's calibrate your notifications");
    expect(out).not.toContain('Agent Harness Security for Claude Code.');
    expect(out).not.toContain('two quick questions');
    // No internal narration (design-doc / decision citations) leaks into the copy.
    expect(out).not.toMatch(/Decision|design doc|ADR/i);
    // The whole card, built from the real manifest version/repo, so a layout
    // regression is caught here rather than only by the individual toContains
    // above (a literal snapshot can't be frozen since the version is real data).
    expect(out).toBe(
      [
        `● ${NAME}  ·  v${PLUGIN_MANIFEST.version ?? ''} · github.com/akasecurity/ai-tc`,
        '',
        "  I'm a security harness for Claude.",
        '',
        '  While it codes, I keep the sensitive information — secrets, keys, regulated data — safely on your machine.',
        "  Most of it I handle quietly; I only notify you when it's worth your call.",
      ].join('\n'),
    );
  });

  it('setup intro: the adapter appends the verified badge when the caller confirms provenance', () => {
    const out = strip(buildIntroCard(PLUGIN_MANIFEST, /* verified */ true));
    expect(out).toContain(
      `v${PLUGIN_MANIFEST.version ?? ''} · github.com/akasecurity/ai-tc · verified`,
    );
  });

  it('setup intro: the adapter fails open with blank facts when the manifest is unreadable', () => {
    // Empty manifest — the fallback intro.ts uses when plugin.json can't be read.
    const out = strip(buildIntroCard({}));
    // Still a card: the identity name and "what I do" body render even with no
    // manifest facts.
    expect(out).toContain(NAME);
    expect(out).toContain("I'm a security harness for Claude.");
    expect(out).not.toContain('verified');
  });

  // The card-render surface leg: drives the composed
  // buildVerifiedIntroCard(manifest, runNpm) render path across five
  // provenance fixtures, each built from npm's REAL
  // `npm audit signatures --json --include-attestations` report shape (a
  // base64 DSSE payload inside verified[].attestationBundles[]) — the same
  // builder shape as test/provenance.test.ts's buildReport fixture.
  describe('buildVerifiedIntroCard: card-render surface over five provenance fixtures', () => {
    const PACKAGE_NAME = '@akasecurity/ai-tc-claude-code';
    const VERSION = PLUGIN_MANIFEST.version ?? '';
    const SUBJECT_PURL = `pkg:npm/%40akasecurity/ai-tc-claude-code@${VERSION}`;

    const encodePayload = (statement: unknown): string =>
      Buffer.from(JSON.stringify(statement), 'utf8').toString('base64');

    // Mirrors test/provenance.test.ts's buildReport fixture — an
    // `npm audit signatures --json --include-attestations` report for a single
    // verified package. `workflow` seeds the SLSA provenance predicate's
    // buildDefinition; `subjectPurl` seeds the attestation subject binding.
    const buildReport = (opts: {
      workflow?: { repository: string; path: string };
      subjectPurl?: string;
    }): string => {
      const {
        workflow = { repository: EXPECTED_REPOSITORY, path: EXPECTED_WORKFLOW_PATH },
        subjectPurl = SUBJECT_PURL,
      } = opts;
      return JSON.stringify({
        invalid: [],
        missing: [],
        verified: [
          {
            name: PACKAGE_NAME,
            version: VERSION,
            registry: 'https://registry.npmjs.org/',
            attestationBundles: [
              {
                predicateType: 'https://slsa.dev/provenance/v1',
                bundle: {
                  dsseEnvelope: {
                    payload: encodePayload({
                      predicateType: 'https://slsa.dev/provenance/v1',
                      subject: [{ name: subjectPurl, digest: { sha512: 'deadbeef' } }],
                      predicate: {
                        buildDefinition: {
                          externalParameters: {
                            workflow: { ref: 'refs/heads/main', ...workflow },
                          },
                        },
                      },
                    }),
                  },
                },
              },
            ],
          },
        ],
      });
    };

    // No attestation present for the package at all — an empty verified set,
    // the shape npm reports for an unattested package.
    const noAttestationReport = (): string =>
      JSON.stringify({ invalid: [], missing: [], verified: [] });

    const VERIFIED_LINE = `v${VERSION} · github.com/akasecurity/ai-tc · verified`;
    const UNVERIFIED_LINE = `v${VERSION} · github.com/akasecurity/ai-tc`;

    it('(a) matching attestation binding the exact package@version + expected workflow -> badge', () => {
      const out = strip(
        buildVerifiedIntroCard(PLUGIN_MANIFEST, () => ({ ok: true, stdout: buildReport({}) })),
      );
      expect(out).toContain(VERIFIED_LINE);
    });

    it('(b) no attestation present for the package -> no badge', () => {
      const out = strip(
        buildVerifiedIntroCard(PLUGIN_MANIFEST, () => ({
          ok: true,
          stdout: noAttestationReport(),
        })),
      );
      expect(out).toContain(UNVERIFIED_LINE);
      expect(out).not.toContain('verified');
    });

    it('(c) attestation whose source repository/workflow does not match -> no badge', () => {
      const out = strip(
        buildVerifiedIntroCard(PLUGIN_MANIFEST, () => ({
          ok: true,
          stdout: buildReport({
            workflow: {
              repository: 'https://github.com/someone-else/unrelated',
              path: EXPECTED_WORKFLOW_PATH,
            },
          }),
        })),
      );
      expect(out).toContain(UNVERIFIED_LINE);
      expect(out).not.toContain('verified');
    });

    it('(d) the shell-out unavailable/offline -> no badge', () => {
      const out = strip(buildVerifiedIntroCard(PLUGIN_MANIFEST, () => ({ ok: false, stdout: '' })));
      expect(out).toContain(UNVERIFIED_LINE);
      expect(out).not.toContain('verified');
    });

    it('(e) a hung-equivalent child (an injected runner that throws) -> no badge, never throws', () => {
      // Stands in for the timed-out/killed real child, whose hard 2s-bound
      // termination is already proven at the oracle seam in provenance.test.ts.
      const throwingRunner = (): never => {
        throw new Error('spawn exploded');
      };
      expect(() => buildVerifiedIntroCard(PLUGIN_MANIFEST, throwingRunner)).not.toThrow();
      const out = strip(buildVerifiedIntroCard(PLUGIN_MANIFEST, throwingRunner));
      expect(out).toContain(UNVERIFIED_LINE);
      expect(out).not.toContain('verified');
    });

    it('setup always continues: all five fixtures render a card and never throw', () => {
      const unverifiedRunners: NpmRunner[] = [
        () => ({ ok: true, stdout: noAttestationReport() }),
        () => ({
          ok: true,
          stdout: buildReport({
            workflow: { repository: 'https://github.com/someone-else/unrelated', path: 'x.yml' },
          }),
        }),
        () => ({ ok: false, stdout: '' }),
        () => {
          throw new Error('spawn exploded');
        },
      ];
      for (const runNpm of unverifiedRunners) {
        expect(() => buildVerifiedIntroCard(PLUGIN_MANIFEST, runNpm)).not.toThrow();
        expect(strip(buildVerifiedIntroCard(PLUGIN_MANIFEST, runNpm))).toContain(UNVERIFIED_LINE);
      }
      const matchingRunner: NpmRunner = () => ({ ok: true, stdout: buildReport({}) });
      expect(() => buildVerifiedIntroCard(PLUGIN_MANIFEST, matchingRunner)).not.toThrow();
      expect(strip(buildVerifiedIntroCard(PLUGIN_MANIFEST, matchingRunner))).toContain(
        VERIFIED_LINE,
      );
    });
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

  describe('renderFirstRun — installed card', () => {
    // The command files the shipped plugin registers — the Try line must never
    // outrun this set, since a named command with no matching file would 404 when
    // the user types it. Read from disk (never a hardcoded copy) so a renamed or
    // removed command is caught here.
    const REGISTERED = new Set(
      readdirSync(fileURLToPath(new URL('../commands', import.meta.url)))
        .filter((f) => f.endsWith('.md'))
        .map((f) => f.replace(/\.md$/, '')),
    );

    const populated = (over: Partial<Parameters<typeof renderFirstRun>[0]> = {}): string =>
      strip(
        renderFirstRun(
          {
            calibration: 'scan',
            posture: renderPosture([
              { category: 'secret', action: 'redact' },
              { category: 'code_context', action: 'log' },
            ]),
            health: 72,
            findings: 142,
            recommendations: 6,
            worthALook: 2,
            topFindings: [
              finding({
                ruleId: 'secrets/aws-access-key',
                category: 'secret',
                severity: 'critical',
              }),
            ],
            ...over,
          },
          readRegisteredCommands(),
        ),
      );

    it('scan path: heading reads "You\'re all set — tuned to this machine."', () => {
      const out = populated({ calibration: 'scan' });
      expect(out).toContain("✓ You're all set — tuned to this machine.");
      // The floor-path heading never leaks onto the scan path.
      expect(out).not.toContain('safe defaults');
    });

    it('scan path: divider reads "First scan complete"', () => {
      const out = populated({ calibration: 'scan' });
      expect(out).toContain('First scan complete');
      expect(out).not.toContain('Safe defaults in place');
    });

    it('floor path: heading reads the cause-neutral no-scan fallback copy', () => {
      const out = populated({ calibration: 'floor' });
      expect(out).toContain(
        "✓ You're all set — I've started you on safe defaults. Rerun /aka:setup anytime to calibrate from Claude's activity.",
      );
      // The scan-path heading never leaks onto the floor path.
      expect(out).not.toContain('tuned to this machine');
    });

    it('floor path: divider reads "Safe defaults in place" (no scan ran)', () => {
      const out = populated({ calibration: 'floor' });
      expect(out).toContain('Safe defaults in place');
      expect(out).not.toContain('First scan complete');
    });

    it('stats line templates the real health · detections · recommendations, never a fixed literal', () => {
      const out = populated();
      expect(out).toContain('Health 72/100');
      expect(out).toContain('142 detections');
      expect(out).toContain('6 recommendations');
      // A different set of real values flows straight through — proof it is
      // templated over the store, not a baked-in literal.
      const other = populated({ health: 91, findings: 3, recommendations: 1 });
      expect(other).toContain('Health 91/100');
      expect(other).toContain('3 detections');
      expect(other).toContain('1 recommendations');
      // The fixed sample numbers never appear.
      expect(out).not.toContain('82/100');
      expect(out).not.toContain('40 findings');
    });

    it('scan path: a warm summary line rides above the stat row, over the real counts', () => {
      const out = populated({ findings: 142, worthALook: 2, calibration: 'scan' });
      expect(out).toContain(
        "I've gone over 142 detections from Claude's recent work — 2 worth your attention.",
      );
      // A different set of real values flows straight through.
      const other = populated({ findings: 9, worthALook: 4, calibration: 'scan' });
      expect(other).toContain(
        "I've gone over 9 detections from Claude's recent work — 4 worth your attention.",
      );
    });

    it('floor path: no warm summary line — the floor path never scanned anything', () => {
      const out = populated({ calibration: 'floor' });
      expect(out).not.toContain("I've gone over");
      // The stat row still renders over the real store counts.
      expect(out).toContain('Health 72/100');
      expect(out).toContain('142 detections');
      expect(out).toContain('6 recommendations');
    });

    it('shows the posture line the user chose', () => {
      const out = populated();
      expect(out).toContain('Posture');
      expect(out).toContain('secret');
      expect(out).toContain('redact');
      // 'log' (ActionTaken) surfaces to the user as 'monitor'.
      expect(out).toContain('monitor');
    });

    it("renders the '2 worth a look' handoff with the real surfaced count and the Open dashboard / Not now framing", () => {
      const out = populated({ worthALook: 2 });
      expect(out).toContain('2 worth a look — want to see them in the browser?');
      expect(out).toContain('Open dashboard');
      expect(out).toContain('Not now');
      // The count is the surfaced value, echoed — a different count flows through.
      expect(populated({ worthALook: 5 })).toContain('5 worth a look');
    });

    it('the Try line names only commands the shipped plugin registers, in invokable /aka: form', () => {
      const out = populated();
      const tryLine = out.split('\n').find((l) => l.includes('Try:'));
      expect(tryLine).toBeDefined();
      const named = tryLine?.match(/\/aka:[a-z]+/g) ?? [];
      // The line actually names commands (guards against an empty match passing).
      expect(named.length).toBeGreaterThan(0);
      for (const cmd of named) {
        const base = /^\/aka:([a-z]+)$/.exec(cmd)?.[1] ?? '';
        expect(REGISTERED.has(base)).toBe(true);
      }
      // The not-yet-shipped rename targets do not exist yet — the Try line must not print them.
      expect(out).not.toContain('/aka:secretscan');
      expect(out).not.toContain('/aka:codescan');
    });

    it('clean scan hides the Top findings section', () => {
      const out = populated({ topFindings: [], worthALook: 0 });
      expect(out).not.toContain('Top findings');
    });

    it('nothing surfaced — stats degrade to an honest empty-state, no fabricated count, card stays tidy', () => {
      // No scan surfaced anything: no worthALook, an empty store (0 findings /
      // recommendations), a clean scan (no top findings). The card degrades
      // honestly — the numeric stats triple becomes explicit empty-state copy
      // rather than a bare '0 detections · 0 recommendations' scan tally, and the
      // dashboard handoff is withheld (never a fabricated '0 worth a look').
      const out = strip(
        renderFirstRun(
          {
            calibration: 'scan',
            posture: renderPosture([{ category: 'secret', action: 'redact' }]),
            health: 40,
            findings: 0,
            recommendations: 0,
            topFindings: [],
            // worthALook intentionally omitted — nothing surfaced.
          },
          readRegisteredCommands(),
        ),
      );

      // No fabricated dashboard handoff, no bare numeric scan tally, and no
      // fabricated warm-summary claim of a review over zero detections.
      expect(out).not.toContain('worth a look');
      expect(out).not.toContain('0 detections');
      expect(out).not.toContain('0 recommendations');
      expect(out).not.toContain("I've gone over");
      // Instead, an explicit honest empty-state line.
      expect(out).toContain("you're starting clean");
      // The card still reads as a tidy success state: scan-path heading + posture.
      expect(out).toContain("You're all set — tuned to this machine.");
      expect(out).toContain('Posture');
      expect(out).toContain('secret');
      expect(out).toContain('redact');
    });

    it('lists the top findings table when the scan caught something', () => {
      const out = populated({
        topFindings: [
          finding({ ruleId: 'secrets/aws-access-key', category: 'secret', severity: 'critical' }),
          finding({ ruleId: 'pii/email', category: 'pii', severity: 'low' }),
        ],
      });
      expect(out).toContain('Top findings (2)');
      expect(out).toContain('secrets/aws-access-key');
      expect(out).toContain('pii/email');
      // The masked match shows; the raw secret never does (finding() masks it).
      expect(out).toContain('AKIA…MPLE');
    });
  });

  it('buildHandoffOffer: live-key branch — chain entry composed with the dashboard handoff', () => {
    // 5 surfaced important findings, 3 of them live-key secrets.
    const offer = buildHandoffOffer(5, 3);
    expect(SetupHandoffOffer.safeParse(offer).success).toBe(true);
    // Both counts are whatever the caller derived from the store — echoed, not invented.
    expect(offer.worthALook).toBe(5);
    expect(offer.liveKeys).toBe(3);
    // A surfaced live-key count composes the chain-entry option AHEAD of — never
    // in place of — the dashboard handoff.
    expect(offer.options).toEqual([
      { id: 'enter-remediation', label: 'Review leaked keys' },
      { id: 'open-dashboard', label: 'Open dashboard' },
      { id: 'not-now', label: 'Not now' },
    ]);
  });

  it('buildHandoffOffer: important-but-no-secrets — surfaced findings without live keys offer no remediation', () => {
    // 3 surfaced important findings, none of them live-key secrets: the gate is
    // the live-key count, NOT the all-category surfaced count, so no chain entry.
    const offer = buildHandoffOffer(3, 0);
    expect(SetupHandoffOffer.safeParse(offer).success).toBe(true);
    expect(offer.worthALook).toBe(3);
    // No live keys → no remediation offered, just the dashboard handoff.
    expect(offer.options).toEqual([
      { id: 'open-dashboard', label: 'Open dashboard' },
      { id: 'not-now', label: 'Not now' },
    ]);
  });

  it('buildHandoffOffer: honest zero — a clean store carries a real 0, plain dashboard handoff only', () => {
    const offer = buildHandoffOffer(0, 0);
    expect(SetupHandoffOffer.safeParse(offer).success).toBe(true);
    expect(offer.worthALook).toBe(0);
    // Nothing surfaced → no remediation offered, just the dashboard handoff.
    expect(offer.options).toEqual([
      { id: 'open-dashboard', label: 'Open dashboard' },
      { id: 'not-now', label: 'Not now' },
    ]);
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

describe('renderPosture', () => {
  it('lists each category with its action, aligned', () => {
    const out = renderPosture([
      { category: 'secret', action: 'warn' },
      { category: 'code_context', action: 'log' },
    ]);
    expect(out).toContain('secret');
    expect(out).toContain('warn');
    expect(out).toContain('code_context');
    // 'log' (ActionTaken) surfaces to the user as 'monitor'
    expect(out).toContain('monitor');
    expect(out).not.toMatch(/\blog\b/);
  });

  it('orders rows canonically regardless of input order', () => {
    // Rows arrive in whatever order the store returned them; the card must
    // render in the schema's canonical category order so it stays stable.
    const out = renderPosture([
      { category: 'code_context', action: 'monitor' },
      { category: 'secret', action: 'warn' },
      { category: 'pii', action: 'warn' },
      { category: 'financial', action: 'monitor' },
    ]);
    const order = out.split('\n').map((line) => line.trim().split(/\s+/)[0]);
    expect(order).toEqual(['pii', 'financial', 'secret', 'code_context']);
  });
});

describe('renderRecommendedPosture — condensed recommended view', () => {
  it('shows each pack with its recommended level, compact and in canonical order', () => {
    const out = renderRecommendedPosture(severityFloorPosture());
    // One compact row per pack — the recommended level, not the full 8×4 grid of
    // every level (that is the start-light branch's table).
    const packs = out
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => line.trim().split(/\s+/)[0]);
    expect(packs).toEqual([
      'pii',
      'financial',
      'secret',
      'phi',
      'code_context',
      'code_flaw',
      'custom',
      'config',
    ]);
    // The recommendation: sensitive packs surface (warn); observe-only packs
    // monitor. Palette vocabulary only — no DB 'log' leaks through.
    expect(out).not.toMatch(/\blog\b/);
    expect(out).not.toMatch(/\bblock\b/);
    // The whole block, so a layout/copy regression is caught as a snapshot diff.
    expect(out).toMatchInlineSnapshot(`
      "  pii           warn
        financial     warn
        secret        warn
        phi           warn
        code_context  monitor
        code_flaw     warn
        custom        warn
        config        monitor"
    `);
  });

  it('renders whatever recommended map it is handed (no hardcoded levels)', () => {
    const out = renderRecommendedPosture({
      secret: 'block',
      pii: 'redact',
      financial: 'warn',
      phi: 'warn',
      code_context: 'monitor',
      code_flaw: 'warn',
      custom: 'warn',
      config: 'monitor',
    });
    expect(out).toContain('secret');
    expect(out).toContain('block');
    expect(out).toContain('redact');
  });
});

describe('renderPostureGrid — full 8×4 posture matrix', () => {
  // The eight packs, in the schema's canonical category order — the same order
  // renderPosture/renderRecommendedPosture use, and the order the grid must lock.
  const CANONICAL = [
    'pii',
    'financial',
    'secret',
    'phi',
    'code_context',
    'code_flaw',
    'custom',
    'config',
  ];

  it('lays every pack against all four levels, marks the chosen one, in canonical order', () => {
    const out = renderPostureGrid(severityFloorPosture());

    // Every pack renders, once, in canonical category order (header and rule
    // lines excluded by keeping only rows whose first token is a known pack).
    const packs = out
      .split('\n')
      .map((line) => line.trim().split(/\s+/)[0])
      .filter((tok): tok is string => tok !== undefined && CANONICAL.includes(tok));
    expect(packs).toEqual(CANONICAL);

    // All four level labels head the grid — palette vocabulary only, never the
    // DB action forms 'log'/'allow' (the full grid lays out every level per pack,
    // unlike renderRecommendedPosture's condensed one-level glance).
    expect(out).toContain('MONITOR');
    expect(out).toContain('WARN');
    expect(out).toContain('REDACT');
    expect(out).toContain('BLOCK');
    expect(out).not.toMatch(/\blog\b/);
    expect(out).not.toMatch(/\ballow\b/);

    // The whole 8×4 grid, so a layout regression is caught as a snapshot diff.
    // Feeding the default posture map, the mark sits in monitor for the observe-only
    // packs (code_context, config) and in warn for the rest.
    expect(out).toMatchInlineSnapshot(`
      "  CATEGORY       MONITOR   WARN   REDACT   BLOCK
        ────────────   ───────   ────   ──────   ─────
        pii                      ●                    
        financial                ●                    
        secret                   ●                    
        phi                      ●                    
        code_context   ●                              
        code_flaw                ●                    
        custom                   ●                    
        config         ●                              "
    `);
  });
});

describe('renderStartLight — 0.3b start-light card', () => {
  // The eight packs in canonical category order — the order the embedded grid and
  // the per-pack rationale block must both follow.
  const CANONICAL = [
    'pii',
    'financial',
    'secret',
    'phi',
    'code_context',
    'code_flaw',
    'custom',
    'config',
  ];
  const posture = severityFloorPosture();

  it('leads with the start-light heading', () => {
    expect(renderStartLight(posture)).toContain('Starting light — your detection categories');
  });

  it('embeds the full 8×4 default posture grid, composed from the shared primitive', () => {
    // The card composes renderPostureGrid seeded with the default posture, so a grid
    // layout regression surfaces here too, not only in renderPostureGrid's own test.
    expect(renderStartLight(posture)).toContain(renderPostureGrid(posture));
  });

  it('carries a per-pack rationale line for every pack, never omitted or placeholdered', () => {
    const out = renderStartLight(posture);
    for (const pack of CANONICAL) {
      // A rationale line names the pack, its default level, then a non-empty reason.
      const line = out.split('\n').find((l) => l.trim().startsWith(`${pack} —`));
      expect(line, `rationale line for ${pack}`).toBeTruthy();
      const reason = (line ?? '').split(':').slice(1).join(':').trim();
      expect(reason.length, `rationale text for ${pack}`).toBeGreaterThan(0);
      expect(reason, `rationale for ${pack} is not a placeholder`).not.toMatch(
        /todo|tbd|placeholder|…|xxx/i,
      );
    }
  });

  it('closes with the re-tune hint, single-sourced from RE_TUNE_HINT', () => {
    // The exported constant is what setup.md and the applied-frame copy single-source.
    expect(RE_TUNE_HINT).toBe('Re-tune anytime with /aka:setup or the dashboard');
    expect(renderStartLight(posture)).toContain(RE_TUNE_HINT);
  });

  it('matches the whole-card snapshot so copy/layout regressions surface', () => {
    expect(renderStartLight(posture)).toMatchInlineSnapshot(`
      "● Starting light — your detection categories

        I don't have any of Claude's past work to learn from yet, so I'll start each detection category at a careful default.

        CATEGORY       MONITOR   WARN   REDACT   BLOCK
        ────────────   ───────   ────   ──────   ─────
        pii                      ●                    
        financial                ●                    
        secret                   ●                    
        phi                      ●                    
        code_context   ●                              
        code_flaw                ●                    
        custom                   ●                    
        config         ●                              

        pii — warn: personal data carries real obligations, so I surface it before it moves.
        financial — warn: card and account numbers are sensitive by default, so these come to you.
        secret — warn: keys and credentials are the costliest thing to lose, so I bring those straight to you.
        phi — warn: health information is regulated wherever it lands, so I flag it for your call.
        code_context — monitor: proprietary code context is common and mostly benign, so I watch quietly and keep the record.
        code_flaw — warn: an insecure pattern is worth a look before it ships, so I raise it.
        custom — warn: your own policy matches start surfaced so nothing you care about slips by unseen.
        config — monitor: config values are noisy, so I keep an eye on them without notifying you.

        Re-tune anytime with /aka:setup or the dashboard"
    `);
  });
});

describe('renderAdjustConfirm — 0.4b adjust-confirm table', () => {
  // The eight packs in canonical category order — the order the confirm table
  // rows must follow, recommended and yours side by side on each.
  const CANONICAL = [
    'pii',
    'financial',
    'secret',
    'phi',
    'code_context',
    'code_flaw',
    'custom',
    'config',
  ];
  const recommended = severityFloorPosture();
  // The user's chosen posture: the recommended base with two packs overridden
  // (secret warn→redact, config monitor→warn), the other six kept as recommended.
  const chosen: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {
    ...recommended,
    secret: 'redact',
    config: 'warn',
  };

  it("heads a three-column 'category │ recommended │ yours' table", () => {
    // Built from present.ts table(), which uppercases the column headers.
    const out = renderAdjustConfirm(recommended, chosen);
    expect(out).toContain('CATEGORY');
    expect(out).toContain('RECOMMENDED');
    expect(out).toContain('YOURS');
  });

  it('lays one row per pack in canonical order, recommended beside yours', () => {
    const out = renderAdjustConfirm(recommended, chosen);
    const order = out
      .split('\n')
      .map((l) => l.trim().split(/\s+/)[0])
      .filter((tok): tok is string => tok !== undefined && CANONICAL.includes(tok));
    expect(order).toEqual(CANONICAL);

    // Both columns are visible on every row: a changed pack shows a different
    // 'yours' value, an unchanged pack repeats the recommended level.
    const row = (pack: string): string[] =>
      (out.split('\n').find((l) => l.trim().startsWith(`${pack} `)) ?? '').trim().split(/\s+/);
    // secret: recommended warn, yours redact (changed).
    expect(row('secret')).toEqual(['secret', 'warn', 'redact']);
    // config: recommended monitor, yours warn (changed).
    expect(row('config')).toEqual(['config', 'monitor', 'warn']);
    // pii: unchanged — recommended and yours both warn, both columns present.
    expect(row('pii')).toEqual(['pii', 'warn', 'warn']);
  });

  // The adjust fork writes posture just like the confirm spine, so it must flag an
  // enforcement downgrade the same way — a pack hardened out of band can otherwise
  // be lowered here with nothing shown to the user.
  describe('downgrade guard against the stored posture', () => {
    it('appends the downgrade footer when a pick ranks below the stored action', () => {
      // The store holds 'secret' at block; the user picks redact.
      const out = renderAdjustConfirm(recommended, chosen, { secret: 'block' });
      expect(out).toContain('Heads up — this would lower 1 detection level (secret) below');
    });

    it('names every lowered detection category and pluralizes the count', () => {
      const out = renderAdjustConfirm(recommended, chosen, {
        secret: 'block',
        config: 'redact',
      });
      expect(out).toContain(
        'Heads up — this would lower 2 detection levels (secret, config) below',
      );
    });

    it('stays silent when every pick is the same or stronger than the stored action', () => {
      // secret: stored warn -> picked redact (stronger). config: stored log
      // ('monitor') -> picked warn (stronger).
      const out = renderAdjustConfirm(recommended, chosen, { secret: 'warn', config: 'log' });
      expect(out).not.toContain('WARNING');
    });

    it('has no baseline to compare against when current is omitted', () => {
      expect(renderAdjustConfirm(recommended, chosen)).not.toContain('WARNING');
    });
  });

  it('carries the adjust copy and the shared re-tune hint', () => {
    const out = renderAdjustConfirm(recommended, chosen);
    expect(out).toContain("I'll keep the rest as recommended");
    // The re-tune pointer to the deep-tuning surface is single-sourced.
    expect(out).toContain(RE_TUNE_HINT);
  });

  it('matches the whole-card snapshot so copy/layout regressions surface', () => {
    expect(renderAdjustConfirm(recommended, chosen)).toMatchInlineSnapshot(`
      "● Adjust — set the packs you want, keep the rest

        CATEGORY       RECOMMENDED   YOURS  
        ────────────   ───────────   ───────
        pii            warn          warn   
        financial      warn          warn   
        secret         warn          redact 
        phi            warn          warn   
        code_context   monitor       monitor
        code_flaw      warn          warn   
        custom         warn          warn   
        config         monitor       warn   

        I'll keep the rest as recommended.

        Re-tune anytime with /aka:setup or the dashboard"
    `);
  });
});

describe('renderApplied — applying confirmation', () => {
  // The read-command files the shipped plugin registers — the real registry the
  // Ready line must not outrun. A command it names with no matching file would
  // 404 when the user runs it, so the line is asserted against this set, never a
  // hardcoded copy.
  const REGISTERED = new Set(
    readdirSync(fileURLToPath(new URL('../commands', import.meta.url)))
      .filter((f) => f.endsWith('.md'))
      .map((f) => f.replace(/\.md$/, '')),
  );

  // The installed command registry, resolved the way the shipped caller does and
  // threaded into the pure renderer so the Ready line's curated set is validated
  // against the commands the plugin actually registers.
  const REGISTRY = readRegisteredCommands();

  it('templates the real dismissed count and confirms the tuned category count', () => {
    const out = renderApplied(8, 12, REGISTRY);
    expect(out).toContain('✓ Set all 8 detection categories');
    expect(out).toContain('set aside 12 routine results');
    // N is templated from the real count — a different value flows straight
    // through, never a baked-in literal.
    expect(renderApplied(8, 3, REGISTRY)).toContain('set aside 3 routine results');
    // Singular is grammatical when exactly one routine result was set aside.
    expect(renderApplied(8, 1, REGISTRY)).toContain('set aside 1 routine result');
    expect(renderApplied(8, 1, REGISTRY)).not.toContain('1 routine results');
    // The tuned count is threaded too, not hardcoded to 8.
    expect(renderApplied(5, 3, REGISTRY)).toContain('✓ Set all 5 detection categories');
  });

  it('renders an honest empty-state when nothing routine was set aside', () => {
    const out = renderApplied(8, 0, REGISTRY);
    expect(out).toContain('✓ Set all 8 detection categories');
    // No fabricated 'set aside 0 routine results' — honest copy instead.
    expect(out).not.toContain('set aside 0');
    expect(out).toContain('nothing routine to set aside');
  });

  it('the Ready line names only commands the plugin actually registers, in invokable /aka: form', () => {
    const ready = (renderApplied(8, 5, REGISTRY).split('Ready:')[1] ?? '').trim();
    const named = ready.match(/\/[a-z:]+/g) ?? [];
    // The line actually names commands (guards against an empty match passing).
    expect(named.length).toBeGreaterThan(0);
    for (const cmd of named) {
      // The plugin registers commands under its `aka` namespace, so the only
      // form that resolves when typed is `/aka:<command>` — a bare `/<command>`
      // would not invoke. Require the namespace, then check the base name is a
      // real registered command file (never a hardcoded copy).
      const match = /^\/aka:([a-z]+)$/.exec(cmd);
      expect(match).not.toBeNull();
      expect(REGISTERED.has(match?.[1] ?? '')).toBe(true);
    }
  });

  it('builds the Ready line through the registry mechanism — an unregistered curated command throws', () => {
    // The Ready line's curated set is validated against the registry, not
    // free-printed: a registry missing one of its curated commands fails loud
    // rather than rendering a call-to-action the user cannot invoke.
    const withoutHealth = REGISTRY.filter((c) => c !== '/aka:health');
    expect(() => renderApplied(8, 5, withoutHealth)).toThrow(/aka:health/);
  });

  it("reads '✓ Set all 8 detection categories' from the real 8-pack the posture writer wrote", () => {
    // onboard.ts feeds its confirmation the size of the posture it actually
    // wrote: renderCategoriesTuned(Object.keys(posture).length). Drive that with
    // the real recommended map so the '8' is the true pack count, not a
    // literal — this is the segment that composes into the applying-confirmation line.
    const packCount = Object.keys(severityFloorPosture()).length;
    expect(packCount).toBe(8);
    expect(renderCategoriesTuned(packCount)).toBe('✓ Set all 8 detection categories');
    // Same phrase renderApplied composes — single-sourced, so the two can't drift.
    expect(renderApplied(packCount, 5, REGISTRY)).toContain(renderCategoriesTuned(packCount));
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
      // decision renders as 'monitored' (the finding is still recorded and masked).
      expect(strip(await runQuery('audit', gateway))).toContain('monitored');
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
