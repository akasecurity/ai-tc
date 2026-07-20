import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { safeMaskedMatch } from '@akasecurity/plugin-sdk';
import type { TriageHit } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { buildTriageHit, scanHistory } from '../../src/history/scan.ts';

// In standalone mode the effective ruleset is the store's INSTALLED snapshot
// (seeded from bundledDetections() by resolveDataGateway), not ad-hoc packs
// registered into the engine — so the backfill detects with a REAL bundled rule
// (secrets/aws-access-key, critical). Composed at runtime so the repo's own
// secret scanning doesn't flag this file.
const BACKFILL_SECRET = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

const LEAK_TS = '2026-06-20T12:00:00.000Z';
const NOW = Date.parse('2026-06-24T00:00:00.000Z');

function config(dataDir: string, historicalAccess: 'full' | 'session-only'): PluginConfig {
  return {
    settings: { specVersion: 2, runMode: 'standalone', policy: 'redact', historicalAccess },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

// Build a transcripts root with one project/session containing a leaking prompt,
// a benign assistant reply, and a tool_result (which the scan must ignore).
function seedTranscripts(root: string, secret: string): void {
  const projectDir = join(root, '-Users-me-project');
  mkdirSync(projectDir, { recursive: true });
  const lines = [
    JSON.stringify({
      type: 'user',
      timestamp: LEAK_TS,
      message: { role: 'user', content: `here is a key ${secret}` },
    }),
    JSON.stringify({
      type: 'assistant',
      timestamp: '2026-06-20T12:00:05.000Z',
      message: { role: 'assistant', content: [{ type: 'text', text: 'nothing sensitive here' }] },
    }),
    JSON.stringify({
      type: 'user',
      timestamp: '2026-06-20T12:00:10.000Z',
      message: { role: 'user', content: [{ type: 'tool_result', content: `ignored ${secret}` }] },
    }),
  ];
  writeFileSync(join(projectDir, 'session.jsonl'), lines.join('\n'));
}

describe('scanHistory', () => {
  let dir: string;
  let transcripts: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-scan-data-'));
    transcripts = mkdtempSync(join(tmpdir(), 'aka-scan-tx-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    rmSync(transcripts, { recursive: true, force: true });
  });

  it('records pre-install findings with the original timestamp and never the raw secret', async () => {
    const SECRET = BACKFILL_SECRET;
    seedTranscripts(transcripts, SECRET);

    const summary = await scanHistory(config(dir, 'full'), {
      dir: transcripts,
      windowDays: 30,
      now: NOW,
    });

    expect(summary.consented).toBe(true);
    expect(summary.scanned).toBe(2); // the prompt + the assistant reply; tool_result ignored
    expect(summary.findings).toBe(1);
    expect(summary.bySeverity.critical).toBe(1);

    // The finding landed in the same store the read surfaces query.
    const gateway = resolveDataGateway(config(dir, 'full'));
    try {
      const findings = await gateway.recentFindings({ limit: 25 });
      expect(findings).toHaveLength(1);
      expect(findings[0]?.ruleId).toBe('secrets/aws-access-key');
      // Carries the ORIGINAL transcript timestamp, not scan time.
      expect(findings[0]?.occurredAt).toBe(LEAK_TS);
      // The raw secret never reaches the store — only a masked match.
      expect(JSON.stringify(findings)).not.toContain(SECRET);
    } finally {
      await gateway.close();
    }
  });

  it('is idempotent — re-running records no duplicate findings', async () => {
    seedTranscripts(transcripts, BACKFILL_SECRET);
    const opts = { dir: transcripts, windowDays: 30, now: NOW };

    const first = await scanHistory(config(dir, 'full'), opts);
    expect(first.findings).toBe(1);
    expect(first.skipped).toBe(0);

    // Second run: the leaking prompt is already stored → skipped; nothing new.
    const second = await scanHistory(config(dir, 'full'), opts);
    expect(second.findings).toBe(0);
    expect(second.skipped).toBeGreaterThanOrEqual(1);

    // The store still holds exactly one finding, not two.
    const gateway = resolveDataGateway(config(dir, 'full'));
    try {
      expect(await gateway.recentFindings({ limit: 25 })).toHaveLength(1);
    } finally {
      await gateway.close();
    }
  });

  it('is a no-op without consent (session-only)', async () => {
    seedTranscripts(transcripts, BACKFILL_SECRET);
    const summary = await scanHistory(config(dir, 'session-only'), {
      dir: transcripts,
      windowDays: 30,
      now: NOW,
    });
    expect(summary).toMatchObject({ consented: false, scanned: 0, findings: 0 });

    const gateway = resolveDataGateway(config(dir, 'session-only'));
    try {
      expect(await gateway.recentFindings({ limit: 25 })).toHaveLength(0);
    } finally {
      await gateway.close();
    }
  });
});

describe('buildTriageHit', () => {
  it('slices the correct context window and carries safeMaskedMatch(rawMatch) as maskedMatch', () => {
    const text = `padding before the leak ${BACKFILL_SECRET} padding after the leak`;
    const start = text.indexOf(BACKFILL_SECRET);
    const end = start + BACKFILL_SECRET.length;
    const finding = {
      ruleId: 'secrets/aws-access-key',
      category: 'secret' as const,
      severity: 'critical' as const,
      rawMatch: BACKFILL_SECRET,
      span: { start, end },
      confidence: 0.9,
    };

    const hit = buildTriageHit(text, finding);

    expect(hit.context).toBe(
      text.slice(Math.max(0, start - 120), Math.min(text.length, end + 120)),
    );
    expect(hit.maskedMatch).toBe(safeMaskedMatch(BACKFILL_SECRET));
    expect(hit.rawMatch).toBe(BACKFILL_SECRET);
    // No source path was supplied, so filePath is absent — the finding derives
    // '(location unavailable)' downstream rather than an empty-string path.
    expect(hit.filePath).toBeUndefined();
  });

  it('carries the source transcript path when one is supplied, so a surfaced finding can be located and struck', () => {
    const path = '/Users/me/.claude/projects/-Users-me-project/session.jsonl';
    const text = `padding ${BACKFILL_SECRET} padding`;
    const start = text.indexOf(BACKFILL_SECRET);
    const finding = {
      ruleId: 'secrets/aws-access-key',
      category: 'secret' as const,
      severity: 'critical' as const,
      rawMatch: BACKFILL_SECRET,
      span: { start, end: start + BACKFILL_SECRET.length },
      confidence: 0.9,
    };

    const hit = buildTriageHit(text, finding, [], path);

    expect(hit.filePath).toBe(path);
  });

  it('never sets maskedMatch to the raw value, even for a single-char-local-part email', () => {
    const rawMatch = 'a@test.com';
    const finding = {
      ruleId: 'core-pii/email',
      category: 'pii' as const,
      severity: 'medium' as const,
      rawMatch,
      span: { start: 0, end: rawMatch.length },
      confidence: 0.9,
    };

    const hit = buildTriageHit(rawMatch, finding);

    expect(hit.maskedMatch).not.toBe(rawMatch);
  });

  it("redacts another finding's raw value inside the context window, keeping its own match legible", () => {
    const otherSecret = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
    const text = `${otherSecret} close by, then ${BACKFILL_SECRET} is the real leak`;
    const otherStart = text.indexOf(otherSecret);
    const start = text.indexOf(BACKFILL_SECRET);
    const finding = {
      ruleId: 'secrets/aws-access-key',
      category: 'secret' as const,
      severity: 'critical' as const,
      rawMatch: BACKFILL_SECRET,
      span: { start, end: start + BACKFILL_SECRET.length },
      confidence: 0.9,
    };
    const other = {
      rawMatch: otherSecret,
      span: { start: otherStart, end: otherStart + otherSecret.length },
    };

    const hit = buildTriageHit(text, finding, [other]);

    expect(hit.context).toContain(BACKFILL_SECRET);
    expect(hit.context).not.toContain(otherSecret);
  });
});

describe('scanHistory — onHit sink', () => {
  let dir: string;
  let transcripts: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-scan-onhit-data-'));
    transcripts = mkdtempSync(join(tmpdir(), 'aka-scan-onhit-tx-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    rmSync(transcripts, { recursive: true, force: true });
  });

  it('is called exactly once per finding, with context sliced from the correct message', async () => {
    const otherSecret = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
    seedTranscripts(transcripts, BACKFILL_SECRET);

    const otherProjectDir = join(transcripts, '-Users-me-other-project');
    mkdirSync(otherProjectDir, { recursive: true });
    writeFileSync(
      join(otherProjectDir, 'session.jsonl'),
      JSON.stringify({
        type: 'user',
        timestamp: '2026-06-21T12:00:00.000Z',
        message: { role: 'user', content: `here is another key ${otherSecret}` },
      }),
    );

    const hits: TriageHit[] = [];
    await scanHistory(
      config(dir, 'full'),
      { dir: transcripts, windowDays: 30, now: NOW },
      (hit) => {
        hits.push(hit);
      },
    );

    expect(hits).toHaveLength(2);
    for (const hit of hits) {
      expect(hit.context).toContain(hit.rawMatch);
    }
    const backfillHit = hits.find((h) => h.rawMatch === BACKFILL_SECRET);
    const otherHit = hits.find((h) => h.rawMatch === otherSecret);
    expect(backfillHit?.context).not.toContain(otherSecret);
    expect(otherHit?.context).not.toContain(BACKFILL_SECRET);
    // Each streamed hit carries the real transcript it was found in, so the
    // remediation redact path can locate and strike the leaked key in place.
    expect(backfillHit?.filePath).toBe(join(transcripts, '-Users-me-project', 'session.jsonl'));
    expect(otherHit?.filePath).toBe(join(transcripts, '-Users-me-other-project', 'session.jsonl'));
  });

  it('redacts a neighboring secret from context when two findings share one message', async () => {
    const otherSecret = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
    const projectDir = join(transcripts, '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(
      join(projectDir, 'session.jsonl'),
      JSON.stringify({
        type: 'user',
        timestamp: LEAK_TS,
        message: { role: 'user', content: `key one ${BACKFILL_SECRET} and key two ${otherSecret}` },
      }),
    );

    const hits: TriageHit[] = [];
    await scanHistory(
      config(dir, 'full'),
      { dir: transcripts, windowDays: 30, now: NOW },
      (hit) => {
        hits.push(hit);
      },
    );

    expect(hits).toHaveLength(2);
    const backfillHit = hits.find((h) => h.rawMatch === BACKFILL_SECRET);
    const otherHit = hits.find((h) => h.rawMatch === otherSecret);
    // Each hit's own match stays legible, but its neighbor's raw value never does.
    expect(backfillHit?.context).toContain(BACKFILL_SECRET);
    expect(backfillHit?.context).not.toContain(otherSecret);
    expect(otherHit?.context).toContain(otherSecret);
    expect(otherHit?.context).not.toContain(BACKFILL_SECRET);
  });

  it('keeps scanning the rest of the history when the onHit sink throws', async () => {
    seedTranscripts(transcripts, BACKFILL_SECRET);

    const summary = await scanHistory(
      config(dir, 'full'),
      { dir: transcripts, windowDays: 30, now: NOW },
      () => {
        throw new Error('sink exploded');
      },
    );

    // The throw is contained — the sweep still records the finding normally.
    expect(summary.findings).toBe(1);
    expect(summary.scanned).toBe(2);
  });
});
