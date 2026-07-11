import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { scanHistory } from './scan.ts';

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
