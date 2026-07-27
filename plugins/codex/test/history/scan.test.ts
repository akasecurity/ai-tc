// Adapted from plugins/claude-code/src/history/scan.test.ts — same
// consent-gated backfill contract, exercised against a synthetic Codex
// rollout file instead of a Claude Code transcript.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { scanHistory } from '../../src/history/scan.ts';

// In standalone mode the effective ruleset is the store's INSTALLED snapshot
// (seeded from bundledDetections() by resolveDataGateway), not ad-hoc packs
// registered into the engine — so the backfill detects with a REAL bundled
// rule (secrets/aws-access-key, critical). Composed at runtime so the repo's
// own secret scanning doesn't flag this file.
const BACKFILL_SECRET = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

const LEAK_TS = '2026-06-20T12:00:00.000Z';
const NOW = Date.parse('2026-06-24T00:00:00.000Z');

function config(dataDir: string, historicalAccess: 'full' | 'session-only'): PluginConfig {
  return {
    settings: {
      specVersion: 3,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess,
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: { provider: 'openai' },
  };
}

// Build a rollout root with one session file containing a leaking prompt, a
// benign assistant reply, and a function_call (which the scan must ignore —
// only `message` response_items carry scannable prose).
function seedRollout(root: string, secret: string): void {
  const dayDir = join(root, '2026', '06', '20');
  mkdirSync(dayDir, { recursive: true });
  const lines = [
    JSON.stringify({
      timestamp: LEAK_TS,
      type: 'response_item',
      payload: {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: `here is a key ${secret}` }],
      },
    }),
    JSON.stringify({
      timestamp: '2026-06-20T12:00:05.000Z',
      type: 'response_item',
      payload: {
        type: 'message',
        role: 'assistant',
        content: [{ type: 'output_text', text: 'nothing sensitive here' }],
      },
    }),
    JSON.stringify({
      timestamp: '2026-06-20T12:00:10.000Z',
      type: 'response_item',
      payload: {
        type: 'function_call',
        name: 'shell',
        arguments: `{"command":"echo ${secret}"}`,
        call_id: 'c1',
      },
    }),
  ];
  writeFileSync(join(dayDir, 'rollout-session.jsonl'), lines.join('\n'));
}

describe('scanHistory', () => {
  let dir: string;
  let rollout: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-scan-data-'));
    rollout = mkdtempSync(join(tmpdir(), 'aka-scan-tx-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    rmSync(rollout, { recursive: true, force: true });
  });

  it('records pre-install findings with the original timestamp and never the raw secret', async () => {
    const SECRET = BACKFILL_SECRET;
    seedRollout(rollout, SECRET);

    const summary = await scanHistory(config(dir, 'full'), {
      dir: rollout,
      windowDays: 30,
      now: NOW,
    });

    expect(summary.consented).toBe(true);
    expect(summary.scanned).toBe(2); // the prompt + the assistant reply; function_call ignored
    expect(summary.findings).toBe(1);
    expect(summary.bySeverity.critical).toBe(1);

    const gateway = resolveDataGateway(config(dir, 'full'));
    try {
      const findings = await gateway.recentFindings({ limit: 25 });
      expect(findings).toHaveLength(1);
      expect(findings[0]?.ruleId).toBe('secrets/aws-access-key');
      expect(findings[0]?.occurredAt).toBe(LEAK_TS);
      expect(JSON.stringify(findings)).not.toContain(SECRET);
    } finally {
      await gateway.close();
    }
  });

  it('is idempotent — re-running records no duplicate findings', async () => {
    seedRollout(rollout, BACKFILL_SECRET);
    const opts = { dir: rollout, windowDays: 30, now: NOW };

    const first = await scanHistory(config(dir, 'full'), opts);
    expect(first.findings).toBe(1);
    expect(first.skipped).toBe(0);

    const second = await scanHistory(config(dir, 'full'), opts);
    expect(second.findings).toBe(0);
    expect(second.skipped).toBeGreaterThanOrEqual(1);

    const gateway = resolveDataGateway(config(dir, 'full'));
    try {
      expect(await gateway.recentFindings({ limit: 25 })).toHaveLength(1);
    } finally {
      await gateway.close();
    }
  });

  it('is a no-op without consent (session-only)', async () => {
    seedRollout(rollout, BACKFILL_SECRET);
    const summary = await scanHistory(config(dir, 'session-only'), {
      dir: rollout,
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
