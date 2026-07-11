// Historical backfill: when the user granted "full" review at onboarding, sweep
// their prior Claude Code transcripts for secrets that leaked BEFORE AKA was
// installed (the live hooks cover everything after). Format-agnostic — the
// Claude Code transcript shape lives in ./transcripts; here we just feed each
// message through the same SDK detect→mask→record path the hooks use, so a
// backfilled finding is indistinguishable from a live one.
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { contentHashOf, createPluginRuntime } from '@akasecurity/plugin-sdk';

import { type HistoryWalkOptions, iterateHistory } from './transcripts.ts';

export interface ScanSummary {
  // false when historicalAccess !== 'full' — the scan is a no-op without consent.
  consented: boolean;
  scanned: number; // messages examined this run
  skipped: number; // messages already recorded (deduped) — not re-scanned
  findings: number; // findings recorded this run
  bySeverity: Record<string, number>;
  windowDays: number;
}

// Scan the host's transcript history and record any findings into the same
// local store the read surfaces query. Gated on consent; reuses ONE gateway +
// runtime for the whole sweep and persists only messages that actually leaked
// (`with-findings`) so a benign 30-day history doesn't flood the store.
//
// Idempotent: messages whose content is already recorded (a prior scan, or a
// live capture) are skipped, so `/aka:setup` can re-run the scan any number of
// times without ever duplicating findings. A cleared store re-scans in full.
export async function scanHistory(
  config: PluginConfig,
  opts: HistoryWalkOptions = {},
): Promise<ScanSummary> {
  const windowDays = opts.windowDays ?? 30;
  if (config.settings.historicalAccess !== 'full') {
    return { consented: false, scanned: 0, skipped: 0, findings: 0, bySeverity: {}, windowDays };
  }

  const gateway = resolveDataGateway(config);
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  const bySeverity: Record<string, number> = {};
  let scanned = 0;
  let skipped = 0;
  let findings = 0;
  try {
    // Hashes already in the store (and we add each one we record, so duplicate
    // messages within this same run dedup too).
    const seen = await gateway.knownContentHashes();
    for (const message of iterateHistory(opts)) {
      const hash = contentHashOf(message.text);
      if (seen.has(hash)) {
        skipped++;
        continue;
      }
      seen.add(hash);
      scanned++;
      const result = await runtime.capture(
        {
          kind: message.kind,
          sourceTool: 'claude-code',
          text: message.text,
          occurredAt: message.occurredAt,
        },
        // 'content-hash': a backfill re-run would otherwise re-record identical
        // messages under fresh event ids — the gateway uses the hash to drop
        // what it already recorded.
        { persist: 'with-findings', dedupe: 'content-hash' },
      );
      for (const finding of result.findings) {
        findings++;
        bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
      }
    }
  } finally {
    await runtime.close();
  }
  return { consented: true, scanned, skipped, findings, bySeverity, windowDays };
}
