// Historical backfill: when the user granted "full" review at onboarding, sweep
// their prior Codex CLI rollout files for secrets that leaked BEFORE AKA was
// installed (the live hooks cover everything after). Format-agnostic — the
// Codex rollout shape lives in ./transcripts; here we just feed each message
// through the same SDK detect→mask→record path the hooks use, so a backfilled
// finding is indistinguishable from a live one. Identical to
// plugins/claude-code/src/history/scan.ts except sourceTool.
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { contentHashOf, createPluginRuntime } from '@akasecurity/plugin-sdk';

import { type HistoryWalkOptions, iterateHistory } from './transcripts.ts';

export interface ScanSummary {
  consented: boolean;
  scanned: number;
  skipped: number;
  findings: number;
  bySeverity: Record<string, number>;
  windowDays: number;
}

// Scan the host's rollout history and record any findings into the same local
// store the read surfaces query. Gated on consent; reuses ONE gateway +
// runtime for the whole sweep and persists only messages that actually leaked
// (`with-findings`) so a benign 30-day history doesn't flood the store.
//
// Idempotent: messages whose content is already recorded (a prior scan, or a
// live capture) are skipped, so the setup skill can re-run the scan any number
// of times without ever duplicating findings. A cleared store re-scans in full.
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
          sourceTool: 'codex',
          text: message.text,
          occurredAt: message.occurredAt,
        },
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
