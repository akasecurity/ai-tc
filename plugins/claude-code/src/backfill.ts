/**
 * Historical backfill entry — invoked by the `/aka:setup` wizard right after
 * onboarding when the user chose "Grant full review" (historicalAccess: full).
 * It sweeps prior Claude Code transcripts (~/.claude/projects) for secrets that
 * leaked BEFORE AKA was installed and records them into the same local store the
 * read surfaces query.
 *
 * Two output contracts:
 *   - human (default): fully fail-open — any error prints a friendly note and
 *     exits 0 so onboarding never breaks.
 *   - --triage: stdout is a machine-read JSONL data channel and must fail loud.
 *     A truncated stream (mid-scan crash, EPIPE) is byte-indistinguishable from
 *     a complete one, so a completed stream ends in a sentinel line and any
 *     error writes a diagnostic to stderr plus a non-zero exit — never a silent
 *     exit 0 with a partial stream.
 */
import { fileURLToPath } from 'node:url';

import {
  type FingerprintKey,
  fingerprintValue,
  loadConfig,
  loadOrCreateFingerprintKey,
  type PluginConfig,
} from '@akasecurity/plugin-sdk';
import { TriageHit } from '@akasecurity/schema';

import { scanHistory, type ScanSummary } from './history/scan.ts';
import type { HistoryWalkOptions } from './history/transcripts.ts';
import { reconcileHistory } from './history/usage.ts';
import { fenced, indent } from './present.ts';

// The trailing sentinel that terminates a --triage stream. Its presence (and
// only its presence) tells the consumer the stream was not truncated:
//   complete            — the scan ran to completion; count hits precede this.
//   skipped:no-consent  — consent wasn't 'full'; an empty-but-intentional scan.
// A truncated stream has no sentinel, so it is never mistaken for a real
// zero-finding scan (which ends in status:"complete","count":0).
export type TriageStatus = 'complete' | 'skipped:no-consent';

export function triageSentinel(count: number, status: TriageStatus): string {
  return JSON.stringify({ done: true, count, status }) + '\n';
}

// Injected IO so the framing logic is unit-testable without a subprocess; the
// bottom of this file wires the real process streams. fail() marks a non-zero
// exit without writing to stdout — stdout stays the pure data channel.
export interface BackfillIo {
  stdout(chunk: string): void;
  stderr(chunk: string): void;
  fail(): void;
}

export interface BackfillDeps {
  triage: boolean;
  io: BackfillIo;
  loadConfig: () => PluginConfig;
  scanHistory: (
    config: PluginConfig,
    opts: HistoryWalkOptions,
    onHit?: (hit: TriageHit) => void,
  ) => Promise<ScanSummary>;
  reconcileHistory: (config: PluginConfig) => Promise<unknown>;
}

export async function runBackfill(deps: BackfillDeps): Promise<void> {
  const { triage, io } = deps;
  try {
    const cfg = deps.loadConfig();

    if (cfg.settings.historicalAccess !== 'full') {
      if (triage) {
        io.stdout(triageSentinel(0, 'skipped:no-consent'));
      } else {
        io.stdout('Historical scan skipped — full review was not granted.\n');
      }
      return;
    }

    // Resolve the fingerprint key once for the whole stream: a later
    // suppression writeback keys on (ruleId, valueFingerprint, keyVersion).
    // Mints on first use; a corrupt/unwritable key fails secure (fpKey stays
    // null) — hits then stream without a fingerprint, and a downstream
    // writeback step skips exactly those. Only under --triage.
    let fpKey: FingerprintKey | null = null;
    if (triage) {
      try {
        fpKey = loadOrCreateFingerprintKey(cfg.dataDir);
      } catch {
        fpKey = null;
      }
    }

    // Hits actually streamed, so the sentinel can carry N. Only incremented
    // after a successful write, so a mid-write EPIPE throws to the catch below
    // rather than being counted as emitted. Also doubles as the per-hit id
    // sequence (monotonic, 0-based).
    let count = 0;
    // scanHistory isolates each onHit call in its own try/catch (a misbehaving
    // sink must not abort the rest of the sweep), so a synchronous throw from
    // this closure — e.g. an EPIPE from io.stdout when the --triage consumer
    // closes its pipe mid-stream — never reaches this function's own catch.
    // Capture it here instead and rethrow after the scan settles, so a
    // truncated stream still fails loud rather than ending in a silently
    // undercounted 'complete' sentinel.
    let onHitError: unknown;
    const summary = await deps.scanHistory(
      cfg,
      {},
      triage
        ? (hit) => {
            if (onHitError !== undefined) return;
            try {
              const enriched: TriageHit = {
                ...hit,
                id: String(count),
                valueFingerprint: fpKey ? fingerprintValue(fpKey, hit.rawMatch) : undefined,
                keyVersion: fpKey?.version,
              };
              io.stdout(JSON.stringify(TriageHit.parse(enriched)) + '\n');
              count += 1;
            } catch (err) {
              onHitError = err;
            }
          }
        : undefined,
    );
    if (onHitError !== undefined) {
      throw onHitError instanceof Error
        ? onHitError
        : new Error(typeof onHitError === 'string' ? onHitError : 'triage stream write failed');
    }

    try {
      await deps.reconcileHistory(cfg);
    } catch {
      // Token backfill is best-effort; the live Stop-hook pass recovers it.
    }

    if (triage) {
      io.stdout(triageSentinel(count, 'complete'));
    } else {
      const heading = '✓ Historical scan complete';
      const scope = `Scanned ${String(summary.scanned)} messages from the last ${String(summary.windowDays)} days of Claude Code history.`;
      const result =
        summary.findings > 0
          ? `Found ${String(summary.findings)} pre-install finding${summary.findings === 1 ? '' : 's'} — review them with /findings.`
          : 'No new pre-install secrets found in your history.';
      io.stdout(`${fenced([heading, '', indent(scope), '', indent(result)].join('\n'))}\n`);
    }
  } catch (err) {
    if (triage) {
      io.stderr(`aka backfill --triage: history scan failed: ${String(err)}\n`);
      io.fail();
    } else {
      io.stdout(
        'AKA could not scan your history right now. It will still protect everything from here on.\n',
      );
    }
  }
}

// Guard so importing the exported helpers in tests never runs the CLI.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const triage = process.argv.includes('--triage');
  await runBackfill({
    triage,
    io: {
      stdout: (chunk) => process.stdout.write(chunk),
      stderr: (chunk) => process.stderr.write(chunk),
      fail: () => {
        process.exitCode = 1;
      },
    },
    loadConfig,
    scanHistory,
    reconcileHistory,
  });
  // process.exit() does not flush a buffered async stdout write on darwin, so a
  // large --triage stream's trailing sentinel could be dropped; drain first.
  if (process.stdout.writableLength > 0) {
    await new Promise<void>((resolve) => {
      process.stdout.write('', () => {
        resolve();
      });
    });
  }
  process.exit(process.exitCode ?? 0);
}
