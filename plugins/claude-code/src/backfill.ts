/**
 * Historical backfill entry — invoked by the `/aka:setup` wizard right after
 * onboarding when the user chose "Yes, scan" (historicalAccess: full).
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
import { dirname } from 'node:path';
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
import { type HistoryWalkOptions, transcriptsDir } from './history/transcripts.ts';
import { reconcileHistory } from './history/usage.ts';
import { parseHomeFlag } from './home-flag.ts';
import { fenced, indent } from './present.ts';

// The trailing sentinel that terminates a --triage stream. Its presence (and
// only its presence) tells the consumer the stream was not truncated:
//   complete            — the scan ran to completion over history that was examined;
//                         count hits precede this.
//   complete:no-history — the scan ran to completion but the history set was empty
//                         (no messages examined); still a completed, non-truncated
//                         scan, distinguished so the empty-state copy can say why.
//   skipped:no-consent  — consent wasn't 'full'; an empty-but-intentional scan.
// A truncated stream has no sentinel, so it is never mistaken for a real
// zero-finding scan (which ends in status:"complete","count":0).
// The set MUST stay in lockstep with the writeback.ts TRIAGE_STATUSES set.
export const TRIAGE_STATUSES = ['complete', 'complete:no-history', 'skipped:no-consent'] as const;
export type TriageStatus = (typeof TRIAGE_STATUSES)[number];

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
  // Walk options threaded into the scan. The self-contamination guard: `beforeMs`
  // drops any transcript message written at/after the backfill started (so a re-run
  // never re-ingests the wizard's own in-progress session), and `excludeSessionId`
  // skips AKA's OWN session transcript by id when the host exposes it. `dir`
  // overrides the transcript root; it is supplied only by the journey harness/tests
  // to scan a throwaway ~/.claude in isolation — no production call site passes it.
  // Injected (not read from the environment here) so runBackfill stays pure +
  // testable; the CLI wiring at the bottom of this file computes the real values.
  guard?: Pick<HistoryWalkOptions, 'excludeSessionId' | 'beforeMs' | 'dir'>;
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
      deps.guard ?? {},
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
              // Validate WITHOUT letting a ZodError carry the raw hit value: on a
              // shape mismatch the error message would echo rawMatch/context, and
              // it is rethrown to the outer catch which writes it to stderr. Emit
              // a raw-free error at the source instead. A raw-free io.stdout error
              // (e.g. EPIPE) still propagates verbatim for diagnostics.
              const validated = TriageHit.safeParse(enriched);
              if (!validated.success) {
                throw new Error('enriched triage hit failed TriageHit validation');
              }
              io.stdout(JSON.stringify(validated.data) + '\n');
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
      // A completed scan that touched zero messages is a no-history run (a fresh
      // machine with nothing to calibrate from), distinct from a scan that examined
      // history and surfaced/kept nothing. A message already recorded on a prior run
      // counts under skipped (dedup), not scanned, so a fully-deduped rescan of real
      // history is NOT no-history — both counters must be zero.
      const status: TriageStatus =
        summary.scanned === 0 && summary.skipped === 0 ? 'complete:no-history' : 'complete';
      io.stdout(triageSentinel(count, status));
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
      // The raw vector on this path — a ZodError over an enriched (raw-bearing)
      // hit — is neutralised at its source in the onHit sink above, so every error
      // reaching here (config/fs faults, an io.stdout EPIPE) is raw-free and its
      // message is safe (and useful) to surface on the machine channel.
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
  // Self-contamination guard values (see BackfillDeps.guard). `beforeMs` is this
  // run's start: every real pre-install message predates it, so it drops only
  // what is written at/after the scan begins — the wizard's own in-progress
  // session. `excludeSessionId` is best-effort: the host only exposes
  // CLAUDE_CODE_BRIDGE_SESSION_ID while a Remote Control connection is active, so
  // the id-skip is belt-and-suspenders on top of the always-on timestamp cutoff.
  const startedAt = Date.now();
  // eslint-disable-next-line n/no-process-env -- host session id for the self-contamination guard
  const sessionId = process.env.CLAUDE_CODE_BRIDGE_SESSION_ID;
  // The wizard's ~/.aka override; absent on every real run, so loadConfig and the
  // transcript scan fall back to the OS home. The transcript root sits under the OS
  // home, which is ~/.aka's parent — the inverse of defaultDataDir's
  // join(homedir(), '.aka') — so its dirname recovers the OS home to scan.
  const home = parseHomeFlag(process.argv.slice(2));
  const transcriptRoot = home !== undefined ? transcriptsDir(dirname(home)) : undefined;
  await runBackfill({
    triage,
    io: {
      stdout: (chunk) => process.stdout.write(chunk),
      stderr: (chunk) => process.stderr.write(chunk),
      fail: () => {
        process.exitCode = 1;
      },
    },
    loadConfig: () => loadConfig(home),
    scanHistory,
    reconcileHistory: (cfg) =>
      reconcileHistory(cfg, transcriptRoot !== undefined ? { dir: transcriptRoot } : {}),
    guard: {
      beforeMs: startedAt,
      ...(sessionId ? { excludeSessionId: sessionId } : {}),
      ...(transcriptRoot !== undefined ? { dir: transcriptRoot } : {}),
    },
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
