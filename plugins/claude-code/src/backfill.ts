/**
 * Historical backfill entry — invoked by the `/aka:setup` wizard right after
 * onboarding when the user chose "Grant full review" (historicalAccess: full).
 * It sweeps prior Claude Code transcripts (~/.claude/projects) for secrets that
 * leaked BEFORE AKA was installed and records them into the same local store the
 * read surfaces query:
 *
 *   node scripts/backfill.js
 *
 * The scan dedups against the local store's content hashes, so re-running on
 * every `/aka:setup` is idempotent and never duplicates findings. Fully
 * fail-open — any error prints a friendly note and exits 0 so onboarding
 * never breaks.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';

import { scanHistory } from './history/scan.ts';
import { reconcileHistory } from './history/usage.ts';
import { fenced, indent } from './present.ts';

try {
  const cfg = loadConfig();

  if (cfg.settings.historicalAccess !== 'full') {
    // Belt-and-suspenders: setup only runs this when consent is 'full'.
    process.stdout.write('Historical scan skipped — full review was not granted.\n');
    process.exit(0);
  }

  const summary = await scanHistory(cfg);

  // Token-usage backfill: sweep the same
  // transcript window and reconcile token usage into idempotent `llm_call` rows.
  // Independent of the secret scan and fully fail-open — a reconcile error must
  // never break onboarding, so a failure is swallowed and only the scan summary
  // is reported.
  try {
    await reconcileHistory(cfg);
  } catch {
    // Token backfill is best-effort; the live Stop-hook pass recovers it.
  }

  const heading = '✓ Historical scan complete';
  const scope = `Scanned ${String(summary.scanned)} messages from the last ${String(summary.windowDays)} days of Claude Code history.`;
  const result =
    summary.findings > 0
      ? `Found ${String(summary.findings)} pre-install finding${summary.findings === 1 ? '' : 's'} — review them with /findings.`
      : 'No new pre-install secrets found in your history.';

  process.stdout.write(`${fenced([heading, '', indent(scope), '', indent(result)].join('\n'))}\n`);
} catch {
  process.stdout.write(
    'AKA could not scan your history right now. It will still protect everything from here on.\n',
  );
}

process.exit(0);
