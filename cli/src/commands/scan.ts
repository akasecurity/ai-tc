import { parseArgs } from 'node:util';

import type { ScanPathResult } from '@akasecurity/local-ops';
import { scanPathIntoStore } from '@akasecurity/local-ops';
import { openLocalDatabase } from '@akasecurity/persistence';
import { dataDir, registerBundledPacks } from '@akasecurity/plugin-sdk';
import { Severity } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';

// `aka scan [path]` — run the bundled detection rules over a file or directory and
// record any findings into the local store. The raw match never lands on disk:
// findings store only the masked value, and the event keeps a REDACTED copy of
// the file. Default path is the current directory. The walk + record pipeline
// lives in @akasecurity/local-ops (shared with the web-ui's Scan page); the CLI
// evaluates the bundled packs via the engine's process-global registry.
//
// CI surface (both opt-in; the default text output and exit-0 behavior are
// unchanged):
//   --format json         machine-readable result on stdout (findings carry the
//                         masked match + span, never the raw secret)
//   --fail-on <severity>  exit 1 when any finding is at or above the given
//                         severity (critical|high|medium|low)

// Severity.options is ordered most→least severe; lower index = more severe.
function severityRank(s: Severity): number {
  return Severity.options.indexOf(s);
}

export function runScan(argv: string[]): void {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      ...HOME_OPTION,
      format: { type: 'string' },
      'fail-on': { type: 'string' },
    },
    allowPositionals: true,
  });
  const home = homeBase(values.home);
  const target = positionals[0] ?? '.';

  const format = values.format ?? 'text';
  if (format !== 'text' && format !== 'json') {
    process.stderr.write(`aka scan: invalid --format '${format}' (expected text or json)\n`);
    process.exitCode = 1;
    return;
  }
  let failOn: Severity | undefined;
  if (values['fail-on'] !== undefined) {
    const parsed = Severity.safeParse(values['fail-on']);
    if (!parsed.success) {
      process.stderr.write(
        `aka scan: invalid --fail-on '${values['fail-on']}' ` +
          `(expected ${Severity.options.join(', ')})\n`,
      );
      process.exitCode = 1;
      return;
    }
    failOn = parsed.data;
  }

  registerBundledPacks();
  const db = openLocalDatabase(dataDir(home));

  let result: ScanPathResult;
  try {
    // Evaluate the bundled packs via the process-global registry, but resolve each
    // finding's action from the installed snapshot's per-pack policy (ruleActions)
    // so at-rest labels match the plugin's per-pack enforcement; rules not in the
    // snapshot fall back to the per-category default.
    const { ruleActions } = db.installedPacks.installedRuleset();
    result = scanPathIntoStore(db, target, { ruleActions, sourceTool: 'cli' });
  } finally {
    db.close();
  }

  if (format === 'json') {
    const findings = result.files.flatMap((f) =>
      f.findings.map((d) => ({
        file: f.path,
        gitignored: f.gitignored,
        ruleId: d.ruleId,
        category: d.category,
        severity: d.severity,
        span: d.span,
        maskedMatch: d.maskedMatch,
        actionTaken: d.actionTaken,
        confidence: d.confidence,
      })),
    );
    process.stdout.write(
      `${JSON.stringify({ target, scanned: result.scanned, findings }, null, 2)}\n`,
    );
  } else {
    process.stdout.write(
      `Scanned ${String(result.scanned)} file(s) under ${target} · ${String(result.findings)} finding(s) recorded\n`,
    );
  }

  if (failOn !== undefined) {
    const threshold = severityRank(failOn);
    const hit = result.files.some((f) =>
      f.findings.some((d) => severityRank(d.severity) <= threshold),
    );
    if (hit) process.exitCode = 1;
  }
}
