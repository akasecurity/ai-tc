/**
 * Onboarding writer invoked by the `/aka:setup` wizard — the only command that
 * mutates settings.json and the policies store. The wizard (commands/setup.md)
 * collects the answers conversationally, then runs:
 *
 *   node scripts/onboard.js --policy <redact|warn> --historical <full|session-only> \
 *     --posture <json> --floor
 *
 * Each flag is optional and additive: omit one and its current value (or the
 * default) is kept, so a later wizard step is one more flag with no rewrite.
 * Validation lives in @akasecurity/schema (SimpleDetectionPolicy/HistoricalAccess);
 * persistence + the onboardedAt stamp live in the SDK's applyOnboarding. Pure
 * adapter glue.
 *
 * `--posture <json>` writes the wizard's per-category model calibration
 * (validated by ./onboard-posture.ts); `--floor` writes the severity-floor
 * fallback instead (`severityFloorPosture()`) when the backfill was too thin to
 * calibrate from. Both go straight to the policies store via applyCategoryPosture,
 * separate from the settings.json answers above. `--posture` overwrites existing
 * category rows (confirmed calibration) while `--floor` only fills gaps;
 * `--recalibrate` forces an overwrite on the floor write. `--floor` and
 * `--posture` are mutually exclusive.
 */
import { capWarnEraEnforcementOnce, openLocalDatabase } from '@akasecurity/persistence';
import {
  applyCategoryPosture,
  applyOnboarding,
  loadConfig,
  severityFloorPosture,
} from '@akasecurity/plugin-sdk';
import type { WorkspaceSettings } from '@akasecurity/schema';
import { HistoricalAccess, SimpleDetectionPolicy } from '@akasecurity/schema';

import { parsePosture } from './onboard-posture.ts';
import { renderCategoriesTuned } from './render.ts';

// Pull `--flag value` and `--flag=value` pairs out of argv. Unknown flags and
// positionals are ignored — the wizard only ever passes the ones it knows.
function parseFlags(argv: string[]): Map<string, string> {
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg?.startsWith('--')) continue;
    const eq = arg.indexOf('=');
    if (eq !== -1) {
      flags.set(arg.slice(2, eq), arg.slice(eq + 1));
    } else {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags.set(arg.slice(2), next);
        i++;
      }
    }
  }
  return flags;
}

function fail(message: string): never {
  process.stdout.write(`AKA setup failed: ${message}\n`);
  process.exit(1);
}

const flags = parseFlags(process.argv.slice(2));
// The `--home` override that points the wizard at a throwaway ~/.aka home; absent
// on every real run, so loadConfig falls back to the default home. parseFlags
// already captures it.
const home = flags.get('home');
const answers: Partial<WorkspaceSettings> = {};

const rawPolicy = flags.get('policy');
if (rawPolicy !== undefined) {
  const parsed = SimpleDetectionPolicy.safeParse(rawPolicy);
  if (!parsed.success) fail(`invalid --policy "${rawPolicy}" (expected redact or warn)`);
  else answers.policy = parsed.data;
}

const rawHistorical = flags.get('historical');
if (rawHistorical !== undefined) {
  const parsed = HistoricalAccess.safeParse(rawHistorical);
  if (!parsed.success)
    fail(`invalid --historical "${rawHistorical}" (expected full or session-only)`);
  else answers.historicalAccess = parsed.data;
}

const rawPosture = flags.get('posture');
const useFloor = process.argv.includes('--floor');
const recalibrate = process.argv.includes('--recalibrate');

// --floor (the severity-floor fallback) and --posture (a confirmed calibration)
// are two different writes for the same store — passing both is ambiguous, so
// reject it before touching anything.
if (useFloor && rawPosture !== undefined) fail('--floor and --posture are mutually exclusive');

if (Object.keys(answers).length === 0 && rawPosture === undefined && !useFloor) {
  fail('nothing to save — pass --policy, --historical, --posture and/or --floor');
}

if (Object.keys(answers).length > 0) {
  try {
    const settings = applyOnboarding(answers, home);
    process.stdout.write(
      `AKA configured: policy=${settings.policy}, ` +
        `historicalAccess=${settings.historicalAccess}. ` +
        `Settings saved to ~/.aka/settings/settings.json.\n`,
    );
    // Caps any existing block/redact category rows to warn once when this
    // store's chosen handling is 'warn'. Failure here does not fail the
    // settings write above.
    try {
      const dataDir = loadConfig(home).dataDir;
      const db = openLocalDatabase(dataDir);
      try {
        const { capped } = capWarnEraEnforcementOnce(db, settings.policy, dataDir);
        if (capped > 0) {
          process.stdout.write(
            `AKA: kept ${String(capped)} existing block/redact categories at warn ` +
              `(the global "warn only" handling was retired). Confirm per-category ` +
              `enforcement in this setup.\n`,
          );
        }
      } finally {
        db.close();
      }
    } catch {
      // Best-effort: see comment above.
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : 'could not write settings.json');
  }
}

// The wizard's per-category posture (its model calibration, or the
// severity-floor fallback on a too-thin backfill) — written straight to the
// policies store, separate from the settings.json answers above.
if (rawPosture !== undefined || useFloor) {
  try {
    let posture;
    if (useFloor) posture = severityFloorPosture();
    else if (rawPosture !== undefined) posture = parsePosture(rawPosture);
    else fail('--posture requires a JSON value');
    // --posture is a user-confirmed calibration, so it overwrites any existing
    // category rows; --floor is the fallback and only fills gaps (never
    // downgrades a calibrated posture) unless --recalibrate forces an overwrite.
    const mode = rawPosture !== undefined || recalibrate ? 'overwrite' : 'fill-gaps';
    const db = openLocalDatabase(loadConfig(home).dataDir);
    try {
      applyCategoryPosture(posture, db.policies, mode);
      // The applying confirmation — the "tuned" segment reports the
      // categories the applied posture covers (the 8-pack matrix, or the
      // severity-floor fallback), never a literal.
      const categoryCount = Object.keys(posture).length;
      process.stdout.write(
        renderCategoriesTuned(categoryCount) + (useFloor ? ' (severity floor)' : '') + '\n',
      );
    } finally {
      db.close();
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : 'could not save per-category posture');
  }
}

// Explicit success exit, matching the other adapter entry scripts (query.js,
// the hooks) which hard-exit so node:sqlite handles can't keep the process
// alive. Reaching here means the write above succeeded — every failure path
// goes through fail() → exit(1).
process.exit(0);
