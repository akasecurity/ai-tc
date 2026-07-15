/**
 * Onboarding writer invoked by the `/aka:setup` wizard — the only command that
 * mutates settings.json. The wizard (commands/setup.md) collects the answers
 * conversationally, then runs:
 *
 *   node scripts/onboard.js --policy <redact|warn> --historical <full|session-only>
 *
 * Each flag is optional and additive: omit one and its current value (or the
 * default) is kept, so a later wizard step is one more flag with no rewrite.
 * Validation lives in @akasecurity/schema (SimpleDetectionPolicy/HistoricalAccess);
 * persistence + the onboardedAt stamp live in the SDK's applyOnboarding. Pure
 * adapter glue.
 */
import { capWarnEraEnforcementOnce, openLocalDatabase } from '@akasecurity/persistence';
import { applyCategoryPosture, applyOnboarding, loadConfig } from '@akasecurity/plugin-sdk';
import type { WorkspaceSettings } from '@akasecurity/schema';
import {
  FULL_ENFORCEMENT_POSTURE,
  HistoricalAccess,
  SimpleDetectionPolicy,
} from '@akasecurity/schema';

// Pull `--flag value` and `--flag=value` pairs out of argv. Unknown flags and
// positionals are ignored — the wizard only ever passes the two it knows.
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

if (Object.keys(answers).length === 0) {
  fail('nothing to save — pass --policy and/or --historical');
}

try {
  const settings = applyOnboarding(answers);
  process.stdout.write(
    `AKA configured: policy=${settings.policy}, ` +
      `historicalAccess=${settings.historicalAccess}. ` +
      `Settings saved to ~/.aka/settings/settings.json.\n`,
  );
  // Caps any existing block/redact category rows to warn once when this
  // store's chosen handling is 'warn'. Failure here does not fail the
  // settings write above.
  try {
    const dataDir = loadConfig().dataDir;
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
  // A --policy redact flag writes FULL_ENFORCEMENT_POSTURE as real
  // per-category policy rows. --policy warn requires no additional write.
  if (rawPolicy === 'redact') {
    try {
      const db = openLocalDatabase(loadConfig().dataDir);
      try {
        applyCategoryPosture(FULL_ENFORCEMENT_POSTURE, db.policies, 'overwrite');
      } finally {
        db.close();
      }
    } catch {
      // Best-effort: a failed write here leaves the existing posture in place.
    }
  }
} catch (err) {
  fail(err instanceof Error ? err.message : 'could not write settings.json');
}

// Explicit success exit, matching the other adapter entry scripts (query.js,
// the hooks) which hard-exit so node:sqlite handles can't keep the process
// alive. Reaching here means the write above succeeded — every failure path
// goes through fail() → exit(1).
process.exit(0);
