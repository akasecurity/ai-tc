import { existsSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { cliRecordedBy } from '@akasecurity/local-ops';
import { DATA_FILE_MODE, openLocalDatabase } from '@akasecurity/persistence';
import {
  bundledDetections,
  dataDir,
  dbPath,
  ensureDataDirSync,
  settingsDir,
} from '@akasecurity/plugin-sdk';
import { defaultWorkspaceSettings } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';

// `aka init` — scaffold the local AKA home: owner-only ~/.aka, a default
// settings.json, and the SQLite store (openLocalDatabase creates the data dir,
// applies migrations, and seeds the default per-category policies). Idempotent:
// re-running re-applies no migration and re-seeds nothing.
export async function runInit(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: HOME_OPTION });
  const home = homeBase(values.home);

  ensureDataDirSync(home);
  const settings = settingsDir(home);
  ensureDataDirSync(settings);
  const settingsFile = join(settings, 'settings.json');
  // Don't clobber an existing settings.json — a re-run must preserve the user's
  // onboarding choices (runMode/policy/historicalAccess). Only write defaults on
  // first init.
  const settingsCreated = !existsSync(settingsFile);
  if (settingsCreated) {
    // Owner-only (0600) + atomic tmp+rename, matching how every other writer
    // treats files under ~/.aka — a crash mid-write must never leave a
    // truncated or group-readable settings.json.
    const tmp = `${settingsFile}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(defaultWorkspaceSettings(), null, 2)}\n`, {
      mode: DATA_FILE_MODE,
    });
    renameSync(tmp, settingsFile);
  }

  const db = openLocalDatabase(dataDir(home));
  let policyCount: number;
  let packCount: number;
  let updatesAvailable: number;
  try {
    // Record the binary's detection inventory (as the plugin's standalone
    // gateway does on open): refresh the available_packs mirror and install
    // packs that are missing. Existing installed packs are NEVER modified here
    // — updates are applied manually via `aka detections update`.
    db.installedPacks.recordInventory(bundledDetections(), cliRecordedBy());
    policyCount = (await db.policies.readPolicies()).length;
    packCount = (await db.installedPacks.counts()).packs;
    updatesAvailable = (await db.detections.listDetections({ filter: 'all' })).counts.updates;
  } finally {
    db.close();
  }

  process.stdout.write(
    `✓ Initialized AKA at ${home}\n` +
      `  settings: ${settingsFile}${settingsCreated ? '' : ' (kept existing)'}\n` +
      `  database: ${dbPath(home)}\n` +
      `  seeded ${String(policyCount)} default policies, ${String(packCount)} detection pack(s)\n` +
      (updatesAvailable > 0
        ? `  ⬆ ${String(updatesAvailable)} detection pack update(s) available — review with \`aka detections\`, apply with \`aka detections update --all\`\n`
        : ''),
  );
}
