import { existsSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as readline from 'node:readline/promises';
import { parseArgs } from 'node:util';

import {
  cliRecordedBy,
  findAgent,
  installedPluginVersions,
  pluginRef,
} from '@akasecurity/local-ops';
import { DATA_FILE_MODE, openLocalDatabase } from '@akasecurity/persistence';
import {
  bundledDetections,
  dataDir,
  dbPath,
  ensureDataDirSync,
  settingsDir,
} from '@akasecurity/plugin-sdk';
import { defaultWorkspaceSettings, PRODUCT_NAME, PRODUCT_TAGLINE } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import { runPlugins } from './plugins.ts';

// The init plugin-offer copy, built from the canonical product identity single-sourced
// in @akasecurity/schema so the CLI and plugin present the same name and tagline.
export const PLUGIN_OFFER_IDENTITY = `${PRODUCT_NAME} — ${PRODUCT_TAGLINE}`;

// `aka init` — scaffold the local AKA home: owner-only ~/.aka, a default
// settings.json, and the SQLite store (openLocalDatabase creates the data dir,
// applies migrations, and seeds the default per-category policies). Idempotent:
// re-running re-applies no migration and re-seeds nothing. Also checks for the
// Claude Code plugin — the default install path — and offers to add it via the
// marketplace when it's missing, so a CLI-first install ends up with both.
export async function runInit(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, yes: { type: 'boolean', short: 'y' } },
  });
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

  await offerPluginInstall(values.yes === true);
}

// The CLI alone only scans on demand (`aka scan`) — it doesn't see live agent
// traffic. The Claude Code plugin is what does, so a CLI-first install (no
// plugin yet) is offered the marketplace route here, mirroring the reverse
// offer /aka:setup makes for the CLI after a plugin-first install.
async function offerPluginInstall(autoYes: boolean): Promise<void> {
  const agent = findAgent('claude-code');
  const ref = agent ? pluginRef(agent) : undefined;
  if (!agent || !ref) return;
  if (installedPluginVersions().has(ref)) return;

  const out = process.stdout;
  if (!autoYes) {
    if (!process.stdin.isTTY) {
      out.write(
        `\n${PLUGIN_OFFER_IDENTITY}\n` +
          `No Claude Code plugin detected. Install it via the marketplace:\n` +
          `  /plugin marketplace add ${agent.marketplaceSource ?? ''}\n` +
          `  /plugin install ${ref}\n` +
          `Or re-run \`aka init --yes\` to install it automatically.\n`,
      );
      return;
    }
    if (
      !(await confirm(
        `\n${PLUGIN_OFFER_IDENTITY}\n` +
          `Install the ${PRODUCT_NAME} plugin for Claude Code now (via the marketplace)? [y/N] `,
      ))
    ) {
      out.write('Skipped. Install anytime with `aka plugins install claude-code`.\n');
      return;
    }
  }
  await runPlugins(['install', 'claude-code']);
}

async function confirm(question: string): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(question)).trim().toLowerCase();
    return answer === 'y' || answer === 'yes';
  } finally {
    rl.close();
  }
}
