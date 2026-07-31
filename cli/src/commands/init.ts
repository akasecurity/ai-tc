import { existsSync, lstatSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import * as readline from 'node:readline/promises';
import { parseArgs } from 'node:util';

import {
  cliRecordedBy,
  findAgent,
  installedPluginVersions,
  pluginRef,
} from '@akasecurity/local-ops';
import {
  keysDir,
  openLocalDatabase,
  tightenFile,
  writeOwnerOnlyFileSync,
} from '@akasecurity/persistence';
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

// Every path the store spans and holds to an owner-only mode: the base, its
// layout directories, and the two files that exist once init has run. Not all of
// them are created by `aka init` — keys/ is minted lazily by the vault key
// provider, on first use — so an absent path is the normal case and each caller
// filters it out rather than treating it as a finding.
function storeTargets(home: string): string[] {
  return [
    home,
    settingsDir(home),
    dataDir(home),
    keysDir(home),
    join(settingsDir(home), 'settings.json'),
    dbPath(home),
  ];
}

// The store paths whose owner-only mode could not be applied. `aka init` tightens
// all of them; any that stay group/other-readable means the filesystem rejected
// chmod (a root-owned home, an SMB/NFS/DrvFs mount), so the store has no at-rest
// control. The runtime tighten is silent to keep the fail-open hook path quiet;
// this is the one place a failure is surfaced, because it is user-initiated and
// actionable. POSIX-only — Windows never applies these modes (see SECURITY.md).
export function looseStorePaths(home: string): string[] {
  if (process.platform === 'win32') return [];
  return storeTargets(home).filter((p) => {
    try {
      // A symlinked path is deliberately never chmod'd (see symlinkedStorePaths),
      // so reporting its target's mode here would blame the filesystem for a
      // permission this code chose not to apply.
      if (lstatSync(p).isSymbolicLink()) return false;
      return (statSync(p).mode & 0o077) !== 0; // any group/other bit → not owner-only
    } catch {
      return false; // absent → not a loose target
    }
  });
}

// The store paths that are symlinks, with what they resolve to and the mode that
// target carries right now. A chmod is never applied through a symlink (see
// @akasecurity/persistence's chmodBestEffort), so a symlinked store path keeps
// whatever mode its target already had — and the store, including the prompt
// corpus in aka.db, is written inside that target. Neither fact is visible from
// the outside, and the runtime paths stay silent to keep hooks fail-open and
// quiet, so `aka init` is where both are named.
// POSIX-only, for the same reason looseStorePaths is.
export function symlinkedStorePaths(
  home: string,
): { path: string; target: string; mode?: number }[] {
  if (process.platform === 'win32') return [];
  return storeTargets(home).flatMap((path) => {
    try {
      if (!lstatSync(path).isSymbolicLink()) return [];
      return [{ path, target: linkTarget(path), mode: targetMode(path) }];
    } catch {
      return []; // absent → not a symlinked target
    }
  });
}

// Where a link points, preferring the fully resolved absolute path — that is the
// directory the store actually lands in, which is what the warning is about. A
// link resolving nowhere has no real path, so fall back to its literal contents,
// resolved against the link's own directory: readlink returns whatever was
// stored, and a relative target on its own names nothing a reader can act on.
function linkTarget(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(dirname(path), readlinkSync(path));
  }
}

// The mode the link's target carries. This is the permission the store actually
// inherits, and it is the fact looseStorePaths can no longer report — it skips a
// symlinked path, because the chmod there was declined rather than rejected, and
// without this the one actionable half of the warning ("that target is readable
// by everyone") would go unsaid. Undefined when there is nothing to stat, so a
// link resolving nowhere reads as unknown rather than as owner-only.
function targetMode(path: string): number | undefined {
  try {
    return statSync(path).mode & 0o777; // statSync follows the link, which is the point
  } catch {
    return undefined;
  }
}

// The `aka init` warning for one symlinked store path. Names the inherited mode,
// and says plainly when it is not owner-only — that is the sentence a reader has
// to act on, and the loose-path warning can no longer carry it.
function symlinkWarning({ path, target, mode }: { path: string; target: string; mode?: number }) {
  const inherited =
    mode === undefined
      ? ''
      : ` (currently ${formatMode(mode)}${(mode & 0o077) !== 0 ? ', NOT owner-only' : ''})`;
  return (
    `  ⚠ ${path} is a symlink to ${target}${inherited} — permissions are never changed ` +
    `through a symlink, so the store keeps that target's own, and its contents (including ` +
    `the prompt corpus in aka.db) are written there ` +
    `(see the "Data at rest" note in SECURITY.md)\n`
  );
}

function formatMode(mode: number): string {
  return `0${mode.toString(8).padStart(3, '0')}`;
}

// A store directory that is a symlink resolving nowhere cannot be created: mkdir
// raises ENOENT naming a path that DOES exist, which reads as a missing parent
// rather than a broken link. It also throws before the symlink report above is
// ever reached, so without this the one diagnosis that would explain the failure
// never prints. Refuse here instead, naming the link and its target.
//
// Not gated on POSIX — a broken link is broken everywhere, and none of this is
// about modes. Checked for the three directories init creates through: the base,
// settings/, and data/ (via openLocalDatabase).
function assertStoreLinksResolve(home: string): void {
  for (const dir of [home, settingsDir(home), dataDir(home)]) {
    if (!isBrokenLink(dir)) continue;
    throw new Error(
      `${dir} is a symlink to ${linkTarget(dir)}, which does not exist — ` +
        'create that target or remove the link, then re-run `aka init`',
    );
  }
}

// existsSync follows the link, so a link whose target is gone is exactly the
// pair "lstat says symlink, exists says no".
function isBrokenLink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink() && !existsSync(path);
  } catch {
    return false; // absent, or unreadable — not this diagnosis
  }
}

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

  assertStoreLinksResolve(home);
  ensureDataDirSync(home);
  const settings = settingsDir(home);
  ensureDataDirSync(settings);
  const settingsFile = join(settings, 'settings.json');
  // Don't clobber an existing settings.json — a re-run must preserve the user's
  // onboarding choices (runMode/policy/historicalAccess). Only write defaults on
  // first init.
  const settingsCreated = !existsSync(settingsFile);
  if (settingsCreated) {
    // Owner-only atomic write (tmp + rename), matching every other writer under
    // ~/.aka — a crash mid-write must never leave a truncated or group-readable
    // settings.json, and a pre-existing loose `.tmp` isn't carried through.
    writeOwnerOnlyFileSync(
      settingsFile,
      `${JSON.stringify(defaultWorkspaceSettings(), null, 2)}\n`,
    );
  }
  // Re-tighten whether or not we just wrote it: a re-run of `aka init` over a
  // settings.json a prior release left loose (the leftover-`.tmp` bug) must
  // self-heal it to 0600 — the same repair the dirs, key, and db already get on
  // their own access paths. Gating this on `settingsCreated` left settings.json
  // as the one artifact under ~/.aka that never self-healed.
  tightenFile(settingsFile);

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

  const loose = looseStorePaths(home);
  const symlinked = symlinkedStorePaths(home);
  process.stdout.write(
    `✓ Initialized AKA at ${home}\n` +
      `  settings: ${settingsFile}${settingsCreated ? '' : ' (kept existing)'}\n` +
      `  database: ${dbPath(home)}\n` +
      `  seeded ${String(policyCount)} default policies, ${String(packCount)} detection pack(s)\n` +
      (updatesAvailable > 0
        ? `  ⬆ ${String(updatesAvailable)} detection pack update(s) available — review with \`aka detections\`, apply with \`aka detections update --all\`\n`
        : '') +
      (loose.length > 0
        ? `  ⚠ could not enforce owner-only permissions on ${loose.join(', ')} — this filesystem rejects chmod, so the store has no at-rest protection here (see the "Data at rest" note in SECURITY.md)\n`
        : '') +
      symlinked.map(symlinkWarning).join(''),
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
