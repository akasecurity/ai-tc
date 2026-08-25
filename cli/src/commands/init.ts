import { existsSync, lstatSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import * as readline from 'node:readline/promises';
import { parseArgs } from 'node:util';

import {
  cliRecordedBy,
  findAgent,
  installedPluginVersions,
  pluginRef,
} from '@akasecurity/local-ops';
import type { SymlinkedStorePath } from '@akasecurity/persistence';
import {
  FileLockError,
  keysDir,
  linkTarget,
  openLocalDatabase,
  storeTargets,
  symlinkedStorePaths,
  tightenFile,
  withFileLock,
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

// Every path whose owner-only MODE this command stands behind. The layout above
// has to stay enumerated — some of it does not exist yet on a first run, and an
// absent target is not a loose one — but the artifacts beside the store and
// beside the vault key are not a fixed list, so both directories are walked
// instead. SQLite's `-wal`/`-shm`/`-journal`
// appear with whichever journal mode is active, and the legacy drop leaves an
// `aka.db.pre-drop.<ts>.<rand>.bak` — a byte-for-byte copy of the prompt corpus
// — on any run that carries pre-cutover history forward (never a first one: the
// drop takes no snapshot where it would destroy no row).
// `tightenPerms`/`tightenFile` already
// hold all of them at 0600, so each is a path a rejected chmod can strand; a
// hardcoded list here would never name one, and could not name whatever the
// next migration adds.
function storeModeTargets(home: string): string[] {
  const targets = new Set(storeTargets(home));
  // Both directories that accumulate artifacts the enumerated layout cannot
  // name. data/ holds the sidecars and the backups; keys/ holds `vault.key`
  // itself — enumerated only as a DIRECTORY above, so the key inside it, and the
  // rotation lock beside it, were checked by nothing until this walked here too.
  for (const dir of [dataDir(home), keysDir(home)]) {
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        // A `.partial` FILE is the legacy staging shape: an older version wrote
        // its snapshot copy straight to one and only tightened it just before
        // the rename, so a copy cut short by a kill left a 0644 file behind on
        // purpose. Reporting it would blame the filesystem for a mode nothing
        // tried to apply — the wrong diagnosis, which is the same reason a
        // symlinked path is skipped below. The current shape is a `.partial`
        // DIRECTORY created owner-only before the copy starts (see
        // snapshotStore), and that mode IS one this command stands behind.
        if (entry.name.endsWith('.partial') && !entry.isDirectory()) continue;
        targets.add(join(dir, entry.name));
      }
    } catch {
      // absent or unreadable — the enumerated layout still applies
    }
  }
  return [...targets];
}

// The store paths whose owner-only mode could not be applied. `aka init` tightens
// all of them; any that stay group/other-readable means the filesystem rejected
// chmod (a root-owned home, an SMB/NFS/DrvFs mount), so the store has no at-rest
// control. The runtime tighten is silent to keep the fail-open hook path quiet;
// this is the one place a failure is surfaced, because it is user-initiated and
// actionable. POSIX-only — Windows never applies these modes (see SECURITY.md).
export function looseStorePaths(home: string): string[] {
  if (process.platform === 'win32') return [];
  return storeModeTargets(home).filter((p) => {
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

// The `aka init` warnings for the symlinked store paths. Each names what really
// lands at that path, and the mode it inherits — saying plainly when that is not
// owner-only, which is the sentence a reader has to act on and the one the
// loose-path warning can no longer carry.
//
// Three shapes, because one sentence cannot be true of all of them:
//   - a resolving link inherits a permission, so the mode is the story;
//   - on Windows no mode is ever applied (see SECURITY.md), so claiming the
//     target's own is kept would describe a control that does not exist there —
//     the clause is dropped rather than reworded, and the redirection stands;
//   - a link resolving NOWHERE inherits nothing and has received nothing. Saying
//     it "keeps that target's own permissions" is false twice over: there is no
//     target, and the write has not happened. What follows is a failure the next
//     time something tries to create through it — for keys/, the vault key mint.
export function symlinkWarnings(
  paths: SymlinkedStorePath[],
  platform: NodeJS.Platform = process.platform,
): string {
  const seeAlso = '(see the "Data at rest" note in SECURITY.md)';
  return paths
    .map(({ path, target, holds, missing, mode }) => {
      if (missing) {
        return (
          `  ⚠ ${path} is a symlink to ${target}, which does not exist — ${holds} ` +
          `cannot be written there until you create that target or remove the link ${seeAlso}\n`
        );
      }
      const inherited =
        mode === undefined
          ? ''
          : ` (currently ${formatMode(mode)}${(mode & 0o077) !== 0 ? ', NOT owner-only' : ''})`;
      const kept =
        platform === 'win32' ? '' : 'permissions are never changed through a symlink, so ';
      const under = platform === 'win32' ? '' : " under that target's own permissions";
      return `  ⚠ ${path} is a symlink to ${target}${inherited} — ${kept}${holds} is written there${under} ${seeAlso}\n`;
    })
    .join('');
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

// A store directory that already exists as a FILE cannot be created either, and
// the raw failure is actively misleading: `mkdir` raises EEXIST, whose message
// ("file already exists") reads as "this is already done" rather than "something
// else is sitting where the store goes". Every occupied path reports that way,
// at any depth — `ensureDataDirSync` passes `recursive: true`, so it fails at
// the occupied component itself and never creates *through* a file. Refuse here
// instead, naming the path that is occupied and what to do about it.
//
// Checked for the same three directories as the broken-link guard, and after
// it, so a broken link keeps its own more specific diagnosis. `statSync`
// follows a link deliberately: a link to a regular file is this fault, not a
// symlink note, and `aka init` supports a home symlinked to a real directory.
//
// Which means the path named here may itself be a link, and saying "move that
// file aside" of one sends a reader to the TARGET — someone else's real file,
// which removing would be the wrong repair and is not reversible. A link is
// therefore reported as a link, naming what it resolves to, the way
// assertStoreLinksResolve reports its own.
function assertStorePathsAreDirectories(home: string): void {
  // keys/ is included even though `aka init` does not create it: the vault
  // mints it lazily on first use, so a regular file there lets init SUCCEED
  // and then blames the filesystem — "could not enforce owner-only permissions
  // on …/keys" — for a path that is simply occupied, while `aka vault` later
  // dies on a bare EEXIST. An absent path is not a finding, so adding it costs
  // the common case nothing.
  for (const dir of [home, settingsDir(home), dataDir(home), keysDir(home)]) {
    if (!existsAsNonDirectory(dir)) continue;
    const occupant = isSymlink(dir)
      ? `is a symlink to ${linkTarget(dir)}, which is not a directory — remove the link`
      : 'exists but is not a directory — move that file aside or remove it';
    throw new Error(`${dir} ${occupant}. AKA keeps its store there; re-run \`aka init\` after.`);
  }
}

function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function existsAsNonDirectory(path: string): boolean {
  try {
    return !statSync(path).isDirectory();
  } catch {
    // Absent (the normal case on a fresh init), a broken link (already
    // diagnosed above), or unreadable — none of them this diagnosis.
    return false;
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
  assertStorePathsAreDirectories(home);
  ensureDataDirSync(home);
  const settings = settingsDir(home);
  ensureDataDirSync(settings);
  const settingsFile = join(settings, 'settings.json');
  // Don't clobber an existing settings.json — a re-run must preserve the user's
  // onboarding choices (runMode/policy/historicalAccess). Only write defaults on
  // first init.
  //
  // Under the same lock the wizard and the dashboard take, and the existence
  // check is re-run INSIDE it: this is the third writer of one file, and an
  // unlocked check-then-write can see no file, have the wizard's answers land
  // while it decides, and then replace them with defaults.
  //
  // The lock is taken only when there is a write to make. A settings.json that
  // is already there needs neither the lock nor the write, and taking one anyway
  // would make `aka init` fail on a store whose settings dir refuses new files —
  // the broken state this command exists to repair, and one it used to walk
  // through untouched.
  //
  // A `timeout` is swallowed because the only writer that can hold this lock is
  // one writing this same file: it is creating what init would have created, so
  // there is nothing left to do. An `unavailable` directory is a real fault and
  // propagates, exactly as the failed write did before there was a lock.
  let settingsCreated = false;
  if (!existsSync(settingsFile)) {
    try {
      settingsCreated = withFileLock(settingsFile, () => {
        // Re-checked INSIDE the lock: the wizard's answers can land between the
        // check above and this one, and defaults must never replace them.
        if (existsSync(settingsFile)) return false;
        // Owner-only atomic write (tmp + rename), matching every other writer under
        // ~/.aka — a crash mid-write must never leave a truncated or group-readable
        // settings.json, and a pre-existing loose `.tmp` isn't carried through.
        writeOwnerOnlyFileSync(
          settingsFile,
          `${JSON.stringify(defaultWorkspaceSettings(), null, 2)}\n`,
        );
        return true;
      });
    } catch (err) {
      if (!(err instanceof FileLockError) || err.reason !== 'timeout') throw err;
    }
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
      // "kept existing" is a claim about a file that is there. The one path that
      // reaches here with nothing on disk is a write skipped because another
      // process held the lock, and saying "kept existing" about a file that does
      // not exist would make the case where init did not do its job read exactly
      // like the case where it had nothing to do.
      `  settings: ${settingsFile}${settingsCreated ? '' : existsSync(settingsFile) ? ' (kept existing)' : ' (not written — another process was writing it)'}\n` +
      `  database: ${dbPath(home)}\n` +
      `  seeded ${String(policyCount)} default policies, ${String(packCount)} detection pack(s)\n` +
      (updatesAvailable > 0
        ? `  ⬆ ${String(updatesAvailable)} detection pack update(s) available — review with \`aka detections\`, apply with \`aka detections update --all\`\n`
        : '') +
      (loose.length > 0
        ? `  ⚠ could not enforce owner-only permissions on ${loose.join(', ')} — this filesystem rejects chmod, so the store has no at-rest protection here (see the "Data at rest" note in SECURITY.md)\n`
        : '') +
      symlinkWarnings(symlinked),
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
