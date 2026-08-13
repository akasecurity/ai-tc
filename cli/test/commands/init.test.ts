import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, sep } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import { cachePath, writeCache } from '@akasecurity/local-ops';
import { keysDir, openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, dataDir, dbPath, settingsDir } from '@akasecurity/plugin-sdk';
import type { DetectionDetail } from '@akasecurity/schema';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import {
  looseStorePaths,
  runInit,
  symlinkedStorePaths,
  symlinkWarnings,
} from '../../src/commands/init.ts';
import { runPlugins } from '../../src/commands/plugins.ts';

// Force the offer's non-interactive branch to emit: report no installed plugin so
// offerPluginInstall reaches the print path, independent of the host's ~/.claude.
vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return { ...actual, installedPluginVersions: vi.fn(() => new Map<string, string>()) };
});

// The install is stubbed for the whole file, not just the cases that reach it.
// `runPlugins(['install', 'claude-code'])` shells out to `claude plugin install`
// — a real, machine-wide side effect on whoever runs the suite — so the only
// safe place to observe the `--yes` path is behind a stand-in. A file-scoped
// mock also means a case that reaches the installer by accident records a call
// instead of installing something.
vi.mock('../../src/commands/plugins.ts', () => ({ runPlugins: vi.fn(() => Promise.resolve()) }));

// The confirm prompt, recorded rather than answered from a terminal. `answer` is
// what `rl.question` resolves to, so a case picks the branch it wants; `asked`
// is every prompt string put to the user, which is what "--yes skips the prompt"
// is a claim about.
const prompt = vi.hoisted(() => ({ asked: [] as string[], answer: 'n' }));
vi.mock('node:readline/promises', () => ({
  createInterface: () => ({
    question: (question: string) => {
      prompt.asked.push(question);
      return Promise.resolve(prompt.answer);
    },
    close: () => undefined,
  }),
}));

let dir: string;
let stdinTTY: PropertyDescriptor | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-init-'));
  // The interactive offer is TTY-gated; force the non-TTY branch so runInit
  // prints the offer copy without blocking on a confirm prompt.
  stdinTTY = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
  prompt.asked.length = 0;
  prompt.answer = 'n';
  vi.mocked(runPlugins).mockClear();
});

afterEach(() => {
  removeTree(dir);
  if (stdinTTY) Object.defineProperty(process.stdin, 'isTTY', stdinTTY);
  else delete (process.stdin as { isTTY?: boolean }).isTTY;
  vi.restoreAllMocks();
});

// Every path under `home`, the home itself included. A hardcoded list of the
// paths init writes cannot cover what a later change adds — the migration's
// `aka.db.pre-drop.<ts>.bak`, a byte-for-byte copy of the store, is already one
// such file and no list here names it.
//
// Deliberately its own walk rather than a call into looseStorePaths: a test that
// reuses the implementation it is checking cannot catch a bug in that walk.
function storeTree(home: string): string[] {
  const entries = readdirSync(home, { withFileTypes: true, recursive: true });
  return [home, ...entries.map((e) => join(e.parentPath, e.name))];
}

// Is one walked path group/other-readable? `lstat`, not `stat`: stat follows a
// link and would report its TARGET's mode as a store failure, and the mode a
// symlinked store path keeps was never ours to set (see chmodBestEffort). A
// sibling that vanished between the readdir and here — an atomic write's `.tmp`
// — is not a finding; every other error must throw rather than read as clean,
// so a permission denial can never empty the haystack an absence assertion
// searches. The paths that must exist are asserted unguarded by the caller.
function looseInTree(path: string): boolean {
  try {
    const stats = lstatSync(path);
    if (stats.isSymbolicLink()) return false;
    return (stats.mode & 0o077) !== 0;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

const mode = (p: string): number => statSync(p).mode & 0o777;

// The five paths `aka init` creates and holds to a documented mode, with that
// mode. Kept as a pair so a case can assert the CONTRACT (0700 dirs, 0600 files)
// rather than only owner-only-ness: `& 0o077` alone passes a 0400 file and a
// 0700 one, neither of which is what SECURITY.md's "Data at rest" note promises.
function documentedModes(home: string): [path: string, mode: number][] {
  return [
    [home, 0o700],
    [settingsDir(home), 0o700],
    [dataDir(home), 0o700],
    [join(settingsDir(home), 'settings.json'), 0o600],
    [dbPath(home), 0o600],
  ];
}

describe('plugin-install offer identity', () => {
  it('emits offer copy carrying the canonical product name and tagline', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runInit(['--home', dir]);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('AKA Security');
    expect(out).toContain('We secure agent harnesses at the source.');
  });
});

describe('runInit contract', () => {
  it('still scaffolds ~/.aka and asks no posture questions', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runInit(['--home', dir]);

    // Scaffolding: the settings file and the SQLite store both land under the home.
    expect(existsSync(join(settingsDir(dir), 'settings.json'))).toBe(true);
    expect(existsSync(dbPath(dir))).toBe(true);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain(`Initialized AKA at ${dir}`);
    // init never interrogates the user about detection posture or historical access.
    expect(out).not.toMatch(/posture/i);
    expect(out).not.toMatch(/historical access/i);
  });

  it('leaves ~/.aka owner-only: 0700 dirs (base, settings/, data/) and 0600 files (settings.json, aka.db)', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    // Start from a loose home so this proves init TIGHTENS it, not merely that a
    // fresh mkdir happens to land at 0700. These modes are the store's only
    // at-rest control (see the "Data at rest" note in SECURITY.md).
    //
    // All THREE directories are pre-created loose, not just the base. `mkdir`
    // with `recursive: true` is a no-op on a path that already exists and its
    // `mode` is ignored there, so a pre-existing dir can only be repaired by the
    // explicit tighten — and with just the base planted, two of the three paths
    // this case names were reached by the create path instead.
    for (const d of [dir, settingsDir(dir), dataDir(dir)]) {
      mkdirSync(d, { recursive: true });
      chmodSync(d, 0o777);
    }

    await runInit(['--home', dir]);

    for (const [path, expected] of documentedModes(dir)) expect(mode(path)).toBe(expected);
  });

  it('holds every path under ~/.aka owner-only whatever umask the caller has', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    // What this pins is narrower than it looks, so state it exactly. No umask
    // can loosen 0700/0600 — a umask only ever CLEARS bits, and neither mode has
    // a group or other bit left to clear — so this case does NOT stand behind
    // the chmod; the loose-home case above is what does. What it stands behind
    // is that the modes never come from the caller's umask happening to be
    // tight: anything created here with no explicit mode lands 0777/0666, where
    // a default `umask 022` host would have shown the same bug as a milder
    // 0755/0644, and a `umask 077` host would have hidden it outright.
    //
    // The walk is the other half — see storeTree.
    //
    // The umask is process-global and restored in the `finally`; vitest runs a
    // file's tests in sequence, so the window is this case only. It also needs
    // the default `forks` pool — setting the umask raises
    // ERR_WORKER_UNSUPPORTED_OPERATION on a worker thread, so a switch to
    // `pool: 'threads'` fails this case loudly rather than skipping it.
    const outside = mkdtempSync(join(tmpdir(), 'aka-umask-control-'));
    const control = join(outside, 'no-mode');

    try {
      const previousUmask = process.umask(0o000);
      try {
        writeFileSync(control, ''); // no explicit mode — the precondition below
        await runInit(['--home', dir]);
      } finally {
        process.umask(previousUmask);
      }

      // Precondition: a no-mode file lands 0666 only under a genuinely
      // permissive umask. Without it the case passes vacuously wherever the
      // umask is ignored.
      expect(statSync(control).mode & 0o777).toBe(0o666);

      // The documented contract first, exactly — 0700 dirs and 0600 files, not
      // merely "no group or other bit". These five also stat unguarded, so a
      // store artifact that vanished under the walk below cannot pass as clean.
      for (const [path, expected] of documentedModes(dir)) expect(mode(path)).toBe(expected);

      const tree = storeTree(dir);
      // ...and the walk has to have reached the store, or "nothing is loose"
      // holds vacuously over an empty tree.
      expect(tree).toContain(dbPath(dir));
      expect(tree).toContain(join(settingsDir(dir), 'settings.json'));
      // Everything ELSE it found is owner-only too — the part a five-path list
      // cannot cover, and where the pre-drop backup is caught.
      expect(tree.filter(looseInTree)).toEqual([]);

      // The user-facing signal has to agree with the disk. It can: looseStorePaths
      // walks data/ rather than naming a fixed set, so a loose backup or sidecar
      // reaches this assertion. Before that fix it could not disagree about the
      // one artifact the walk above exists to catch.
      const out = stdout.mock.calls.map((c) => String(c[0])).join('');
      expect(out).not.toContain('could not enforce owner-only permissions');
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('re-tightens a pre-existing loose settings.json on re-run (tighten is not gated on creating it)', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    // Simulate a user who hit the pre-fix leftover-.tmp bug: settings.json exists
    // at 0666, so `settingsCreated` is false and the write block is skipped. The
    // re-run must still repair the mode — settings.json self-heals like the dirs,
    // the key, and the db.
    const settings = settingsDir(dir);
    mkdirSync(settings, { recursive: true });
    const file = join(settings, 'settings.json');
    writeFileSync(file, '{"specVersion":1,"runMode":"standalone","policy":"warn"}');
    chmodSync(file, 0o666);

    await runInit(['--home', dir]);

    expect(statSync(file).mode & 0o777).toBe(0o600);
    // ...and it did not clobber the user's saved answers.
    expect(readFileSync(file, 'utf8')).toContain('"policy":"warn"');
  });

  it('a second init preserves an existing settings.json (never clobbers onboarding answers)', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runInit(['--home', dir]);
    const file = join(settingsDir(dir), 'settings.json');

    // What the FIRST run wrote, checked before it is replaced below. Capturing
    // it and comparing the two runs was all this case used to do, and that
    // comparison could not fail — both runs write defaults, so a clobbering
    // init produced byte-identical output and passed. Replacing the file with
    // non-default answers is what makes the comparison bite, but doing only
    // that would leave the fresh write asserted by nothing at all.
    const firstRun = readFileSync(file, 'utf8');
    expect(JSON.parse(firstRun)).toEqual(defaultWorkspaceSettings());

    // The answers have to DIFFER from what init would write, or the comparison
    // below holds however the second run behaves. Onboarding is exactly what
    // puts a non-default value here, so stand in for it.
    const answers = `${JSON.stringify({ ...defaultWorkspaceSettings(), policy: 'warn' }, null, 2)}\n`;
    expect(answers).not.toBe(firstRun);
    writeFileSync(file, answers);
    stdout.mockClear();

    await runInit(['--home', dir]);

    // A re-run re-applies no migration and must not overwrite the user's answers.
    expect(readFileSync(file, 'utf8')).toBe(answers);
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('(kept existing)');
  });

  it('leaves a CORRUPT settings.json exactly as it found it, and still initializes', async () => {
    // init never READS settings.json — the only question it asks is whether the
    // path exists — so a file that no parser would accept is preserved by the
    // same branch that preserves a good one. Pinned because the tempting
    // "repair" (parse it, fall back to defaults when it throws) would silently
    // destroy the one copy of answers a user could still hand-edit back into
    // shape, and it would do so on the command people are told to re-run when
    // something looks wrong.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    mkdirSync(settingsDir(dir), { recursive: true });
    const file = join(settingsDir(dir), 'settings.json');
    // Truncated mid-object: valid JSON up to the cut, which is what a crash
    // during a non-atomic write leaves behind.
    const corrupt = '{\n  "specVersion": 1,\n  "runMode": "standalone",\n  "policy": "wa';
    writeFileSync(file, corrupt);

    await runInit(['--home', dir]);

    // Byte-for-byte, not merely "still parses as the same thing" — there is
    // nothing here that parses.
    expect(readFileSync(file, 'utf8')).toBe(corrupt);
    // ...and the run completed rather than dying on the unreadable file: the
    // store is there, and the file is reported as kept rather than created.
    expect(existsSync(dbPath(dir))).toBe(true);
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('(kept existing)');
  });

  it('preserves answers another writer publishes while init waits for the lock', async () => {
    // init is the THIRD writer of settings.json, behind the wizard and the
    // dashboard. Checking for the file outside the write lock lets it find none,
    // have the wizard's answers land while it decides, and then replace them
    // with defaults — the same silent loss the lock exists to remove, from the
    // one writer whose payload is "no answers at all".
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    mkdirSync(settingsDir(dir), { recursive: true });
    const file = join(settingsDir(dir), 'settings.json');
    const answers = `${JSON.stringify({ ...defaultWorkspaceSettings(), policy: 'warn' }, null, 2)}\n`;

    const holder = spawn(
      process.execPath,
      [join(import.meta.dirname, '..', 'helpers', 'settings-lock-holder.ts'), file, answers, '600'],
      { stdio: ['ignore', 'pipe', 'inherit'] },
    );
    // Bound to the event BEFORE anything is awaited. `close` fires once, so a
    // listener attached in the `finally` waits for a second emission that never
    // comes — the test would hang to its own timeout whenever init outlasts the
    // hold, which is the ordinary case.
    const holderClosed = once(holder, 'close');
    try {
      // Start init only once the lock is really held, so this is not a race that
      // happens to resolve one way. From here the ordering is the lock's to
      // enforce: the holder writes the file before releasing, and a live holder
      // is never stolen from, so an init that waits for the section always
      // finds it.
      await once(holder.stdout, 'data');
      await runInit(['--home', dir]);
    } finally {
      await holderClosed;
    }

    expect(JSON.parse(readFileSync(file, 'utf8'))).toMatchObject({ policy: 'warn' });
    // The observable difference. Unlocked, init writes its defaults before the
    // holder ever publishes — the answers still end up on disk (the holder
    // renames last), but init reports having CREATED the file, which is only
    // true if it clobbered somebody.
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('(kept existing)');
  });
});

// What `aka init` does to the detection tables. Two separate claims live here
// and they pull in opposite directions: the binary's inventory has to reach the
// store (or a fresh install scans with nothing), while a pack the user already
// has must come through untouched (or an `aka init` — the command people re-run
// when something looks wrong — silently reverts a pack they updated on purpose,
// or worse, downgrades one to whatever an older CLI on the same machine ships).
describe('runInit and the bundled detection inventory', () => {
  // The row this reads back, projected off the schema's own DetectionDetail
  // rather than restated: `update` in particular is a shape @akasecurity/schema
  // already describes, and spelling it `unknown` here would leave the
  // toMatchObject below unchecked against a rename of its fields.
  type PackRow = Pick<DetectionDetail, 'version' | 'name' | 'update'> & { rules: number };

  interface StoreInventory {
    packs: number;
    updates: number;
    rows: Map<string, PackRow>;
  }

  // Read back through the same ports the dashboard and `aka detections` use, so
  // this asserts what a user would actually see rather than raw rows. The handle
  // is opened and closed around the read: init closes its own, and a second live
  // one would keep the temp tree busy for the teardown.
  async function inventory(home: string): Promise<StoreInventory> {
    const db = openLocalDatabase(dataDir(home));
    try {
      const rows: StoreInventory['rows'] = new Map();
      for (const pack of bundledDetections()) {
        const id = `${pack.namespace}/${pack.packId}`;
        const row = await db.detections.getDetectionDetail(id);
        if (row) {
          rows.set(id, {
            version: row.version,
            name: row.name,
            rules: row.rules.length,
            update: row.update,
          });
        }
      }
      return {
        packs: (await db.installedPacks.counts()).packs,
        updates: (await db.detections.listDetections({ filter: 'all' })).counts.updates,
        rows,
      };
    } finally {
      db.close();
    }
  }

  // A pack that is missing is a different failure from a pack whose columns
  // moved, so say which — `undefined.version` names neither.
  function installed(store: StoreInventory, id: string): PackRow {
    const row = store.rows.get(id);
    if (!row) throw new Error(`pack ${id} is not installed`);
    return row;
  }

  it('installs the whole bundled inventory on a fresh home, and says how many', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const bundled = bundledDetections();
    expect(bundled.length).toBeGreaterThan(0); // precondition: there is an inventory to record

    await runInit(['--home', dir]);

    const store = await inventory(dir);
    expect(store.packs).toBe(bundled.length);
    // Each one at the version and rule count THIS binary ships, so a pack that
    // landed truncated or at the wrong version is caught rather than counted.
    for (const pack of bundled) {
      const row = installed(store, `${pack.namespace}/${pack.packId}`);
      expect(row.version).toBe(pack.version);
      expect(row.rules).toBe(pack.rules.length);
    }
    // Nothing is offered as an update on a fresh install: installed and
    // available were written from the same inventory in the same call.
    expect(store.updates).toBe(0);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain(`${String(bundled.length)} detection pack(s)`);
    expect(out).not.toContain('update(s) available');
  });

  it('never modifies a pack the user already has — it offers an update instead', async () => {
    // The user's ACTIVE snapshot is theirs. `recordInventory` is install-if-absent
    // (ON CONFLICT DO NOTHING), so a pack already in installed_packs keeps its
    // version, name and rules whatever this binary ships; the available_packs
    // mirror moves to the binary's inventory, and the difference is what the
    // manual update flow presents. Standing this up needs a pack that is present
    // and DIFFERENT, which is what an older binary on the same machine leaves.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    // Bound once: the seeded pack and the count asserted at the end have to come
    // from the same list, or the case compares against a value re-derived rather
    // than the one it reasoned about.
    const bundled = bundledDetections();
    const stale = bundled[0];
    if (!stale) throw new Error('no bundled packs to drive this case');
    const staleId = `${stale.namespace}/${stale.packId}`;
    const seededRules = stale.rules.slice(0, 1);
    // Older than anything shipped, so the mirror's downgrade guard treats the
    // bundled copy as newer and really does refresh — at an equal or higher
    // seeded version the guard would leave the mirror alone and the update
    // assertion below would be measuring the guard, not this command.
    const seeded = { ...stale, version: '0.0.1', name: 'older local copy', rules: seededRules };
    {
      const db = openLocalDatabase(dataDir(dir));
      try {
        db.installedPacks.recordInventory([seeded]);
      } finally {
        db.close();
      }
    }
    const before = await inventory(dir);
    // Precondition: the pack really is present and really does differ from what
    // this binary ships, or "unchanged" below holds for the wrong reason.
    expect(installed(before, staleId)).toMatchObject({
      version: '0.0.1',
      rules: seededRules.length,
    });
    expect(stale.version).not.toBe('0.0.1');

    await runInit(['--home', dir]);

    const after = await inventory(dir);
    const row = installed(after, staleId);
    // Untouched on every column recordInventory could have moved.
    expect(row.version).toBe('0.0.1');
    expect(row.name).toBe('older local copy');
    expect(row.rules).toBe(seededRules.length);
    // ...while the mirror DID take this binary's inventory, which is the half
    // that makes "never modified" a deferral rather than a dead end.
    expect(row.update).toMatchObject({ available: true, latestVersion: stale.version });
    expect(after.updates).toBe(1);
    // The packs this store did NOT already have are still installed — the guard
    // is per pack, not a blanket "skip the whole inventory".
    expect(after.packs).toBe(bundled.length);

    // And the user is told, with the command that applies it.
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('1 detection pack update(s) available');
    expect(out).toContain('aka detections update --all');
  });
});

// The offer that runs after the store is scaffolded. Three branches, and the
// only one that reaches a real installer is `--yes` — which is why runPlugins is
// stubbed for this whole file.
describe('the plugin-install offer', () => {
  const asTTY = (isTTY: boolean): void => {
    Object.defineProperty(process.stdin, 'isTTY', { value: isTTY, configurable: true });
  };

  it('prints the marketplace commands and asks nothing when stdin is not a TTY', async () => {
    // Piped stdin (CI, `aka init | tee`, a wrapper script) has nobody to answer
    // a prompt, so the offer degrades to copy-pasteable instructions. Blocking
    // on a read that never returns would hang the command instead.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    asTTY(false);
    // Captured and restored around the run: `process.exitCode` is process-wide,
    // so a value left set here would fail the whole vitest run at exit.
    const previousExitCode = process.exitCode;
    process.exitCode = undefined;

    try {
      await runInit(['--home', dir]);

      const out = stdout.mock.calls.map((c) => String(c[0])).join('');
      expect(out).toContain('No Claude Code plugin detected');
      // The two commands are the whole point of the branch — a reader has to be
      // able to paste them.
      expect(out).toContain('/plugin marketplace add akasecurity/marketplace');
      expect(out).toContain('/plugin install ai-tc@akasecurity');
      expect(out).toContain('aka init --yes');
      // Nothing was asked and nothing was installed.
      expect(prompt.asked).toEqual([]);
      expect(runPlugins).not.toHaveBeenCalled();
      // "…and exits 0" — asserted on the SAME run that printed the instructions.
      // A missing plugin is not an error condition, so this branch may neither
      // throw (the await above) nor mark the process failed. The bin entry's own
      // half of that chain is spawned separately below; this is the half that
      // ties the exit status to the branch that produced the copy.
      expect(process.exitCode).toBeUndefined();
    } finally {
      process.exitCode = previousExitCode;
    }
  });

  it('asks before installing when stdin IS a TTY', async () => {
    // The control that makes `--yes` mean something: without it there is a
    // prompt to skip. Answering no must leave the machine as it was and say how
    // to change your mind.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    asTTY(true);
    prompt.answer = 'n';

    await runInit(['--home', dir]);

    expect(prompt.asked).toHaveLength(1);
    expect(prompt.asked[0]).toContain('[y/N]');
    expect(runPlugins).not.toHaveBeenCalled();
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('Skipped.');
    expect(out).toContain('aka plugins install claude-code');
  });

  it('installs when the TTY answer is yes', async () => {
    // The other half of the same branch, so "no installs happened" above is a
    // decision this code makes rather than a path it cannot reach at all.
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    asTTY(true);
    prompt.answer = 'y';

    await runInit(['--home', dir]);

    expect(prompt.asked).toHaveLength(1);
    expect(runPlugins).toHaveBeenCalledWith(['install', 'claude-code']);
  });

  it.each([['--yes'], ['-y']])('%s installs without asking, even on a TTY', async (flag) => {
    // Driven on a TTY deliberately. On a pipe the prompt is skipped by the
    // non-TTY branch anyway, so the case would pass with the flag ignored
    // entirely — the skip is only observable where a prompt would otherwise be
    // put.
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    asTTY(true);
    // Set to the answer that DECLINES, so a prompt that is somehow reached
    // cannot be mistaken for the flag working.
    prompt.answer = 'n';

    await runInit(['--home', dir, flag]);

    expect(prompt.asked).toEqual([]);
    expect(runPlugins).toHaveBeenCalledWith(['install', 'claude-code']);
  });
});

describe('looseStorePaths', () => {
  it('reports the store paths that are not owner-only, and none when all are tight', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const settings = settingsDir(dir);
    mkdirSync(settings, { recursive: true });
    mkdirSync(dataDir(dir), { recursive: true });
    const file = join(settings, 'settings.json');
    writeFileSync(file, '{}');

    // All owner-only → nothing reported.
    for (const p of [dir, settings, dataDir(dir), file]) chmodSync(p, p === file ? 0o600 : 0o700);
    expect(looseStorePaths(dir)).toEqual([]);

    // Loosen settings.json → it (and only it) is reported.
    chmodSync(file, 0o644);
    expect(looseStorePaths(dir)).toEqual([file]);
  });

  it('reports a loose artifact beside the store that no enumerated target names', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // The layout is a fixed list; what sits beside the store is not. The legacy
    // drop leaves an `aka.db.pre-drop.<ts>.<rand>.bak` — a byte-for-byte copy of
    // the prompt corpus — on every run, and the SQLite sidecars appear with
    // whichever journal mode is active. tightenFile/tightenPerms hold all of
    // them at 0600, so one left group-readable is a rejected chmod, which is
    // exactly what this warning exists to surface. Before this walk the store's
    // only at-rest control could fail on the largest file in the directory and
    // the user would never be told.
    const settings = settingsDir(dir);
    mkdirSync(settings, { recursive: true });
    mkdirSync(dataDir(dir), { recursive: true });
    const file = join(settings, 'settings.json');
    writeFileSync(file, '{}');
    for (const p of [dir, settings, dataDir(dir), file]) chmodSync(p, p === file ? 0o600 : 0o700);
    expect(looseStorePaths(dir)).toEqual([]); // precondition: nothing enumerated is loose

    const backup = join(dataDir(dir), 'aka.db.pre-drop.1785500790653.545ee74f.bak');
    writeFileSync(backup, 'prompt corpus');
    chmodSync(backup, 0o644);
    const sidecar = join(dataDir(dir), 'aka.db-wal');
    writeFileSync(sidecar, '');
    chmodSync(sidecar, 0o644);

    expect(looseStorePaths(dir).sort()).toEqual([backup, sidecar].sort());
  });

  it('stays silent about the update-check cache, which is a real store file held at 0600', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // Driven by the REAL writer, not a stand-in, because the property is that
    // `writeCache`'s own mode agrees with what this walk stands behind. When it
    // wrote at the caller's umask, walking data/ turned an ordinary `aka init`
    // into "this filesystem rejects chmod" — nothing had rejected one, and
    // nothing had attempted one. That misattribution is exactly what the
    // `.partial` skip below exists to avoid, so it must not reappear here by a
    // different route.
    //
    // Not reachable through runInit: the notice that writes this cache runs in
    // main() after the handler returns, so only the writer itself can set it up.
    mkdirSync(dataDir(dir), { recursive: true });
    mkdirSync(settingsDir(dir), { recursive: true });
    for (const p of [dir, settingsDir(dir), dataDir(dir)]) chmodSync(p, 0o700);

    writeCache(dir, {
      checkedAt: Date.now(),
      report: { statuses: [], availablePlugins: [] },
      notifiedPluginIds: [],
    });

    expect(existsSync(cachePath(dir))).toBe(true); // precondition: the walk has it to find
    expect(statSync(cachePath(dir)).mode & 0o777).toBe(0o600);
    expect(looseStorePaths(dir)).toEqual([]);
  });

  it('does not report a `.partial` (loose by design mid-copy, not a rejected chmod)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // snapshotStore tightens its staging copy only just before the rename, so
    // the file exists at the caller's umask for the whole VACUUM INTO and a copy
    // cut short by a kill leaves a 0644 `.partial` behind on purpose. Naming it
    // here would blame the filesystem for a mode nothing tried to apply — the
    // same wrong diagnosis the symlink case below avoids.
    mkdirSync(dataDir(dir), { recursive: true });
    mkdirSync(settingsDir(dir), { recursive: true });
    for (const p of [dir, settingsDir(dir), dataDir(dir)]) chmodSync(p, 0o700);
    const partial = join(dataDir(dir), 'aka.db.pre-drop.1.aaaaaaaa.bak.partial');
    writeFileSync(partial, 'half a copy');
    chmodSync(partial, 0o644);

    expect(looseStorePaths(dir)).toEqual([]);
  });

  it('makes `aka init` print a warning when a mode could not be applied', async () => {
    // macOS-only fault injection: chflags freezes the settings dir so init's
    // tighten of settings.json fails, and init must surface that (data/ stays
    // writable, so the store still initializes). Runs on the `macOS · Full
    // suite` leg in ci.yml — the only leg it executes on, since the early return
    // below reports a pass everywhere else.
    if (process.platform !== 'darwin') return;
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const settings = settingsDir(dir);
    mkdirSync(settings, { recursive: true });
    writeFileSync(join(settings, 'settings.json'), '{}');
    chmodSync(join(settings, 'settings.json'), 0o644);
    execFileSync('chflags', ['uchg', settings]);
    try {
      await runInit(['--home', dir]);
      const out = stdout.mock.calls.map((c) => String(c[0])).join('');
      expect(out).toContain('could not enforce owner-only permissions');
    } finally {
      execFileSync('chflags', ['nouchg', settings]); // so afterEach can clean up
    }
  });

  it('does not report a symlinked path as loose (that mode was never ours to apply)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // statSync follows links, so a symlink to a 0755 dir looks group-readable.
    // Reporting it here would blame the filesystem for rejecting a chmod that was
    // deliberately skipped — the symlink warning is the accurate diagnosis.
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    expect(looseStorePaths(home)).toEqual([]);
  });
});

describe('symlinkedStorePaths', () => {
  it('reports each symlinked store path with what it resolves to, and none when all are real', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // A real home reports nothing.
    mkdirSync(settingsDir(dir), { recursive: true });
    mkdirSync(dataDir(dir), { recursive: true });
    expect(symlinkedStorePaths(dir)).toEqual([]);

    // Each store directory a symlink can stand in for — ~/.aka is covered by the
    // runInit case below; here the two layout leaves plus keys/, at a second
    // home. Each is named with the directory the store actually lands in, fully
    // resolved, so a chain of links still names the real destination (on macOS
    // the tmpdir is itself reached through /var -> /private/var).
    const home = join(dir, 'home2');
    mkdirSync(home);
    const elsewhereSettings = join(dir, 'elsewhere-settings');
    const elsewhereData = join(dir, 'elsewhere-data');
    const elsewhereKeys = join(dir, 'elsewhere-keys');
    for (const victim of [elsewhereSettings, elsewhereData, elsewhereKeys]) mkdirSync(victim);
    // Distinct modes, none of them 0700: the inherited permission is reported
    // per path, so a shared literal would not show it is read from the target.
    chmodSync(elsewhereSettings, 0o755);
    chmodSync(elsewhereData, 0o777);
    chmodSync(elsewhereKeys, 0o700);
    symlinkSync(elsewhereSettings, settingsDir(home));
    symlinkSync(elsewhereData, dataDir(home));
    symlinkSync(elsewhereKeys, join(home, 'keys'));

    // Reported in store-layout order: settings/, data/, keys/ — each with the
    // mode the store inherits from that target, which is what init warns about.
    expect(symlinkedStorePaths(home)).toEqual([
      {
        path: settingsDir(home),
        target: realpathSync(elsewhereSettings),
        holds: 'your settings file',
        missing: false,
        mode: 0o755,
      },
      {
        path: dataDir(home),
        target: realpathSync(elsewhereData),
        holds: 'the store database (including the prompt corpus)',
        missing: false,
        mode: 0o777,
      },
      {
        path: join(home, 'keys'),
        target: realpathSync(elsewhereKeys),
        holds: 'the vault key',
        missing: false,
        mode: 0o700,
      },
    ]);
  });

  it('still reports a link that resolves nowhere, naming an absolute target', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // realpath has nothing to resolve on a dangling link; falling through to
    // readlink keeps the report rather than dropping it as absent. There is
    // nothing to stat either, so the mode reads as unknown rather than as
    // owner-only — an absent mode must not be reported as a safe one.
    const home = join(dir, 'home3');
    mkdirSync(home);
    const missing = join(dir, 'unmounted-volume');
    symlinkSync(missing, join(home, 'keys'));

    expect(symlinkedStorePaths(home)).toEqual([
      {
        path: join(home, 'keys'),
        target: missing,
        holds: 'the vault key',
        missing: true,
        mode: undefined,
      },
    ]);
  });

  it('resolves a RELATIVE dangling target against the link, not the cwd', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // readlink returns whatever was stored, so a relative link reports a path
    // that names nothing on its own — the reader cannot tell where the corpus
    // would land. Resolve it against the link's own directory.
    const home = join(dir, 'home4');
    mkdirSync(home);
    symlinkSync('../unmounted-volume', join(home, 'keys'));

    expect(symlinkedStorePaths(home)).toEqual([
      {
        path: join(home, 'keys'),
        target: join(dir, 'unmounted-volume'),
        holds: 'the vault key',
        missing: true,
        mode: undefined,
      },
    ]);
  });
});

describe('symlinkWarnings', () => {
  // The redirection is the whole warning on Windows: no mode is ever applied
  // there, so there is no inherited permission to describe — but the prompt
  // corpus still lands wherever the junction points, and a junction needs no
  // elevation to create. Driven through the injected platform so both copies are
  // pinned from any host; the DEFAULT binding is pinned by the runInit cases
  // above, which read the real process.platform.
  const link = {
    path: '/home/u/.aka',
    target: '/srv/shared',
    holds: 'the store (including the prompt corpus in aka.db)',
    missing: false,
    mode: 0o755,
  };

  it('states the inherited permission on POSIX', () => {
    const out = symlinkWarnings([link], 'linux');
    expect(out).toContain('(currently 0755, NOT owner-only)');
    expect(out).toContain("under that target's own permissions");
    expect(out).toContain('prompt corpus');
  });

  it('drops the permissions clause on Windows but keeps the redirection', () => {
    const out = symlinkWarnings([{ ...link, mode: undefined }], 'win32');
    expect(out).toContain('/home/u/.aka is a symlink to /srv/shared');
    expect(out).toContain('prompt corpus');
    // No mode is applied on Windows at all, so claiming the target's own is
    // kept would describe a control that does not exist there.
    expect(out).not.toContain("under that target's own permissions");
    expect(out).not.toContain('currently');
  });

  // P1-a: the body is emitted once per store path, and aka.db only ever lands
  // under data/. A single generic sentence claimed the prompt corpus goes to
  // every one of them, which would send a reader to the wrong directory.
  it('names what actually lands at each path, not the corpus everywhere', () => {
    const out = symlinkWarnings(
      [
        { ...link, path: '/home/u/.aka/keys', holds: 'the vault key' },
        { ...link, path: '/home/u/.aka/settings', holds: 'your settings file' },
      ],
      'linux',
    );

    expect(out).toContain('/home/u/.aka/keys is a symlink to /srv/shared');
    expect(out).toContain('the vault key is written there');
    expect(out).toContain('your settings file is written there');
    // Neither path ever receives aka.db, so neither line may claim it does.
    expect(out).not.toContain('prompt corpus');
    expect(out).not.toContain('aka.db');
  });

  // P1-b: a link resolving nowhere inherits nothing and has received nothing.
  // Claiming it keeps the target's permissions is false twice over.
  it('says a link resolving nowhere has no target rather than inheriting one', () => {
    const out = symlinkWarnings(
      [
        {
          path: '/home/u/.aka/keys',
          target: '/mnt/unmounted',
          holds: 'the vault key',
          missing: true,
          mode: undefined,
        },
      ],
      'linux',
    );

    expect(out).toContain('is a symlink to /mnt/unmounted, which does not exist');
    expect(out).toContain('the vault key cannot be written there');
    expect(out).toContain('create that target or remove the link');
    // The two claims that are wrong for a target that is not there.
    expect(out).not.toContain("under that target's own permissions");
    expect(out).not.toContain('is written there');
  });

  it('reports no mode on Windows even where one is readable', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // statSync would happily return a mode on this host — the win32 branch must
    // decline to read it rather than report a permission Windows never applies.
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    expect(symlinkedStorePaths(home, 'win32')).toEqual([
      {
        path: home,
        target: realpathSync(victim),
        holds: 'the store (including the prompt corpus in aka.db)',
        missing: false,
        mode: undefined,
      },
    ]);
    expect(symlinkedStorePaths(home, 'linux')).toEqual([
      {
        path: home,
        target: realpathSync(victim),
        holds: 'the store (including the prompt corpus in aka.db)',
        missing: false,
        mode: 0o755,
      },
    ]);
  });
});

describe('runInit on a symlinked home', () => {
  it('leaves the victim directory mode unchanged and names the link', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // End-to-end through the real command: a symlink planted at the home path
    // used to be followed — the target was chmod'd to 0700 and the whole store
    // written inside it, with no warning. init must now leave the target's mode
    // alone and say where the store went.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    await runInit(['--home', home]);

    expect(statSync(victim).mode & 0o777).toBe(0o755); // victim NOT tightened
    expect(lstatSync(home).isSymbolicLink()).toBe(true); // link left as-is

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain(`${home} is a symlink to ${realpathSync(victim)}`);
    expect(out).toContain('prompt corpus');
    // The wrong diagnosis must not also fire: nothing here rejected a chmod.
    expect(out).not.toContain('could not enforce owner-only permissions');
  });

  it('names the mode the store inherits, and says when it is NOT owner-only', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // looseStorePaths skips a symlinked path (the chmod was declined, not
    // rejected), so this warning is the ONLY place the store's real at-rest
    // permission is stated. Without the mode a reader is told the target's
    // permissions were kept, but never that they are readable by everyone —
    // which is the whole point of the warning.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    await runInit(['--home', home]);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('(currently 0755, NOT owner-only)');
  });

  // Each of the three directories init creates through. `it.each` cannot carry
  // the test context a Windows skip needs, so the cases are generated by hand.
  for (const [label, at] of [
    ['the base', (home: string) => home],
    ['settings/', (home: string) => settingsDir(home)],
    ['data/', (home: string) => dataDir(home)],
  ] as const) {
    it(`diagnoses a BROKEN link at ${label} instead of raising a bare ENOENT`, async (ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('unprivileged symlink creation is not available on Windows');
        return;
      }
      // mkdir on a dangling link raises `ENOENT ... mkdir '<path>'` at a path
      // that does exist, which reads as a missing parent. It also throws before
      // the symlink report runs, so the diagnosis never prints.
      vi.spyOn(process.stdout, 'write').mockReturnValue(true);
      const home = join(dir, 'linkhome');
      mkdirSync(home);
      const missing = join(dir, 'unmounted-volume');
      const link = at(home);
      if (link === home) rmSync(home, { recursive: true });
      else mkdirSync(dirname(link), { recursive: true });
      symlinkSync(missing, link);

      await expect(runInit(['--home', home])).rejects.toThrow(
        `${link} is a symlink to ${missing}, which does not exist`,
      );
    });
  }

  it('does not cry wolf when the symlink target is already owner-only', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // The other half of the same property: a deliberately symlinked home that is
    // already 0700 still gets the redirection warning (the corpus does land
    // elsewhere) but must not be labelled loose, or the label stops meaning
    // anything.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const victim = join(dir, 'victim-private');
    mkdirSync(victim);
    chmodSync(victim, 0o700);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    await runInit(['--home', home]);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('(currently 0700)');
    expect(out).not.toContain('NOT owner-only');
  });

  it('still initializes the store through the link (surfaced, not refused)', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // The pinned decision: a home a user deliberately symlinked keeps working,
    // and the directories init creates inside it are still held owner-only.
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    await runInit(['--home', home]);

    expect(existsSync(join(victim, 'settings', 'settings.json'))).toBe(true);
    expect(existsSync(join(victim, 'data', 'aka.db'))).toBe(true);
    expect(statSync(join(victim, 'data')).mode & 0o777).toBe(0o700);
    expect(statSync(join(victim, 'settings', 'settings.json')).mode & 0o777).toBe(0o600);
  });
});

// `~/.aka` is not always a directory this process can create. A user can have a
// file sitting at that path, or a home tightened so `aka init` cannot write into
// it at all. Neither is exotic — both are what a hostile or merely unusual home
// looks like — and `aka init` is the one surface that has to say something a
// user can act on, because unlike a hook it is not allowed to fail open and
// carry on silently.
describe('runInit on a ~/.aka it cannot create', () => {
  // The three directories init creates through, each occupied by a regular
  // file. Driven per path rather than only at the base: `mkdir` reports EEXIST
  // at the base but ENOTDIR deeper down, naming the component that is NOT the
  // problem, so the deeper paths are where a raw error misleads most.
  for (const at of ['base', 'settings', 'data'] as const) {
    it(`refuses with an actionable error when ${at} is a regular file`, async () => {
      const home = join(dir, 'filehome');
      const occupied = at === 'base' ? home : at === 'settings' ? settingsDir(home) : dataDir(home);
      if (at !== 'base') mkdirSync(home, { recursive: true });
      writeFileSync(occupied, 'someone else owns this path\n');

      const err = await runInit(['--home', home]).then(
        () => undefined,
        (e: unknown) => e as Error,
      );

      // Named before the absence check below, so this is the refusal that was
      // reached and not merely some error.
      expect(err).toBeDefined();
      expect(err?.message).toContain(occupied);
      expect(err?.message).toContain('exists but is not a directory');
      // What to do about it. A message that only reports the state leaves a
      // user to guess whether AKA will fix it on the next run.
      expect(err?.message).toContain('move that file aside');
      // The raw failure this replaces read as "already done" rather than
      // "something else is there", which is the whole reason for the guard.
      // Only EEXIST is asserted: `recursive: true` fails at the occupied
      // component itself, so runInit never produces ENOTDIR here and an
      // absence check for it would be green whatever the guard did.
      expect(err?.message).not.toContain('EEXIST');
    });
  }

  it('leaves the occupying file untouched, so moving it aside is safe advice', async () => {
    const home = join(dir, 'filehome-intact');
    const original = 'someone else owns this path\n';
    writeFileSync(home, original);

    const err = await runInit(['--home', home]).then(
      () => undefined,
      (e: unknown) => e as Error,
    );

    // Named, so the untouched file below is evidence about THIS refusal. The
    // raw mkdir failure this guard replaces also leaves the file alone, so
    // without naming which error was reached the case passes identically with
    // the guard deleted and proves nothing about it.
    expect(err?.message).toContain('exists but is not a directory');
    expect(readFileSync(home, 'utf8')).toBe(original);
  });

  it('names the link and its target when a store path is a symlink to a file', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // The guard stats THROUGH a link on purpose, so this is the case that
    // decision creates. Telling the user to "move that file aside" of a symlink
    // points them at the target — someone else's real file — and deleting it is
    // both the wrong repair and irreversible. The link is what has to go.
    const target = join(dir, 'someone-elses-file');
    writeFileSync(target, 'not ours\n');
    const home = join(dir, 'linked-to-a-file');
    symlinkSync(target, home);

    const err = await runInit(['--home', home]).then(
      () => undefined,
      (e: unknown) => e as Error,
    );

    expect(err).toBeDefined();
    expect(err?.message).toContain(home);
    expect(err?.message).toContain('is a symlink to');
    expect(err?.message).toContain(target);
    expect(err?.message).toContain('remove the link');
    // Calling a symlink a file is the specific wording this case exists to
    // keep out.
    expect(err?.message).not.toContain('move that file aside');
    // And the target is still there to be pointed at.
    expect(readFileSync(target, 'utf8')).toBe('not ours\n');
  });

  it('initializes once the file is moved aside', async () => {
    // The positive control: the refusal is the occupied path and nothing
    // permanent about this home.
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const home = join(dir, 'filehome-cleared');
    writeFileSync(home, 'someone else owns this path\n');
    const refused = await runInit(['--home', home]).then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    // Named, not discarded. Swallowing this error makes the case survive
    // deleting the guard entirely — it would then be asserting only that
    // `aka init` works on an empty directory.
    expect(refused?.message).toContain('exists but is not a directory');

    rmSync(home, { force: true });
    await runInit(['--home', home]);

    expect(existsSync(dbPath(home))).toBe(true);
  });

  it('refuses when keys/ is occupied, rather than blaming the filesystem', async () => {
    // keys/ is minted lazily by the vault, so it is absent on a normal init and
    // the guard used to skip it. A file there let init SUCCEED and print a
    // permissions warning about a path that was merely occupied — sending the
    // user to chmod something that was never a mode problem — while the next
    // `aka vault` died on a bare EEXIST from the key provider.
    const home = join(dir, 'keyshome');
    mkdirSync(home, { recursive: true });
    writeFileSync(keysDir(home), 'someone else owns this path\n');

    const err = await runInit(['--home', home]).then(
      () => undefined,
      (e: unknown) => e as Error,
    );

    expect(err).toBeDefined();
    expect(err?.message).toContain(keysDir(home));
    expect(err?.message).toContain('exists but is not a directory');
  });

  it('is not bypassed by a trailing separator on --home', async () => {
    // `statSync('<a regular file>/')` raises ENOTDIR rather than describing the
    // file, so the guard's "is this a non-directory?" question came back "no"
    // and the path went through — producing the bare mkdir failure the guard
    // exists to replace. homeBase resolves the path, which drops the separator.
    const home = join(dir, 'slashhome');
    writeFileSync(home, 'someone else owns this path\n');

    const err = await runInit(['--home', home + sep]).then(
      () => undefined,
      (e: unknown) => e as Error,
    );

    expect(err).toBeDefined();
    expect(err?.message).toContain('exists but is not a directory');
    expect(err?.message).not.toContain('ENOTDIR');
  });

  it('self-heals a ~/.aka the owner has locked themselves out of', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('chmod does not deny a directory on Windows');
      return;
    }
    // Documented because it is the opposite of what the mode suggests, and it
    // is why the file case above is the one that needs a guard. A 0000 home is
    // still the owner's to widen, and `ensureDataDirSync` chmods it back to
    // 0700 on the way in — so `aka init` repairs this fault rather than
    // reporting it, and ends with the documented modes like any other run.
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const home = join(dir, 'lockedhome');
    mkdirSync(home, { recursive: true });
    chmodSync(home, 0o000);

    await runInit(['--home', home]);

    expect(existsSync(dbPath(home))).toBe(true);
    expect(statSync(home).mode & 0o777).toBe(0o700);
  });
});

// The EXIT CODE is `src/cli.ts`'s contract, not runInit's. runInit throws; the
// four-line bin shim is what turns that into a message on stderr and a non-zero
// exit, and nothing can import that shim without running the CLI. So these
// cases spawn the real entry point — the only place the whole chain (parse →
// refuse → report → exit) is observable, and the only thing that would catch a
// refactor that swallowed a throw and exited 0 with an empty store.
describe('aka init through the real bin entry', () => {
  // vitest's own per-test budget, not a `timeout(1)` shell-out — the package
  // default is 20s and a cold tsx transform of the whole workspace graph on a
  // loaded Windows runner has no business fitting inside it.
  const SPAWN_BUDGET_MS = 90_000;
  // Comfortably inside the budget above, so the in-band deadline wins the race
  // and gets to kill the child; equal values would let vitest fail the test
  // first and abandon the wait, which is the case this exists to avoid.
  const CLOSE_DEADLINE_MS = 75_000;
  const CLI_ROOT = join(import.meta.dirname, '..', '..');

  // Spawned via `node --import <tsx> <entry>` rather than a built artifact:
  // nothing here builds the CLI, and `node <entry>` alone dies on the first
  // parameter property in @akasecurity/persistence (strip-only mode).
  //
  // Two POSIX-only shapes are avoided deliberately. It never execs
  // `node_modules/.bin/tsx`, which on win32 is a `.cmd` launcher a bare spawn
  // cannot run without a shell; and the loader is resolved to a URL here rather
  // than passed as the bare specifier `tsx`, which Node would resolve against
  // the CHILD's cwd. `import.meta.resolve` asks the loader that is really
  // present, from this file's own position in the package, so nothing is
  // hand-written as a `file://` string.
  const TSX_LOADER = import.meta.resolve('tsx');

  async function runCli(
    args: string[],
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    const child = spawn(
      process.execPath,
      ['--import', TSX_LOADER, join(CLI_ROOT, 'src', 'cli.ts'), ...args],
      { cwd: CLI_ROOT, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    // A ChildProcess `error` with no listener is rethrown as an UNCAUGHT
    // exception, which kills the vitest worker and takes the rest of the file
    // with it. Recorded and reported through the normal return instead, so a
    // spawn that never starts fails this case with something readable.
    let spawnError: Error | undefined;
    child.on('error', (err: Error) => (spawnError = err));
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => (stdout += chunk));
    child.stderr.on('data', (chunk: string) => (stderr += chunk));
    // The wait is bounded HERE rather than left to vitest's per-test budget.
    // A vitest timeout rejects the test but does not cancel this function, so an
    // `await` on a child that never exits stays pending for ever and a `finally`
    // that kills it is never reached — leaving a live `node` holding the temp
    // store open, which on Windows turns one timeout into an EBUSY teardown
    // failure for every case after it. Losing this race is also a clearer
    // report than a bare timeout: it names what did not exit.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const overdue = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        reject(
          new Error(`aka ${args.join(' ')} did not exit within ${String(CLOSE_DEADLINE_MS)}ms`),
        );
      }, CLOSE_DEADLINE_MS);
    });
    try {
      const [code] = (await Promise.race([once(child, 'close'), overdue])) as [number | null];
      if (spawnError) throw spawnError;
      return { code, stdout, stderr };
    } finally {
      // Cleared whichever way the race went, so a settled call leaves no pending
      // timer to reject unobserved and no handle holding the event loop open.
      clearTimeout(timer);
      child.kill(); // a no-op on a child that has already exited
    }
  }

  // The child's stderr with Node's own diagnostics filtered out. Asserting a
  // spawned Node process writes NOTHING there is a promise the runtime does not
  // make: an ExperimentalWarning from the loader, or any deprecation notice,
  // lands on stderr beside whatever the CLI itself said. What these cases are
  // about is the CLI's own output, which the bin entry prefixes with `aka:`.
  const cliStderr = (stderr: string): string =>
    stderr
      .split('\n')
      .filter((line) => !/^\((?:node|tsx):\d+\)/u.test(line) && !/^\s*(?:at |Warning:)/u.test(line))
      .join('\n')
      .trim();

  it(
    'exits 0 and puts the store under --home, not the default home',
    async () => {
      // `--home` is the only way to point the CLI somewhere else — there is no
      // env override by design — so this is also what stands behind every other
      // case in this file being able to run against a temp dir at all.
      const home = join(dir, 'store');

      const { code, stdout, stderr } = await runCli(['init', '--home', home]);

      // The CLI said nothing on stderr — Node's own warnings are not the CLI's
      // output and must not decide this case (see cliStderr).
      expect(cliStderr(stderr)).toBe('');
      expect(code).toBe(0);
      expect(stdout).toContain(`Initialized AKA at ${home}`);
      expect(existsSync(dbPath(home))).toBe(true);
      expect(existsSync(join(settingsDir(home), 'settings.json'))).toBe(true);
      // Deliberately no assertion about the plugin offer here: which branch it
      // takes depends on whether the HOST running this suite has the Claude Code
      // plugin installed, and the copy is pinned in-process above, where
      // installedPluginVersions is stubbed. Both branches exit 0, which is the
      // claim this case makes.
    },
    SPAWN_BUDGET_MS,
  );

  it(
    'exits 1 with the actionable message when ~/.aka is a regular file',
    async () => {
      const home = join(dir, 'filehome');
      writeFileSync(home, 'someone else owns this path\n');

      const { code, stdout, stderr } = await runCli(['init', '--home', home]);

      expect(code).toBe(1);
      // Named before anything is asserted absent: this is the refusal that was
      // reached, not merely some non-zero exit.
      expect(stderr).toContain('exists but is not a directory');
      expect(stderr).toContain(home);
      expect(stderr).toContain('move that file aside');
      // A refusal must not also claim success on stdout.
      expect(stdout).not.toContain('Initialized AKA');
      // ...and the occupying file is still there to be moved.
      expect(readFileSync(home, 'utf8')).toBe('someone else owns this path\n');
    },
    SPAWN_BUDGET_MS,
  );

  it(
    'exits 1 on a corrupt store, and offers NO way to recover from it',
    async () => {
      // Pinned as CURRENT behaviour, not as behaviour worth having. A store
      // SQLite cannot open takes `aka init` down with a bare engine string —
      // the command a user is told to re-run when something is wrong is exactly
      // the command that cannot repair this, and nothing in the output says so
      // or names the file to move aside. The absence assertions below are the
      // pin: improving this is a deliberate edit that turns them red, rather
      // than a silent change nobody notices.
      const home = join(dir, 'corrupthome');
      mkdirSync(dataDir(home), { recursive: true });
      writeFileSync(dbPath(home), 'not a sqlite file, just bytes\n');

      const { code, stdout, stderr } = await runCli(['init', '--home', home]);

      const said = cliStderr(stderr);
      expect(code).toBe(1);
      // The positive control. Without it every absence check below is satisfied
      // by an empty stderr, which is the one outcome that would mean the guard
      // never ran.
      expect(said).toContain('file is not a database');
      expect(stdout).not.toContain('Initialized AKA');
      // What a recovery path would have to say, and none of it is said: which
      // file is broken, and what to do about it.
      //
      // Matched as WORDS, not substrings. A bare `not.toContain('move')` is
      // satisfied by nothing the CLI wrote and broken by anything that happens
      // to say "removed" — the word is inside it — so the pin would report a
      // recovery hint that does not exist.
      expect(said).not.toContain(dbPath(home));
      for (const word of ['move', 'moving', 're-run', 'rerun', 'backup', 'delete', 'recover']) {
        expect(said).not.toMatch(new RegExp(`\\b${word}\\b`, 'iu'));
      }
    },
    SPAWN_BUDGET_MS,
  );
});
