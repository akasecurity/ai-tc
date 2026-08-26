import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';

import { ATTACHED_CREDENTIAL_FILENAME } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { EXCEPTION_KEY_FILENAME } from '../src/fingerprint.ts';
import { SNAPSHOT_STAGING_SUFFIX } from '../src/internal/snapshot.ts';
import { dataDir, defaultDataDir, keysDir, settingsDir } from '../src/local-layout.ts';
import { DATA_DIR_MODE, DATA_FILE_MODE, DB_FILENAME, dbSidecars } from '../src/paths.ts';
import { SETTINGS_FILENAME } from '../src/settings.ts';
import { VAULT_KEY_FILENAME } from '../src/vault/key-provider.ts';

/**
 * SECURITY.md's "Data at rest" note is the answer a user gets when they ask what
 * protects the local prompt corpus, and this package owns everything that note
 * describes: the modes, the layout, every filename in it. So the assertions below
 * are DERIVED from those exports rather than pinned to the prose — a new
 * directory, a new file, a fourth sidecar or a changed mode reddens the note
 * until the note names it. Pinned expectations would have stayed green through
 * exactly the drift that put `-journal` in dbSidecars and left it out of the doc,
 * and through the one that added `~/.aka/keys/vault.key` and named it nowhere.
 *
 * The READMEs are the path to that note. A reader who never reaches SECURITY.md
 * cannot act on it, so every shipped front door that introduces the store has to
 * link it from the same page. The root README also states the posture inline, so
 * it carries the same derived mode assertions the note does — a second copy of
 * the modes in prose is a second thing that can drift.
 *
 * plugins/claude-code/test/privacy-claims.test.ts is the other guard over these
 * same READMEs; it covers the egress footnote rather than the at-rest posture.
 * Editing a README can redden either suite.
 */

const repoFile = (relative: string): string =>
  readFileSync(new URL(relative, import.meta.url), 'utf8');

/**
 * One `## ` section of a markdown file, from its heading to the next one,
 * whitespace-normalized so assertions are not coupled to prose line wrapping.
 *
 * Slicing rather than reading the whole file keeps a mention elsewhere on the
 * page from satisfying a claim about this section. An absent heading yields the
 * empty string, so every assertion below it fails rather than matching against
 * the wrong text.
 */
const section = (text: string, heading: string): string => {
  const start = text.indexOf(heading);
  if (start === -1) return '';
  const end = text.indexOf('\n## ', start + heading.length);
  return text.slice(start, end === -1 ? undefined : end).replace(/\s+/g, ' ');
};

const atRest = section(repoFile('../../../SECURITY.md'), '## Data at rest');
const whereData = section(repoFile('../../../README.md'), '## Where your data lives');

// `/Users/you/.aka/data` → `~/.aka/data`: the form the prose uses. Windows
// separators are normalized so one expectation holds on every platform.
const home = homedir();
const tildeify = (path: string): string => path.replace(home, '~').replaceAll('\\', '/');

// Every directory the layout module defines, so a fifth one cannot be added
// without the note naming it. `keysDir` is why this is derived and not a list:
// it was added after the note was written, and a hardcoded three-entry list
// pinned the omission instead of catching it.
const STORE_DIRS = [defaultDataDir(), dataDir(), settingsDir(), keysDir()].map(tildeify);

// Every file the store writes under those directories, each taken from the
// module that writes it.
const STORE_FILES = [
  ATTACHED_CREDENTIAL_FILENAME,
  DB_FILENAME,
  EXCEPTION_KEY_FILENAME,
  SETTINGS_FILENAME,
  VAULT_KEY_FILENAME,
] as const;

// `aka.db-wal` → `-wal`: the suffix the prose names, taken from the code that
// creates and tightens the set.
const SIDECAR_SUFFIXES = dbSidecars(DB_FILENAME).map((path) => path.slice(DB_FILENAME.length));

const octal = (mode: number): string => `0${mode.toString(8)}`;

// A mode has to sit next to the thing it is applied to. A bare
// `toContain(octal(mode))` cannot tell the two apart — both modes are named in
// one sentence, so pointing DATA_DIR_MODE at 0o600 left the directory assertion
// green against prose that still said 0700. Pinning the few words that attach a
// mode to its subject is a deliberate coupling: it is what makes the derived
// value mean anything.
const DIR_MODE_CLAIM = `created owner-only (\`${octal(DATA_DIR_MODE)}\`)`;
const FILE_MODE_CLAIM = `are written \`${octal(DATA_FILE_MODE)}\``;

// The modes are the whole control, and Node cannot apply them on Windows.
// Silence on either point reads as coverage, which is the one answer that would
// put a user wrong about their own machine.
const ONLY_CONTROL = /only at-rest control/i;
const WINDOWS_NULL = /no-op on Windows|do nothing on Windows|unprotected at rest on Windows/i;

// Both pages that state the posture in prose. They are held to the same derived
// claims so neither can drift alone.
const POSTURE_PAGES = [
  ['SECURITY.md "Data at rest"', atRest],
  ['README.md "Where your data lives"', whereData],
] as const;

describe.each(POSTURE_PAGES)('%s', (_name, text) => {
  it('has the section the rest of these assertions read', () => {
    expect(text).not.toBe('');
  });

  it('attributes the directory mode to the directories', () => {
    expect(text).toContain(DIR_MODE_CLAIM);
  });

  it('attributes the file mode to the files', () => {
    expect(text).toContain(FILE_MODE_CLAIM);
  });

  it('states that the modes are the only at-rest control', () => {
    expect(text).toMatch(ONLY_CONTROL);
  });

  it('states that the modes do nothing on Windows', () => {
    expect(text).toMatch(WINDOWS_NULL);
  });
});

/**
 * The authoritative list is the claim that attaches the modes — everything the
 * note holds to 0700/0600, up to the end of that claim.
 *
 * Asserting against the whole section instead would let a passing mention
 * further down satisfy a claim about the list: dropping `vault.key` from the
 * enumeration left the paragraph explaining what `vault.key` IS still standing,
 * and the guard stayed green over a list that no longer named it. That is the
 * same shape as the drift this suite exists to catch.
 */
const upToClaim = (text: string, claim: string): string => {
  const end = text.indexOf(claim);
  return end === -1 ? '' : text.slice(0, end + claim.length);
};

const enumeration = upToClaim(atRest, FILE_MODE_CLAIM);

// How many times the slice anchor occurs in the section it slices.
const occurrences = (text: string, needle: string): number =>
  needle === '' ? 0 : text.split(needle).length - 1;

describe('SECURITY.md "Data at rest" enumerates the store', () => {
  /**
   * The slice above narrows the window to the enumeration, and it holds only
   * while the anchor it slices on occurs ONCE. Nothing used to assert that.
   *
   * The claim is a sentence, not a marker, so it is reachable by an ordinary
   * reword — and `are written 0600` already appeared a second time further down,
   * in the paragraph about the backup copies. Reword the first occurrence and
   * `upToClaim` falls through to that one, the window silently grows back to the
   * whole section, and the guard is a whole-section text search again: dropping
   * both `-journal` and `vault.key` from the list then stays green, because the
   * WAL paragraph and the `vault.key` paragraph mention them anyway. That is
   * exactly the failure mode the slice exists to prevent, so it is asserted
   * rather than assumed — one line, beside the thing it protects.
   */
  it('slices on an anchor that occurs exactly once', () => {
    expect(occurrences(atRest, FILE_MODE_CLAIM)).toBe(1);
  });

  /**
   * The `.bak` paragraph states WHEN a copy is made, and that condition is the
   * part a user audits against: they open `~/.aka/data`, find no `.bak`, and
   * need to know whether that is healthy. It read as unconditional ("before a
   * migration rewrites the schema") long after the pre-drop snapshot became
   * conditional on the drop destroying rows, so a new install — which writes
   * none — looked like a store whose migration had silently not run.
   *
   * Everything else here derives a NAME from the module that writes it, which is
   * why this drifted with nothing going red: no name changed. The condition is
   * prose and has no constant to derive from, so it is pinned as prose, and
   * pinned in BOTH directions — the qualifier has to be present, and the
   * unconditional phrasing it replaced has to be absent, or a reword that
   * reinstates the old claim beside the new one reads as green.
   */
  it('says a snapshot is conditional, not routine', () => {
    expect(atRest).toContain('before a migration that would destroy rows');
    expect(atRest).not.toContain('before a migration rewrites the schema');
    // …and that a store legitimately carrying none is a normal state, which is
    // the half a user needs to read their own data dir.
    expect(atRest).toMatch(/may carry no `\.bak` at all/);
  });

  it.each(STORE_DIRS)('lists the %s directory among the tightened set', (dir) => {
    expect(enumeration).toContain(dir);
  });

  it.each(STORE_FILES)('lists the %s file among the tightened set', (file) => {
    expect(enumeration).toContain(file);
  });

  it.each(SIDECAR_SUFFIXES)('lists the %s sidecar among the tightened set', (suffix) => {
    expect(enumeration).toContain(suffix);
  });

  // Naming a sidecar is not the same as saying when it turns up. `-journal`
  // appears only where WAL is unavailable, which is the part a reader auditing a
  // WSL or network-mounted home has to know to look for.
  it('says when the rollback journal replaces the WAL pair', () => {
    expect(atRest).toMatch(/rollback journal/i);
    expect(atRest).toMatch(/WAL is unavailable/i);
  });

  // A snapshot the store cannot copy is moved aside whole, sidecars included, so
  // the backup is a set rather than the single file the note used to describe.
  it('says the backup carries its own sidecars', () => {
    expect(atRest).toMatch(/moves the whole set aside/i);
  });

  // The staging copy is the one at-rest artifact that cannot be created
  // owner-only — VACUUM INTO refuses an existing target, so the copy lands at
  // the umask and only an enclosing directory can cover it while it is written.
  // Both halves of that have to be in the note, and the suffix is DERIVED from
  // the module that builds the path rather than spelled here: the name is what a
  // reader greps their own data dir for, so a rename that left the note behind
  // would send them looking for a file they do not have.
  it('names the staging directory, and says it is owner-only', () => {
    expect(atRest).toContain(`.bak${SNAPSHOT_STAGING_SUFFIX}`);
    expect(atRest).toMatch(/created owner-only \(`0700`\) before the copy starts/i);
  });

  // And says when it goes. The previous wording — cleared "only when it next
  // takes a snapshot" — was accurate and is now false: the sweep runs on every
  // open. Copy that still implied a snapshot were needed would overstate the
  // exposure, which is its own kind of wrong answer for someone auditing a
  // machine.
  it('bounds when the abandoned staging copy is cleared, and says to delete it', () => {
    expect(atRest).toMatch(/on the next open of the store/i);
    expect(atRest).toMatch(/in flight is left alone/i);
    expect(atRest).toMatch(/delete one that outlives/i);
  });
});

// Every shipped front door. All three describe the same local store, and a
// reader who meets `~/.aka` on one of them should be one link from what protects
// it. The plugin and CLI pages are published to npm, where a relative link does
// not resolve, so they carry the absolute URL — the pattern accepts either form,
// but only for this repo's own file: a link to someone else's SECURITY.md would
// satisfy a loose pattern while telling the reader nothing.
const SECURITY_LINK =
  /]\((?:\.{0,2}\/)?SECURITY\.md(?:#[\w-]*)?\)|]\(https:\/\/github\.com\/akasecurity\/ai-tc\/blob\/[^/)]+\/SECURITY\.md(?:#[\w-]*)?\)/;

const READMES = [
  ['README.md', '../../../README.md'],
  ['cli/README.md', '../../../cli/README.md'],
  ['plugins/claude-code/README.md', '../../../plugins/claude-code/README.md'],
] as const;

describe.each(READMES)('%s at-rest discoverability', (_name, relative) => {
  const text = repoFile(relative);

  it('introduces the store by path', () => {
    expect(text).toContain('~/.aka');
  });

  it('links this repo’s SECURITY.md from the same page', () => {
    expect(text).toMatch(SECURITY_LINK);
  });
});

// The header over DATA_DIR_MODE used to tell readers these modes mirrored a copy
// the plugin SDK kept. The SDK's data-dir module re-exports them from here
// instead, so that sentence sent a reader looking for a second definition that
// does not exist. packages/plugin-sdk/test/data-dir.test.ts pins the direction
// itself; this pins the retired claim so it cannot come back by hand.
describe('paths.ts header', () => {
  const source = repoFile('../src/paths.ts');

  it('does not describe the modes as mirroring an SDK copy', () => {
    expect(source).not.toMatch(/mirror the modes the plugin SDK/i);
    expect(source).not.toMatch(/never depends on the SDK's layout module/i);
  });
});
