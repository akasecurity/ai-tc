import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { DATA_DIR_MODE, DATA_FILE_MODE, DB_FILENAME, dbSidecars } from '../src/paths.ts';

/**
 * SECURITY.md's "Data at rest" note is the answer a user gets when they ask what
 * protects the local prompt corpus, and this package owns everything that note
 * describes: the modes, the store filename, the sidecar set. So the assertions
 * below are DERIVED from those exports rather than pinned to the prose — adding
 * a fourth sidecar or changing a mode reddens the note until the note names it.
 * Pinned phrases would have stayed green through exactly the drift that put
 * `-journal` in dbSidecars and left it out of the doc.
 *
 * The READMEs are the path to that note. A reader who never reaches SECURITY.md
 * cannot act on it, so every shipped front door that introduces the store has to
 * link it from the same page.
 */

const repoFile = (relative: string): string =>
  readFileSync(new URL(relative, import.meta.url), 'utf8');

const security = repoFile('../../../SECURITY.md');

// The note's own section, from its heading to the next one. Slicing here rather
// than asserting on the whole file keeps a mention elsewhere in SECURITY.md from
// satisfying a claim about this note. Whitespace-normalized so the assertions
// are not coupled to prose line wrapping.
const HEADING = '## Data at rest';
const sectionStart = security.indexOf(HEADING);
const sectionEnd = security.indexOf('\n## ', sectionStart + HEADING.length);
const atRest = security
  .slice(sectionStart, sectionEnd === -1 ? undefined : sectionEnd)
  .replace(/\s+/g, ' ');

// `aka.db-wal` → `-wal`: the suffix the prose names, taken from the code that
// creates and tightens the set.
const SIDECAR_SUFFIXES = dbSidecars(DB_FILENAME).map((path) => path.slice(DB_FILENAME.length));

const octal = (mode: number): string => `0${mode.toString(8)}`;

describe('SECURITY.md "Data at rest"', () => {
  it('has the section the rest of these assertions read', () => {
    expect(sectionStart).toBeGreaterThanOrEqual(0);
  });

  it.each(SIDECAR_SUFFIXES)('names the %s sidecar', (suffix) => {
    expect(atRest).toContain(suffix);
  });

  // Naming a sidecar is not the same as saying when it turns up. `-journal`
  // appears only where WAL is unavailable, which is the part a reader auditing a
  // WSL or network-mounted home has to know to look for.
  it('says when the rollback journal replaces the WAL pair', () => {
    expect(atRest).toMatch(/rollback journal/i);
    expect(atRest).toMatch(/WAL is unavailable/i);
  });

  it.each([
    ['directory', DATA_DIR_MODE],
    ['file', DATA_FILE_MODE],
  ])('names the %s mode the code applies', (_label, mode) => {
    expect(atRest).toContain(octal(mode));
  });

  it('names the store file and the three directories it spans', () => {
    expect(atRest).toContain(DB_FILENAME);
    for (const dir of ['~/.aka', '~/.aka/data', '~/.aka/settings']) {
      expect(atRest).toContain(dir);
    }
  });

  // The modes are the whole control, and Node cannot apply them on Windows.
  // Silence there reads as coverage, which is the one answer that would put a
  // user wrong about their own machine.
  it('still states that the modes are the only control and are a no-op on Windows', () => {
    expect(atRest).toMatch(/only at-rest control/i);
    expect(security).toMatch(/no-op on Windows/i);
  });
});

// Every shipped front door. All three describe the same local store, and a
// reader who meets `~/.aka` on one of them should be one link from what protects
// it. The plugin and CLI pages are published to npm, where a relative link does
// not resolve, so they carry the absolute URL — the regex accepts either form.
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

  it('links SECURITY.md from the same page', () => {
    expect(text).toMatch(/]\((?:[^)]*\/)?SECURITY\.md(?:#[^)]*)?\)/);
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
