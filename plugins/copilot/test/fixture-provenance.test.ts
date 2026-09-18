/**
 * The fixture directories are evidence of two different kinds, and the whole
 * value of the distinction is that a reader can tell them apart without asking.
 *
 * `fixtures/cli/` is **recordings** — bytes a real Copilot CLI 1.0.83 session
 * handed to a real hook's stdin. `fixtures/vscode-provisional/` is
 * **doc-derived** — nobody has run the VS Code half, and every capability claim
 * built on it is marked unverified.
 *
 * The failure this guards is a doc-derived specimen being dropped into `cli/`,
 * at which point it reads as a recording and every claim resting on it silently
 * upgrades from "believed" to "observed". That cannot be caught by looking at
 * the JSON, which is identical in either case. What CAN be caught is the
 * paperwork: a recording is only a recording if the README beside it says how
 * it was captured, and this suite holds every file in `cli/` to having a
 * paragraph of its own.
 *
 * The opposite direction is guarded too — the provisional README has to keep
 * saying, in as many words, that nothing in it was recorded — because that
 * sentence is the only thing standing between a placeholder and a fact.
 */
import { readdirSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const CLI_DIR = new URL('./fixtures/cli/', import.meta.url);
const PROVISIONAL_DIR = new URL('./fixtures/vscode-provisional/', import.meta.url);

/** The `.json` basenames in a fixture directory, without their extension. */
function fixtureNames(dir: URL): string[] {
  return readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .map((name) => name.replace(/\.json$/u, ''))
    .sort();
}

const readmeOf = (dir: URL): string => readFileSync(new URL('README.md', dir), 'utf8');

const CLI_README = readmeOf(CLI_DIR);
const PROVISIONAL_README = readmeOf(PROVISIONAL_DIR);

describe('fixtures/cli — recordings, each described by the README beside them', () => {
  it('has recordings to describe', () => {
    // The positive control. Every assertion below loops over this list, and all
    // of them pass on an empty directory.
    expect(fixtureNames(CLI_DIR).length).toBeGreaterThan(0);
  });

  it('describes every recording by name somewhere in the README', () => {
    // Deliberately a mention rather than a section: the README groups events
    // (the four "not recorded here" ones are listed together, the prompt pair
    // is discussed as a pair), and a per-file heading rule would force a shape
    // on prose that is better as prose. What it cannot do is stay silent about
    // a file — which is exactly what a fixture moved across from the
    // provisional directory would do.
    const undescribed = fixtureNames(CLI_DIR).filter((name) => !CLI_README.includes(name));
    expect(undescribed).toEqual([]);
  });

  it('states the build and the session the recordings came from', () => {
    // Without a version the recordings describe no particular host, and
    // "recorded" stops meaning anything checkable.
    expect(CLI_README).toMatch(/1\.0\.83/u);
    expect(CLI_README).toMatch(/recorded/iu);
  });

  it('carries no file that the provisional directory also carries', () => {
    // A doc-derived specimen moved rather than copied would leave no trace in
    // the provisional directory at all, so this is not the whole guard — the
    // README case above is. This catches the sloppier half: the same event
    // appearing in both places, where a reader has no way to tell which one an
    // assertion is driving.
    const overlap = fixtureNames(CLI_DIR).filter((name) =>
      fixtureNames(PROVISIONAL_DIR).includes(name),
    );
    expect(overlap).toEqual([]);
  });
});

describe('fixtures/vscode-provisional — doc-derived, and saying so', () => {
  it('has provisional fixtures', () => {
    expect(fixtureNames(PROVISIONAL_DIR).length).toBeGreaterThan(0);
  });

  it('says plainly that no live session produced them', () => {
    // The sentence the whole separation rests on. A README that lost it would
    // leave eight files that look exactly like the recordings next door.
    expect(PROVISIONAL_README).toMatch(/No live VS Code session produced any file/u);
  });

  it('names the vendor sources it was written from', () => {
    expect(PROVISIONAL_README).toMatch(/code\.visualstudio\.com/u);
  });

  it('lists the fields whose presence, casing or type is unverified', () => {
    // Enumerated rather than waved at: the list is the scope of what a live
    // recording would settle, and each entry names a field a reader can check.
    for (const field of ['session_id', 'cwd', 'transcript_path', 'tool_input', 'tool_response']) {
      expect(PROVISIONAL_README, field).toContain(field);
    }
  });

  it('carries one file per VS Code event this build accepts', async () => {
    // Held to the vocabulary rather than to a list retyped here, so an event
    // added to the adapter without a fixture is a gap that reports itself.
    const { VSCODE_EVENTS } = await import('../src/hooks/event-name.ts');
    expect(fixtureNames(PROVISIONAL_DIR)).toEqual([...VSCODE_EVENTS].sort());
  });
});
