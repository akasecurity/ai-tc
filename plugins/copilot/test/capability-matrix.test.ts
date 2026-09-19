/**
 * The capability matrix is the artifact; `skills/setup/SKILL.md`'s Known
 * limitations is derived from it. This holds the two together.
 *
 * WHY IT IS WORTH A GUARD AT ALL. Every other host in this repository has one
 * hook contract, so its limits can live in prose and stay true. This package
 * covers two hosts whose contracts differ, and one of the two has never been
 * observed — so the document decays in the one direction that matters: a
 * limitation stops reading as a limitation once it has been shipping a while,
 * and an unverified row stops reading as unverified.
 *
 * Both directions are checked, because they fail differently. A matrix row with
 * no sentence is a limit nobody was told about; a sentence with no row is a
 * claim about a surface that has changed underneath it.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { Capability } from '../src/capabilities.ts';
import { CAPABILITY_MATRIX, surfaces, unverified } from '../src/capabilities.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const SKILL = join(HERE, '..', 'skills', 'setup', 'SKILL.md');
const doc = readFileSync(SKILL, 'utf8');

/** The Known limitations section, so a match elsewhere in the file is not one. */
function knownLimitations(): string {
  const start = doc.indexOf('## Known limitations');
  expect(start, 'SKILL.md has no "## Known limitations" section').toBeGreaterThan(-1);
  return doc.slice(start);
}

/** Every markdown table row in the section, as its trimmed cells. */
function tableRows(): string[][] {
  return knownLimitations()
    .split('\n')
    .filter((line) => line.startsWith('|'))
    .map((line) =>
      line
        .slice(1, line.endsWith('|') ? -1 : undefined)
        .split('|')
        .map((cell) => cell.trim()),
    )
    .filter((cells) => cells.length === 5 && !/^-+$/.test(cells[0] ?? ''))
    .filter((cells) => cells[0] !== 'Surface');
}

function rowKey(row: Capability): string {
  return [row.surface, row.event, row.subject, row.channel, row.verified ? 'yes' : 'no'].join(
    ' | ',
  );
}

/**
 * The document's apostrophes are typographic and the matrix's are ASCII, which
 * is a difference about typesetting rather than about meaning. Normalised here
 * so the guard fails on a changed CLAIM and not on a changed quote mark.
 */
function normalize(text: string): string {
  return text.replaceAll('’', "'").trim();
}

/**
 * The same, plus every run of whitespace collapsed to one space.
 *
 * The prose is hard-wrapped and list-indented, so a sentence that reads as one
 * line in the matrix is three lines with leading spaces in the document. Only
 * the CLAIM is being compared, so the wrapping has to stop mattering — without
 * this the guard would fail on a reflow and reward writing the file unwrapped.
 */
function collapse(text: string): string {
  return normalize(text).replace(/\s+/g, ' ');
}

describe('the capability matrix and SKILL.md', () => {
  it('has rows to check at all', () => {
    // The positive control. Every case below iterates one of the two, so an
    // empty matrix or an empty table would satisfy them for free.
    expect(CAPABILITY_MATRIX.length).toBeGreaterThan(0);
    expect(tableRows().length).toBeGreaterThan(0);
  });

  it('agrees row for row, in both directions', () => {
    const fromMatrix = CAPABILITY_MATRIX.map(rowKey).sort();
    const fromDoc = tableRows()
      .map((cells) => normalize(cells.join(' | ')))
      .sort();
    expect(fromDoc).toEqual(fromMatrix.map(normalize));
  });

  /**
   * The table says WHAT; the prose beneath says why. A row whose sentence never
   * made it into the document is the limitation nobody was actually told about,
   * which is the failure mode the table alone cannot catch — a one-word cell
   * reading `none` explains nothing.
   */
  it('carries every row’s sentence in the prose beneath the table', () => {
    const section = collapse(knownLimitations());
    for (const row of CAPABILITY_MATRIX) {
      expect(section, `${row.surface}/${row.event} (${row.subject})`).toContain(collapse(row.note));
    }
  });

  /**
   * The `verified` column is the whole reason this matrix is typed rather than
   * written out, so the document has to say, in its own words, that some of it
   * is unverified — not merely carry `no` in a cell somebody may not read as a
   * warning.
   */
  it('says plainly that the unverified rows have never been seen working', () => {
    expect(unverified().length).toBeGreaterThan(0);
    const section = knownLimitations();
    expect(section).toContain('no live VS Code session has produced a payload');
    expect(section).toContain('never been seen working');
  });

  /**
   * The cloud surface is absent from the matrix on purpose — no hook runs
   * there — and an absence is exactly the kind of fact a reader supplies from
   * memory. So the document must state it, and the matrix must keep it true.
   */
  it('keeps the cloud surface out of the matrix, and says why in the document', () => {
    expect(surfaces()).toEqual(['cli', 'vscode']);
    expect(knownLimitations()).toContain('The cloud coding agent is not covered');
  });

  /**
   * The skill must not read as the guided calibration wizard the other three
   * plugins ship. Nothing here reads Copilot session history, so a wizard that
   * proposed a posture would be proposing it from nothing.
   */
  it('does not claim a calibration flow this host has not got', () => {
    expect(doc).toContain('does not yet ship the guided calibration flow');
  });
});
