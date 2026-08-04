import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Reads the conventions doc so a guard can assert against the TABLE a
// contributor edits, not against a second copy of it kept in a test. A guard
// that mirrors prose goes green whichever copy drifts; one that parses it can
// only go green while the prose is true.
//
// Every function here THROWS rather than returning an empty result. That is the
// point: a parser that yields `[]` for a section it could not find turns every
// assertion downstream into a vacuous pass, which is the failure mode this whole
// family of guards exists to remove. `claude-md.test.js` drives each throw.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');

/** Path of the conventions doc, relative to the repo root. */
export const CONVENTIONS_DOC = 'CLAUDE.md';

/** The conventions doc's text. Throws if it is missing or empty. */
export function readConventions() {
  const path = join(REPO_ROOT, CONVENTIONS_DOC);
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (cause) {
    throw new Error(`Could not read ${CONVENTIONS_DOC} at ${path}.`, { cause });
  }
  if (text.trim() === '') throw new Error(`${CONVENTIONS_DOC} is empty.`);
  return text;
}

/**
 * The text under `heading`, up to the next heading of the same or a higher
 * level. Throws unless the heading line occurs EXACTLY once: a repeated anchor
 * silently widens the slice to whatever the second occurrence bounds, so a guard
 * that meant to read one section ends up reading a different one and still
 * passes.
 * @param {string} md the whole document
 * @param {string} heading the full heading line, e.g. '### 4. No network calls'
 */
export function sectionOf(md, heading) {
  const lines = md.split('\n');
  const at = lines.reduce((hits, line, i) => (line === heading ? [...hits, i] : hits), []);
  if (at.length !== 1) {
    throw new Error(
      `${CONVENTIONS_DOC}: expected exactly one ${JSON.stringify(heading)} heading, found ` +
        `${at.length}. A guard that slices on a non-unique anchor reads the wrong section.`,
    );
  }
  const level = /^#+/.exec(heading)?.[0].length ?? 0;
  const boundary = new RegExp(`^#{1,${level}} `);
  const start = at[0];
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => boundary.test(line));
  return (end === -1 ? rest : rest.slice(0, end)).join('\n');
}

/** A markdown table row's cells. Splits on unescaped pipes only. */
function cellsOf(line) {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split(/(?<!\\)\|/)
    .map((cell) => cell.trim());
}

const isRow = (line) => line.trim().startsWith('|');
const isSeparator = (line) => /^\|[\s:|-]+\|$/.test(line.trim());

/**
 * The body rows of the one table in `section` whose header equals `header`.
 *
 * Selected by header rather than by position because a section can carry more
 * than one table — §4 holds both the opt-out table and the three-gates table —
 * so "the first table" would quietly follow whichever one moved to the top.
 * Throws unless exactly one table matches and it has at least one body row.
 * @param {string} section text to search
 * @param {string[]} header the header cells to match, in order
 * @returns {string[][]} one array of cells per body row
 */
export function tableOf(section, header) {
  const lines = section.split('\n');
  /** @type {string[][][]} */
  const runs = [];
  for (const line of lines) {
    if (!isRow(line)) {
      if (runs.length && runs.at(-1).length) runs.push([]);
      continue;
    }
    if (!runs.length) runs.push([]);
    runs.at(-1).push(cellsOf(line));
  }

  const want = JSON.stringify(header);
  const matches = runs.filter((run) => run.length >= 2 && JSON.stringify(run[0]) === want);
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one table with header ${want}, found ${matches.length}. ` +
        (matches.length === 0
          ? 'The table was renamed, reshaped or deleted — the guard reading it would otherwise ' +
            'pass on an empty match.'
          : 'Two tables share a header, so the guard cannot tell which one it is asserting on.'),
    );
  }

  const [head, separator, ...body] = matches[0];
  if (!isSeparator(`|${separator.join('|')}|`)) {
    throw new Error(`Table ${want} has no separator row, so its first data row was read as one.`);
  }
  if (body.length === 0) throw new Error(`Table ${want} has no body rows.`);
  const wrong = body.filter((row) => row.length !== head.length);
  if (wrong.length) {
    throw new Error(
      `Table ${want} has ${wrong.length} row(s) whose cell count differs from its ${head.length}-` +
        'column header, so a column is being read out of the wrong cell.',
    );
  }
  return body;
}

/** The backticked code spans in a cell, in order. */
export function codeSpansOf(cell) {
  return [...cell.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
}

// Written out rather than pulled from Intl: the doc spells these in prose, and a
// locale-dependent list would make the guard's expectation depend on the runner.
const CARDINALS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'];
const ORDINALS = [
  'zeroth',
  'first',
  'second',
  'third',
  'fourth',
  'fifth',
  'sixth',
  'seventh',
  'eighth',
  'ninth',
];

/** The English word for `n`. Throws past the list rather than returning undefined. */
function wordFor(words, n, kind) {
  if (!Number.isInteger(n) || n < 0 || n >= words.length) {
    throw new Error(
      `No ${kind} word for ${n}. Extend the list in claude-md.js — returning undefined here ` +
        'would compare against undefined and pass.',
    );
  }
  return words[n];
}

export const cardinalFor = (n) => wordFor(CARDINALS, n, 'cardinal');
export const ordinalFor = (n) => wordFor(ORDINALS, n, 'ordinal');

/**
 * The word `pattern` captures in `text`, lower-cased. `pattern` must capture one
 * group and match exactly once — a sentence that was deleted or duplicated is a
 * finding, not something to read past.
 * @param {string} text
 * @param {RegExp} pattern global-flagged, with one capture group
 * @param {string} label what the sentence claims, for the failure message
 */
export function countWordIn(text, pattern, label) {
  const found = [...text.matchAll(pattern)];
  if (found.length !== 1) {
    throw new Error(
      `Expected exactly one sentence matching ${pattern} (${label}), found ${found.length}. ` +
        'The sentence that states the count was reworded, removed or duplicated.',
    );
  }
  return found[0][1].toLowerCase();
}
