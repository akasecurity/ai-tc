/**
 * The capability matrix is code, and `skills/setup/SKILL.md` renders it. This
 * holds the two to each other.
 *
 * The reason is the failure mode a "Known limitations" section has: it is prose
 * about what software cannot do, written once and read by people deciding
 * whether to trust it. Nothing about it changes when the software does, so it
 * decays in the one direction that matters — a limitation that has been lifted
 * reads as caution, while a capability that was never wired reads as coverage.
 *
 * So the table is generated from `CAPABILITY_MATRIX` and compared row for row.
 * The prose ABOVE the table is not generated, because it carries argument
 * rather than data — but the claims in it that the matrix can check are checked.
 */
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import type { Capability } from '../src/capabilities.ts';
import {
  capabilitiesFor,
  CAPABILITY_MATRIX,
  surfaceIsVerified,
  SURFACES,
} from '../src/capabilities.ts';

const SKILL = readFileSync(new URL('../skills/setup/SKILL.md', import.meta.url), 'utf8');

/**
 * One matrix row as CELLS rather than as a line.
 *
 * Prettier owns this file's formatting and pads the columns to the widest cell,
 * so a line-for-line comparison would pin today's column widths — and would go
 * red on a reflow that changed no claim at all. The cells are the content.
 */
const renderRow = (r: Capability): string[] => [
  r.surface,
  r.event,
  r.subject,
  r.channel,
  r.verified ? 'yes' : 'no',
  r.note,
];

/** A rendered table line, split back into its cells. */
const cellsOf = (line: string): string[] =>
  line
    .replace(/^\||\|$/gu, '')
    .split('|')
    .map((cell) => cell.trim());

/** The body rows of the rendered table, in file order. */
function tableRows(): string[][] {
  const lines = SKILL.split('\n');
  const header = lines.findIndex((line) => cellsOf(line)[0] === 'Surface');
  if (header === -1) throw new Error('SKILL.md: the capability table header is missing');
  const rest = lines.slice(header + 2);
  const end = rest.findIndex((line) => !line.startsWith('|'));
  return (end === -1 ? rest : rest.slice(0, end)).filter((line) => line.trim() !== '').map(cellsOf);
}

describe('the capability matrix and the SKILL.md that renders it', () => {
  it('has rows to render', () => {
    // The positive control. The row-for-row comparison below passes on two
    // empty lists, which is exactly the state a deleted table produces.
    expect(CAPABILITY_MATRIX.length).toBeGreaterThan(0);
    expect(tableRows().length).toBeGreaterThan(0);
  });

  it('renders every row, in order, with nothing extra', () => {
    // In ORDER rather than as a set: the table groups by surface and a reader
    // uses that grouping, so a row that drifted into another surface's block
    // would be a set-equal table that reads wrong.
    expect(tableRows()).toEqual(CAPABILITY_MATRIX.map(renderRow));
  });

  it('covers every surface the matrix declares', () => {
    for (const surface of SURFACES) {
      expect(capabilitiesFor(surface).length, surface).toBeGreaterThan(0);
    }
  });

  it('keeps every VS Code row unverified, and says so in the prose', () => {
    // The claim the whole doc-derived half rests on. Two halves: the data says
    // it, and the prose says it — because a reader who trusts the table has
    // already read the paragraph above it.
    expect(capabilitiesFor('vscode').every((row) => !row.verified)).toBe(true);
    expect(surfaceIsVerified('vscode')).toBe(false);
    expect(SKILL).toMatch(/confirmed against no live install/u);
  });

  it('keeps the CLI surface verified, so the column is not decorative', () => {
    // The control on the column. With nothing verified anywhere, `verified`
    // would be a constant and every assertion about it would hold trivially.
    expect(surfaceIsVerified('cli')).toBe(true);
  });

  it('says in prose that only the pre-tool-use event ENFORCES, and the matrix agrees', () => {
    // A cross-check rather than a restatement: the prose claim is falsifiable
    // against the data, so giving a second event a channel without touching
    // this section fails here.
    //
    // The sentence used to read "is wired", which was true while `preToolUse`
    // was the only registration and became false the moment the capture hooks
    // landed — the exact decay this file exists to catch. WIRED and ENFORCING
    // are now different questions, and the matrix can only answer the second:
    // `channel` says what can be done about a finding, so a captured-only event
    // is `none` exactly like an unwired one. Registration is what
    // `hooks-manifest.test.ts` holds.
    expect(SKILL).toMatch(/Only the pre-tool-use event ENFORCES/u);
    const acting = CAPABILITY_MATRIX.filter((row) => row.channel !== 'none');
    expect(acting.length).toBeGreaterThan(0);
    expect([...new Set(acting.map((row) => row.event.toLowerCase()))]).toEqual(['pretooluse']);
  });

  it('says in prose that prompts and tool results are captured but cannot be withheld', () => {
    // The other half of the sentence above, and the one a reader acts on: an
    // event with `channel: 'none'` is either unwired or capture-only, and those
    // mean opposite things about whether a secret shows up as a finding. The
    // matrix cannot tell them apart on the channel alone, so the NOTE is what
    // carries it and the note is what is checked.
    expect(SKILL).toMatch(/are\*\* captured, scanned and recorded/u);
    expect(SKILL).toMatch(/neither can be withheld or masked/u);

    const capturing = CAPABILITY_MATRIX.filter((row) =>
      /userpromptsubmit|posttooluse/u.test(row.event.toLowerCase()),
    );
    // The positive control: without it the loop below runs zero times.
    expect(capturing.length).toBeGreaterThan(0);
    for (const row of capturing) {
      expect(row.channel, `${row.surface}/${row.event}`).toBe('none');
      expect(row.note, `${row.surface}/${row.event}`).toMatch(/Captured and scanned/u);
    }
  });

  it('still says there is no history backfill, which remains unimplemented', () => {
    expect(SKILL).toMatch(/no history backfill/u);
  });

  it('says in prose that command text is never masked in place', () => {
    // And the matrix has no row claiming otherwise: a `rewrite` channel on a
    // command field would contradict the sentence a user is being asked to
    // trust.
    expect(SKILL).toMatch(/Command text is never masked in place/u);
    const rewritingCommands = CAPABILITY_MATRIX.filter(
      (row) => row.channel === 'rewrite' && /\bcommand\b/u.test(row.subject),
    );
    expect(rewritingCommands).toEqual([]);
  });

  it('does not promise a calibration wizard this adapter has not wired', () => {
    // The other direction of the same honesty rule, and the one a copied
    // sibling SKILL.md would break first: the other three plugins run a full
    // calibration flow from this skill and this one does not.
    expect(SKILL).toMatch(/calibration wizard is not wired on this host yet/u);
  });
});
