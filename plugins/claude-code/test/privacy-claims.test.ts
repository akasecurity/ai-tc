/**
 * The READMEs are product surface: their privacy claims get quoted into security
 * reviews and procurement answers long after anyone reads the footnote. Both make
 * a locality claim about data, and both are qualified by an `[^egress]` footnote
 * because one path — the opt-in `/aka:setup` judge — really does send raw
 * findings to the model API.
 *
 * These guards keep the claim and the qualifier from drifting apart: an absolute
 * "nothing leaves" sentence must not stand on its own, and the footnote that
 * carries the correction must keep naming the whole payload.
 */
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const READMES = [
  { name: 'README.md', text: readFileSync(new URL('../../../README.md', import.meta.url), 'utf8') },
  {
    name: 'plugins/claude-code/README.md',
    text: readFileSync(new URL('../README.md', import.meta.url), 'utf8'),
  },
] as const;

// A footnote definition line — the place the correction lives. Everything else is
// body prose a reader (or a quoter) sees first.
const isFootnoteDefinition = (line: string): boolean => /^\[\^[^\]]+]:/.test(line);

// Claims that data does not go anywhere. Each one needs its qualifier attached.
const LOCALITY_CLAIM =
  /nothing (?:leaves|is sent)|never (?:leaves|send)|not sent to a model|no scanning happens off|scanned off your/i;

const paragraphs = (text: string): string[] =>
  text
    .split(/\n{2,}/)
    .filter((p) => !p.split('\n').every(isFootnoteDefinition))
    .filter((p) => p.trim() !== '');

describe.each(READMES)('$name privacy claims', ({ text }) => {
  it('attaches the egress footnote to every locality claim in the body', () => {
    const unqualified = paragraphs(text).filter(
      (p) => LOCALITY_CLAIM.test(p) && !p.includes('[^egress]'),
    );
    expect(unqualified).toEqual([]);
  });

  // A footnote marker is a superscript link to the bottom of the page. It is not
  // enough on its own to carry a claim the calibration path contradicts outright,
  // so the exception has to be readable without following the link.
  it('names the exception inline, not only in the footnote', () => {
    const body = paragraphs(text)
      .filter((p) => LOCALITY_CLAIM.test(p))
      .join('\n');
    expect(body).toMatch(/\/aka:setup|calibration|scanned/i);
  });

  const footnote = text.split('\n').filter(isFootnoteDefinition).join(' ').replace(/\s+/g, ' ');

  it('has an egress footnote', () => {
    expect(footnote).toContain('[^egress]:');
  });

  it('says the judge reaches the model API', () => {
    expect(footnote).toMatch(/model API/);
    expect(footnote).toMatch(/opt.?in/i);
  });

  // The whole TriageHit crosses — rawMatch, a ±120-char context window, and the
  // source transcript's path (see src/history/scan.ts). Copy that names only the
  // secret understates what the user is consenting to.
  it('names the whole payload, not just the secret', () => {
    expect(footnote).toMatch(/secret/i);
    expect(footnote).toMatch(/120 characters of the surrounding transcript text/);
    expect(footnote).toMatch(/path of the transcript file/);
  });

  it('does not present withdrawal as a recall of what was already sent', () => {
    expect(footnote).toMatch(/cannot be recalled|cannot recall/i);
  });

  // No lint rule bans `fetch` today (engineering#5) — the ban is a convention
  // enforced by review. Claiming enforcement the CI does not provide is the same
  // overclaim this footnote exists to retire.
  it('does not claim `fetch` is enforced by tooling', () => {
    expect(text).not.toMatch(/`?fetch`? is banned/i);
    expect(text).not.toMatch(/`?fetch`? is blocked/i);
  });
});
