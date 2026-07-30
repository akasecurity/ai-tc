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

import { TriageHit } from '@akasecurity/schema';
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

  // The minimized payload crosses — rawMatch plus a ±120-char context window
  // (toJudgePayload drops filePath/valueFingerprint/keyVersion before egress).
  // Copy that names only the secret understates what the user is consenting to;
  // copy that still names the file path overstates it (the path no longer crosses).
  it('names the whole payload, not just the secret', () => {
    expect(footnote).toMatch(/secret/i);
    // `on either side` is load-bearing: CONTEXT_RADIUS is applied to BOTH ends of
    // the span (history/scan.ts), so ~240 characters cross. Without the qualifier
    // this assertion stays green on copy that halves the window — the same
    // containment-not-truth shape tightened on the other surfaces.
    expect(footnote).toMatch(/120 characters of the surrounding transcript text on either side/);
    expect(footnote).not.toMatch(/path of the transcript file/);
  });

  it('does not present withdrawal as a recall of what was already sent', () => {
    expect(footnote).toMatch(/cannot be recalled|cannot recall/i);
  });

  // Reading the history and sending what it found are two separate grants, and
  // the judge checks the second one on every run. A footnote that says "after you
  // opt in" describes a single gate and understates the protection the product
  // actually ships — the reader cannot tell that declining the send still leaves
  // the local scan working.
  it('names both opt-ins and that the judge will not run without the second', () => {
    expect(footnote).toMatch(/two\*{0,2} separate opt-ins/i);
    expect(footnote).toMatch(/without (?:that|the) second/i);
  });

  // Derived from the schema rather than pinned to a phrase. `toJudgePayload` is
  // disclosed-by-default — `{ ...hit }` minus three deletes — so a new TriageHit
  // field crosses to the model API with no code edit. judge.test.ts's
  // classification case is the only other exhaustiveness guard, and a one-line
  // append to its DISCLOSED list silences it without moving any copy assertion.
  // This table is what makes a widened payload red on the footnote until the
  // footnote names it, which is what CLAUDE.md §4 promises.
  //
  // Copied per suite rather than shared: these surfaces sit behind different
  // package walls and word the same field differently, the same reason
  // expectNoEchoOf is copied rather than imported (CLAUDE.md, Testing).
  const FOOTNOTE_DISCLOSURE: Record<keyof typeof TriageHit.shape, RegExp | null> = {
    // "raw unmasked value" (root README) / "raw (unmasked) value" (plugin README).
    rawMatch: /raw \(?unmasked\)? value/i,
    context: /transcript text on either side/i,
    ruleId: /\brule\b/i,
    category: /category/i,
    severity: /severity/i,
    maskedMatch: /masked value/i,
    confidence: /confidence/i,
    id: /counter/i,
    // Dropped by toJudgePayload before egress — nothing to disclose.
    filePath: null,
    valueFingerprint: null,
    keyVersion: null,
  };

  it('classifies every TriageHit field as named-in-the-footnote or dropped', () => {
    expect(Object.keys(FOOTNOTE_DISCLOSURE).sort()).toEqual(Object.keys(TriageHit.shape).sort());
  });

  it.each(Object.entries(FOOTNOTE_DISCLOSURE).filter((e): e is [string, RegExp] => e[1] !== null))(
    'names the disclosed field %s',
    (_field, pattern) => {
      expect(footnote).toMatch(pattern);
    },
  );

  // A lint rule DOES ban `fetch` now (`no-restricted-globals` and friends in
  // packages/eslint-config, documented in CLAUDE.md §4), so this is no longer the
  // false claim it once was. The guard stays for a different reason: nothing ties
  // README prose to that config, so an enforcement claim here would silently
  // outlive the rule that justified it. The footnote describes what the source
  // does — "the source uses no `fetch`" — which the reader can check.
  it('does not claim `fetch` is enforced by tooling', () => {
    expect(text).not.toMatch(/`?fetch`? is banned/i);
    expect(text).not.toMatch(/`?fetch`? is blocked/i);
  });
});

// CLAUDE.md §4 counts the `aka <name>` dispatch as a fourth child-process path,
// and it is one — but it is not a fourth path AKA takes. The CLI execs a program
// the user installed and named, so folding it into the footnote's count would
// imply ai-tc sends something it does not, while omitting it entirely leaves the
// footnote's "all through child processes" reading as a complete list when it is
// not. The copy does both halves: it names the dispatch and holds it outside the
// count. Neither half works alone, so both are pinned here.
//
// Root README only — the dispatch is a CLI feature, and the plugin README
// describes the plugin.
describe('README.md aka-<name> dispatch disclosure', () => {
  const footnote = READMES[0].text
    .split('\n')
    .filter(isFootnoteDefinition)
    .join(' ')
    .replace(/\s+/g, ' ');

  it('names the dispatch without folding it into the three-path count', () => {
    expect(footnote).toMatch(/Three narrow paths/);
    expect(footnote).toMatch(/aka-<name>/);
    expect(footnote).toMatch(/not one of the three/i);
  });

  // The whole point of naming it is that its behaviour is undescribable from
  // here. Copy that characterized the child would be asserting something this
  // repo cannot check.
  it('disclaims knowledge of what the dispatched program does', () => {
    expect(footnote).toMatch(/does not bundle, pin or verify it/i);
  });
});
