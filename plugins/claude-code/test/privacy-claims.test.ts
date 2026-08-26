/**
 * The READMEs are product surface: their privacy claims get quoted into security
 * reviews and procurement answers long after anyone reads the footnote. Each one
 * makes a locality claim about data, and each is qualified by an `[^egress]`
 * footnote because some path really does reach the network.
 *
 * These guards keep the claim and the qualifier from drifting apart: an absolute
 * "nothing leaves" sentence must not stand on its own, and the footnote that
 * carries the correction must keep naming what crosses.
 *
 * Two tiers, because the pages do not make the same claim. Every front door
 * carries the locality claim and so owes a footnote; only the pages that
 * describe the `/aka:setup` judge owe the payload disclosure, since the judge is
 * plugin surface and the CLI ships no judge. Folding the CLI page into one tier
 * would demand it describe a `TriageHit` it never sends — copy that overstates
 * what a reader is consenting to is its own kind of wrong answer.
 *
 * Which files are covered is DERIVED from the tree rather than listed. A
 * hand-written list is what let `cli/README.md` carry an unqualified
 * "nothing leaves your computer" for as long as it did: the page was not
 * unguarded by decision, it was unguarded because nobody added it.
 *
 * That derivation lives in packages/eslint-config/test/privacy-claim-coverage.test.js,
 * NOT here, and the reason is turbo's cache rather than tidiness: this task's
 * `inputs` hash only two READMEs, so a new front door elsewhere in the tree
 * left this package's hash byte-identical and CI replayed a cached pass. Only
 * that task's inputs hash the whole workspace. The list below stays here
 * because the TIER split is this suite's own business; the guard over there
 * reads it.
 *
 * Two other guards read these same files and can redden on the same edit:
 * packages/persistence/test/at-rest-docs.test.ts covers the at-rest posture and
 * the SECURITY.md link, and cli/test/privacy-claims.test.ts covers the CLI
 * footnote's own disclosures, which derive from the CLI's flags.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

/**
 * One repo-relative posix path, read from the repo root. Rows are addressed by
 * that path and by no other route, so `name` can serve as both the label and
 * the location — a second field holding the path would be free to name one page
 * and read another.
 */
const repoFile = (relative: string): string => readFileSync(join(REPO_ROOT, relative), 'utf8');

// A footnote definition line — the place the correction lives. Everything else is
// body prose a reader (or a quoter) sees first.
const isFootnoteDefinition = (line: string): boolean => /^\[\^[^\]]+]:/.test(line);

// Claims that data does not go anywhere. Each one needs its qualifier attached.
const LOCALITY_CLAIM =
  /nothing (?:leaves|is sent)|never (?:leaves|send)|not sent to a model|no scanning happens off|scanned off your/i;

// Every footnote definition on a page, whitespace-normalized into one string —
// the correction, as a reader following the marker would meet it. One helper
// because three call sites want it; three copies would be free to normalize
// differently while every assertion still passed.
const footnoteOf = (text: string): string =>
  text.split('\n').filter(isFootnoteDefinition).join(' ').replace(/\s+/g, ' ');

/**
 * Body paragraphs — everything a reader (or a quoter) meets before the footnote.
 *
 * `.trim()` before the split is load-bearing, and is the same fix the CLI copy
 * carries: a footnote paragraph at the END of a page keeps the file's trailing
 * newline, so it splits to `['[^egress]: …', '']`, `.every()` is false, the
 * negation keeps it, and the correction is classified as body prose. Moving a
 * footnote to the bottom of a page is a pure formatting edit, so nothing would
 * warn that it had turned `names the exception inline` into a case the footnote
 * satisfies by itself.
 */
const paragraphs = (text: string): string[] =>
  text
    .split(/\n{2,}/)
    .filter((p) => !p.trim().split('\n').every(isFootnoteDefinition))
    .filter((p) => p.trim() !== '');

/**
 * Every shipped front door, and whether it describes the judge.
 *
 * `describesJudge` is the tier split, and it is a property of the page rather
 * than a convenience: the root README introduces the whole product and the
 * plugin README documents the harness that runs `/aka:setup`, so both send a
 * reader into the calibration. The CLI page ships no judge and points at the
 * plugin page for that payload instead.
 */
const CLASSIFIED_READMES = [
  { name: 'README.md', describesJudge: true },
  { name: 'cli/README.md', describesJudge: false },
  { name: 'plugins/claude-code/README.md', describesJudge: true },
] as const;

// `name` IS the location — there is deliberately no second field holding the
// path. Carrying both let them drift: a row could name one page and read
// another, and the coverage case below (which compares names) would keep
// passing while every assertion ran over the wrong file.
const READMES = CLASSIFIED_READMES.map((r) => ({ ...r, text: repoFile(r.name) }));
const JUDGE_READMES = READMES.filter((r) => r.describesJudge);

describe('locality-claim coverage', () => {
  // Both tiers run through `describe.each`, which registers nothing at all for an
  // empty array — so a mis-set flag that empties a tier would delete its cases
  // and report green. Neither count is allowed to reach zero.
  it('leaves neither tier empty', () => {
    expect(READMES.length).toBeGreaterThan(0);
    expect(JUDGE_READMES.length).toBeGreaterThan(0);
  });
});

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

  const footnote = footnoteOf(text);

  it('has an egress footnote', () => {
    expect(footnote).toContain('[^egress]:');
  });

  // A lint rule DOES ban `fetch` now (`no-restricted-globals` and friends in
  // packages/eslint-config, documented in CLAUDE.md §4), so this is no longer the
  // false claim it once was. The guard stays for a different reason: nothing ties
  // README prose to that config, so an enforcement claim here would silently
  // outlive the rule that justified it.
  it('does not claim `fetch` is enforced by tooling', () => {
    expect(text).not.toMatch(/`?fetch`? is banned/i);
    expect(text).not.toMatch(/`?fetch`? is blocked/i);
  });

  /**
   * Every front door once opened by promising the source contained no network
   * client at all. Attached mode retires that product-wide, so it is guarded
   * product-wide rather than per page — the claim's whole failure mode is being
   * carried across a merge on a page nobody thought to re-read.
   *
   * The `fetch` half is banned though it is still LITERALLY TRUE:
   * `@akasecurity/remote` uses `node:https`, so "the source uses no `fetch`"
   * remains accurate — but it sat in these footnotes as the EVIDENCE for "no
   * built-in network client", which is false now. A true sentence doing false
   * work is the worst failure a privacy page has: it survives every fact-check
   * and still leaves the reader believing nothing opens a socket. Name the
   * client instead, as the root footnote does.
   */
  it('does not claim the source contains no network client', () => {
    expect(text).not.toMatch(/no built-in network client/i);
    expect(text).not.toMatch(/the source uses no `?fetch`?/i);
  });
});

describe.each(JUDGE_READMES)('$name judge payload disclosure', ({ text }) => {
  const footnote = footnoteOf(text);

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
// describes the plugin. The CLI page states the same split against its own
// (smaller) count, and cli/test/privacy-claims.test.ts pins that one.
/**
 * Every path by which the shipped product can reach a network, and the marker
 * that proves the root README's footnote names it.
 *
 * An EXACT set, and the source the count word below is derived from. Anything
 * that adds an outbound path adds a row here, which is what makes the count
 * sentence move with the list instead of drifting behind it.
 *
 * This table is why the merge that produced it was survivable. Two branches
 * each added a fourth path from opposite sides — the update notice and the
 * attached control plane — and each shipped a footnote opening "Four narrow
 * paths" that was true of its own branch alone. The union is five. Every
 * literal pin either branch carried would have gone green on a resolution that
 * kept one sentence verbatim above an enumeration of five.
 */
const EGRESS_PATHS = [
  // Passive and default-on: no command, no consent. `npm view` rather than
  // `update notice` as the marker, because the mechanism is what a reader
  // needs — the dedicated case below pins the disclosure words themselves.
  { name: 'update notice', marker: /npm view/, childProcess: true },
  { name: 'package-manager install', marker: /package-manager installs/, childProcess: true },
  { name: 'supply-chain check', marker: /npm audit signatures/, childProcess: true },
  { name: 'setup calibration', marker: /\/aka:setup/, childProcess: true },
  // The first and only path the source itself opens a connection on. Its
  // `childProcess: false` is what makes the sub-count below mean something:
  // every other row is a spawn, and the footnote has to keep saying so.
  { name: 'attached control plane', marker: /aka attach/, childProcess: false },
] as const;

/**
 * Spelled numerals, because the footnote is prose and says "Four" rather than
 * "4".
 *
 * A count with no word here THROWS rather than resolving to `undefined`. That
 * matters: an undefined interpolated into a regex produces `/undefined narrow
 * paths/`, which no footnote matches — so the case would still go red, but for
 * a reason that reads like the prose is wrong when the table is what ran out.
 * On a guard whose whole job is telling somebody which of the two to move, that
 * is the wrong message.
 */
const COUNT_WORDS = ['Zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven'] as const;

function countWord(n: number): string {
  const word = COUNT_WORDS[n];
  if (word === undefined) {
    throw new Error(
      `no spelled numeral for ${String(n)} — extend COUNT_WORDS. The footnote counts its egress ` +
        'paths in prose, so this table has to reach as far as EGRESS_PATHS does.',
    );
  }
  return word;
}

describe('README.md aka-<name> dispatch disclosure', () => {
  const root = READMES.find((r) => r.name === 'README.md');
  const footnote = footnoteOf(root?.text ?? '');

  it('names the dispatch without folding it into the enumerated count', () => {
    // The SEPARATION is the property: the dispatched program is named and
    // excluded from the count, because its behaviour is the one thing on this
    // list nothing in this repo chose.
    expect(footnote).toMatch(/aka-<name>/);
    expect(footnote).toMatch(new RegExp(`not one of the ${countWord(EGRESS_PATHS.length)}`, 'i'));
  });

  // The count word and the paths it counts, checked against EACH OTHER rather
  // than against a literal.
  //
  // `toMatch(/Four narrow paths/)` was what stood here, and a pin like that is
  // WORSE than no guard on a page like this: it goes green whether or not the
  // number describes the list, so the green asserts that somebody checked. The
  // way it breaks is not hypothetical — it is what this file was merged through:
  // two branches each added a fourth path from opposite sides, both shipped a
  // footnote opening "Four narrow paths", and the union is five. A resolution
  // that kept either sentence verbatim would have left the page counting one
  // short with both branches' suites green.
  //
  // So the numeral is DERIVED from the enumeration. Adding a path means adding
  // it to EGRESS_PATHS, and the count sentence then has to move with it or this
  // fails — which is the forcing function a merge resolution needs.
  it('states a count that matches the number of paths it enumerates', () => {
    const word = countWord(EGRESS_PATHS.length);
    expect(
      footnote,
      `the footnote must open by counting the ${String(EGRESS_PATHS.length)} paths in ` +
        'EGRESS_PATHS. If you added or removed one, move the count sentence with it.',
    ).toMatch(new RegExp(`${word} narrow paths`, 'i'));
  });

  it.each(EGRESS_PATHS)('enumerates the $name path', ({ marker }) => {
    // The other half: a count that agrees with a list nobody checked is only
    // half a guarantee. Each path has to be NAMED, so the count cannot be
    // satisfied by a list that quietly lost one.
    expect(footnote).toMatch(marker);
  });

  it('does not claim every path is a child process', () => {
    // True until attached mode, and the sentence that carried it is the one a
    // merge is most likely to keep: `@akasecurity/remote` reaches the network
    // from the source itself, without spawning anything.
    expect(footnote).not.toMatch(/all through child processes/i);
  });

  // The SUB-count, derived the same way, and it closes the direction the total
  // cannot see.
  //
  // A merge that brings in another party's text can add a path to the PROSE
  // without adding a row here, and the total then still agrees with a table
  // that has quietly fallen behind. But every path added so far except attach
  // is a spawn, so text carrying one also carries a claim about how many of
  // them are — and that sentence is checked here against the rows marked
  // `childProcess`. Between the two numerals, prose and table cannot drift
  // apart in either direction without something going red.
  it('states how many of those paths are child processes, and counts them right', () => {
    const spawned = EGRESS_PATHS.filter((p) => p.childProcess).length;
    expect(
      footnote,
      `the footnote must say ${countWord(spawned)} of the paths are child processes — the rows ` +
        'in EGRESS_PATHS marked childProcess. The remainder reach the network from the source.',
    ).toMatch(new RegExp(`${countWord(spawned)} of them are child processes`, 'i'));
  });

  it('says the attached path is opt-in, and names where its client lives', () => {
    // The footnote used to be able to say the source contains no network client
    // at all. It cannot any more, so what replaces that claim has to be exact:
    // one named package may open a socket, and only after a machine has been
    // attached on purpose.
    expect(footnote).toMatch(/aka attach/);
    expect(footnote).toMatch(/@akasecurity\/remote/);
    expect(footnote).toMatch(/opt-in/i);
  });

  // The whole point of naming it is that its behaviour is undescribable from
  // here. Copy that characterized the child would be asserting something this
  // repo cannot check.
  it('disclaims knowledge of what the dispatched program does', () => {
    expect(footnote).toMatch(/does not bundle, pin or verify it/i);
  });

  /**
   * The one path a reader cannot discover by reading the commands they type.
   *
   * This page enumerates and commits to a COUNT, and the count word alone is a
   * weak thing to pin: the enumeration was `npm`/`claude` installs, the plugin's
   * supply-chain check, and the opt-in calibration — every one of them gated
   * behind either a typed command or a granted consent. The passive notice is
   * neither. `main.ts`'s SKIP_NOTICE covers only the update commands themselves,
   * so a bare `aka stats` on a terminal can reach the registry, and this page
   * said nothing about it while cli/README.md described it in full.
   *
   * Pinned here rather than in a general "enumeration is complete" tier, because
   * only the pages that commit to a count owe this, and there are two of them.
   */
  it('discloses the default-on update notice and its opt-out', () => {
    expect(footnote).toMatch(/update notice/i);
    expect(footnote).toMatch(/on by default/i);
    expect(footnote).toMatch(/needs no command/i);
    expect(footnote).toContain('--no-update-check');
  });
});
