/**
 * `cli/README.md` is the npm front page for `@akasecurity/cli` — the page most
 * likely to be read, and quoted into a procurement answer, by someone who never
 * opens the repo. It makes a locality claim, so it owes the same qualifier the
 * other front doors carry.
 *
 * plugins/claude-code/test/privacy-claims.test.ts holds the claims every README
 * makes in common: that a locality claim carries its `[^egress]` footnote, and
 * that the footnote exists at all. It stops there for this page on purpose —
 * the judge is plugin surface, and the CLI ships none, so holding this page to
 * the `TriageHit` disclosure table would demand it describe a payload it never
 * sends.
 *
 * What this file adds is the half only the CLI owes: its footnote has to name
 * the CLI's OWN outbound paths. Those are easy to leave out precisely because
 * they carry no findings — but the update notice is on by default and needs no
 * prompt, which makes it the one path a reader is most likely to be surprised
 * by and the one they cannot discover from the plugin's page.
 */
import { readFileSync } from 'node:fs';

import { gatherReport } from '@akasecurity/local-ops';
import { describe, expect, it } from 'vitest';

import { GLOBAL_FLAGS } from '../src/command-manifest.ts';

/**
 * Every npm package the passive update check looks up, taken from the real
 * report builder rather than named here.
 *
 * `gatherReport` asks `viewVersion` once for the CLI and once per marketplace
 * agent that has both a ref and an npm package, so recording that seam is what
 * the registry actually sees. Derived because the footnote said "this package",
 * singular, while three lookups crossed — and a hand-written list here would
 * have been just as wrong, just as invisibly. `installed` is deliberately EMPTY:
 * the plugin lookups run whether or not the plugin is installed, which is the
 * reason the copy may not say the registry learns what you have.
 */
const LOOKED_UP_PACKAGES: string[] = [];
gatherReport({
  viewVersion: (pkg: string) => {
    LOOKED_UP_PACKAGES.push(pkg);
    return null;
  },
  cliInstalled: null,
  installed: new Map(),
});

const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

const isFootnoteDefinition = (line: string): boolean => /^\[\^[^\]]+]:/.test(line);

const norm = (text: string): string => text.replace(/\s+/g, ' ').trim();

/**
 * Paragraphs are the unit here, not lines. `isFootnoteDefinition` matches only a
 * footnote's OPENING line, so splitting the page by line would count a wrapped
 * footnote's continuation as body prose — and the body assertions below would
 * then be reading the correction as if it were the headline claim.
 */
const PARAGRAPHS = README.split(/\n{2,}/).filter((p) => p.trim() !== '');

/**
 * `.trim()` before the split is load-bearing. A footnote that sits at the END of
 * the page keeps the file's trailing newline, so its paragraph splits to
 * `['[^egress]: …', '']` and a bare `.every(isFootnoteDefinition)` is false —
 * the footnote is then classified as body prose, `footnote` becomes `''`, and
 * most of this file fails with messages about missing copy rather than about the
 * parser, while `body` silently absorbs the correction. Moving the footnote to
 * the bottom of the page is a pure formatting edit, so nothing would have warned
 * that it broke the guard.
 */
const isFootnoteParagraph = (p: string): boolean =>
  p
    .trim()
    .split('\n')
    .every((line) => isFootnoteDefinition(line));

const footnote = norm(
  PARAGRAPHS.filter(isFootnoteParagraph)
    .flatMap((p) => p.split('\n'))
    .filter(isFootnoteDefinition)
    .join(' '),
);

const body = norm(PARAGRAPHS.filter((p) => !isFootnoteParagraph(p)).join('\n'));

/**
 * The paragraph that carries the footnote MARKER — the claim itself, rather
 * than the page it sits on.
 *
 * Asserting against the whole body is what made an earlier version of the
 * inline-exception case below vacuous: `aka plugins` appears in the command
 * table and the install snippet, so the assertion passed whether or not the
 * claim sentence named that exception at all. A claim is inline or it is not,
 * and only the claim's own paragraph can answer that.
 */
const CLAIM = norm(
  PARAGRAPHS.filter((p) => !isFootnoteParagraph(p) && p.includes('[^egress]')).join('\n'),
);

/**
 * The flag comes from the manifest that defines it, not from a literal here.
 * The footnote's whole value on this point is telling a reader what to type, so
 * a flag that gets renamed has to redden the page that promises it rather than
 * leaving the reader with an option `main()` now rejects.
 *
 * Collected rather than `find`-ed: with two update-related flags, `find` pins
 * whichever sorts first and the guard would silently validate a flag the README
 * never promised.
 */
const UPDATE_OPT_OUTS = GLOBAL_FLAGS.filter((flag) => flag.includes('update'));

/**
 * Every path by which the `aka` CLI itself can reach a network, and the marker
 * that proves this page's footnote names it.
 *
 * An EXACT set, and the source of the count word below. The root README carries
 * the same table over the whole product; this one is smaller because the CLI
 * ships no judge, and the two must be allowed to differ — folding them into one
 * list is what would make this page describe a payload it never sends.
 *
 * It exists because the literal that stood here — `toMatch(/Two narrow paths/)`
 * — is worse than no guard at all: it goes green whether or not the number
 * describes the list, so the green asserts somebody checked. That is not a
 * hypothesis. Two branches each added a path from opposite sides, both said
 * "Two", and the union is three; the literal would have passed on a resolution
 * that kept either sentence.
 */
const CLI_EGRESS_PATHS = [
  { name: 'update notice', marker: /npm view/, childProcess: true },
  { name: 'package-manager shell-outs', marker: /aka plugins install/, childProcess: true },
  // The one path where this CLI's own source opens a connection. Its
  // `childProcess: false` is what gives the sub-count below meaning.
  { name: 'attached control plane', marker: /aka attach/, childProcess: false },
] as const;

/**
 * Spelled numerals, because the footnote is prose and counts in words.
 *
 * A count with no word here THROWS rather than resolving to `undefined`: an
 * undefined interpolated into a regex yields `/undefined narrow paths/`, which
 * matches nothing — so the case still reds, but for a reason that reads like the
 * prose is wrong when the table is what ran out.
 */
const COUNT_WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven'] as const;

function countWord(n: number): string {
  const word = COUNT_WORDS[n];
  if (word === undefined) {
    throw new Error(
      `no spelled numeral for ${String(n)} — extend COUNT_WORDS. This page counts in prose, so ` +
        'the table has to reach as far as the thing it counts.',
    );
  }
  return word;
}

describe('cli/README.md CLI-owned egress disclosure', () => {
  it('has the footnote the rest of these assertions read', () => {
    expect(footnote).toContain('[^egress]:');
  });

  // Derived above, so this is the assertion that makes the derivation mean
  // something: with no update-related global flag there is no opt-out to
  // promise, and every check below would be describing a CLI that does not
  // exist. Exactly one, so the footnote's promise is unambiguous.
  it('takes its opt-out flag from the CLI own global flags', () => {
    expect(UPDATE_OPT_OUTS).toHaveLength(1);
  });

  // The claim paragraph is what several assertions below read, and an empty
  // string satisfies every `not.toMatch` on it. A page whose claim lost its
  // footnote marker would empty it, so it is asserted rather than assumed.
  it('has a claim paragraph carrying the footnote marker', () => {
    expect(CLAIM).not.toBe('');
  });

  /**
   * The update notice is the path that separates this page from the plugin's.
   * It runs after a command with no prompt (main.ts gates it on a TTY and on
   * this flag alone), so a footnote that named only the paths a user triggers
   * on purpose would describe the CLI as quieter than it is.
   */
  it('names the update notice, that it is on by default, and how to skip it', () => {
    expect(footnote).toMatch(/update notice/i);
    expect(footnote).toMatch(/npm view/);
    expect(footnote).toMatch(/on by default/i);
    // No `?? ' '` fallback: a footnote trivially contains a space, so that form
    // passed on exactly the broken derivation this assertion exists to catch.
    expect(footnote).toContain(String(UPDATE_OPT_OUTS[0]));
  });

  // The seam has to have produced something, or every derived assertion below
  // holds over an empty list and this whole group goes quietly vacuous.
  it('records the packages the update check really looks up', () => {
    expect(LOOKED_UP_PACKAGES.length).toBeGreaterThan(1);
  });

  /**
   * Every package the lookup asks for has to be named. The footnote used to say
   * `npm view` ran on "this package" — singular — while three packages crossed,
   * and a reader auditing their own egress from that sentence would expect one
   * request naming one package. Derived from `gatherReport`, so a fourth agent
   * gaining an npm package reddens the page until the page names it.
   */
  it.each(LOOKED_UP_PACKAGES)('names %s among the packages looked up', (pkg) => {
    expect(footnote).toContain(pkg);
  });

  /**
   * And the numeral in front of them, which was the one hand-written token left
   * in a sentence whose names are derived.
   *
   * Antigravity already declares an `npmPackage` and withholds only
   * `pluginName`/`marketplace`, so the day it gains a marketplace ref there are
   * four lookups: the `it.each` above reds on the missing NAME, someone adds the
   * name, and "three" silently understates the disclosure on a privacy page.
   * Spelling it from the same list is what makes both move together.
   */
  it('spells a lookup count that matches what the report actually asks for', () => {
    // Shares `countWord` with the path count below rather than carrying its own
    // copy of the numeral list — a second copy is free to run out at a different
    // length, and then one of the two counts silently stops being checked.
    expect(footnote).toContain(`${countWord(LOOKED_UP_PACKAGES.length)} \`npm view\` lookups`);
  });

  /**
   * And says what that does NOT tell the registry. The plugin lookups run with
   * an empty `installed` map above, so the registry learns which packages this
   * machine asked about — not which it has. The previous copy claimed the
   * opposite ("that it is installed here"), which overstates the disclosure in
   * the one direction a privacy footnote must not.
   */
  it('does not claim the registry learns what is installed', () => {
    expect(footnote).toMatch(/whether or not you have them installed/i);
    expect(footnote).toMatch(/asked about, not which it runs/i);
    expect(footnote).not.toMatch(/installed here/i);
  });

  it('names the package-manager shell-outs as the second path', () => {
    expect(footnote).toMatch(/aka plugins install/);
    expect(footnote).toMatch(/aka update/);
    expect(footnote).toMatch(/aka check-updates/);
    expect(footnote).toMatch(/`npm`/);
    expect(footnote).toMatch(/`claude`/);
    // `aka plugins install codex` spawns the `codex` CLI, not npm or claude
    // (cli-plugin-manager.ts's CliPluginBin is 'claude' | 'codex'). A page whose
    // claim is that the paths are enumerated cannot omit one of the binaries.
    expect(footnote).toMatch(/`codex`/);
  });

  // `aka check-updates` reaches the registry but installs nothing, so grouping
  // it under "commands that install software" misdescribes it in the other
  // direction — the reader cannot tell a read-only lookup from a mutation.
  it('separates the read-only lookup from the installing commands', () => {
    expect(footnote).toMatch(/look up or install/i);
    expect(footnote).toMatch(/only reads/i);
  });

  /**
   * `aka detections` reads and writes the local store — `detections.ts`'s
   * `applyUpdate` is `db.installedPacks.applyUpdate`, not a package-manager
   * spawn — so listing it as a shell-out overstates the CLI's egress.
   *
   * This is pinned rather than left to review because an earlier draft of this
   * very footnote made that mistake, and it is the plausible one to repeat: the
   * command's own summary says "and available updates", which reads networked.
   * A privacy footnote that overstates is a defect in the same way one that
   * understates is — both leave the reader unable to trust the page.
   */
  it('does not attribute network access to the local-only detections command', () => {
    expect(footnote).toMatch(/aka detections` is not one of them/);
    expect(footnote).toMatch(/opens no connection/);
  });

  /**
   * The same split the root README makes, against this page's own count: the
   * `aka-<name>` dispatch is named, and held OUTSIDE the count, because folding
   * it in would imply `ai-tc` sends something it does not while dropping it
   * would leave the count reading as a complete list of what can reach the
   * network from an `aka` invocation. Neither half works alone.
   */
  it('names the aka-<name> dispatch without folding it into the count', () => {
    expect(footnote).toMatch(/aka-<name>/);
    expect(footnote).toMatch(
      new RegExp(`not one of the ${countWord(CLI_EGRESS_PATHS.length)}`, 'i'),
    );
  });

  // The count word and the paths it counts, checked against EACH OTHER rather
  // than against a literal.
  it('states a count that matches the number of paths it enumerates', () => {
    expect(
      footnote,
      `the footnote must open by counting the ${String(CLI_EGRESS_PATHS.length)} paths in ` +
        'CLI_EGRESS_PATHS. If you added or removed one, move the count sentence with it.',
    ).toMatch(new RegExp(`${countWord(CLI_EGRESS_PATHS.length)} narrow paths`, 'i'));
  });

  it.each(CLI_EGRESS_PATHS)('enumerates the $name path', ({ marker }) => {
    // A count that agrees with a list nobody checked is half a guarantee. Each
    // path is NAMED, so the count cannot be satisfied by a list that lost one.
    expect(footnote).toMatch(marker);
  });

  /**
   * The sub-count, which closes the direction the total cannot see: a merge can
   * add a path to the PROSE without adding a row, and the total then agrees with
   * a table that has quietly fallen behind. Every path here but attach is a
   * spawn, so text carrying one also carries a claim about how many are.
   */
  it('states how many of those paths are child processes, and counts them right', () => {
    const spawned = CLI_EGRESS_PATHS.filter((p) => p.childProcess).length;
    expect(
      footnote,
      `the footnote must say ${countWord(spawned)} of the paths are child processes — the rows ` +
        'in CLI_EGRESS_PATHS marked childProcess. The remainder open a socket from the source.',
    ).toMatch(new RegExp(`${countWord(spawned)} are child processes`, 'i'));
  });

  /**
   * Two claims this page carried that attached mode retires. Both are the kind a
   * merge keeps verbatim, because they read as settled background rather than as
   * a fact about the current tree.
   *
   * The second one is banned even though it is still LITERALLY TRUE, and that is
   * the point worth writing down. `@akasecurity/remote` uses `node:https`, so
   * "the source uses no `fetch`" remains accurate — but on this page it sat in
   * the opening reassurance as the evidence for "no built-in network client",
   * which is now false. A true sentence doing false work is the worst failure a
   * privacy footnote has, because it survives every fact-check and still leaves
   * the reader believing nothing opens a socket. Name the client instead.
   */
  it('no longer claims every path is a child process, or that the source has no client', () => {
    expect(footnote).not.toMatch(/both through child processes/i);
    expect(footnote).not.toMatch(/no built-in network client/i);
    expect(footnote).not.toMatch(/the source uses no `?fetch`?/i);
  });

  it('disclaims knowledge of what the dispatched program does', () => {
    expect(footnote).toMatch(/does not bundle, pin or verify it/i);
  });

  /**
   * The judge is the one path that carries the user's own data, and it is the
   * plugin's. Saying so is what keeps this page honest in both directions: a
   * reader must not conclude the CLI sends findings, nor that the product never
   * sends anything. The page hands the payload off to the plugin README rather
   * than restating it — a second copy of that field list is a second thing that
   * can drift, which is why no assertion here asks for one.
   */
  it('attributes the judge to the plugin and points at the page that details it', () => {
    expect(footnote).toMatch(/\/aka:setup/);
    expect(footnote).toMatch(/plugin rather than to this CLI/i);
    expect(footnote).toContain('plugins/claude-code/README.md');
  });

  /**
   * The page hands the PAYLOAD off to the plugin README, but it still makes two
   * substantive claims of its own — that the calibration reaches the model API,
   * and that it sits behind two separate opt-ins. Those are consent claims, and
   * the tier split put every judge assertion in JUDGE_READMES, which excludes
   * this page: a product collapsing to a single gate would redden the two judge
   * pages while this one went on promising two, with nothing to catch it.
   *
   * So they are pinned here. This is not the payload table returning — the
   * TriageHit field list deliberately stays off this page — it is the narrower
   * rule that a page may not make a consent claim no guard holds.
   */
  it('pins the consent claims it makes about the judge', () => {
    expect(footnote).toMatch(/model API/);
    expect(footnote).toMatch(/two separate opt-ins/i);
  });

  /**
   * The shared suite's inline-exception case is satisfied on this page by the
   * word "scanned" inside the claim itself, which is the claim's own wording
   * rather than an exception — so it would pass over a page that named no
   * exception at all. This is the non-vacuous form for this page: the claim
   * paragraph has to name the paths before the reader reaches the marker.
   *
   * Read against CLAIM, not the whole body. `aka plugins` occurs in the command
   * table and the install snippet further down, so the body form of this
   * assertion could not fail — the page was free to drop the exception from the
   * claim and stay green, which is the vacuity this case was written to remove.
   */
  it('names the exceptions in the claim itself, not only in the footnote', () => {
    expect(CLAIM).toMatch(/version check/i);
    // Every command that reaches the registry, not just the one that installs.
    // The claim named `aka plugins` alone while the footnote below it also named
    // `aka update` and `aka check-updates` — so the sentence a reader quotes was
    // narrower than the correction underneath it, and someone running
    // `aka check-updates` would believe it stayed on the machine.
    expect(CLAIM).toMatch(/aka plugins/);
    expect(CLAIM).toMatch(/aka update/);
    expect(CLAIM).toMatch(/aka check-updates/);
  });

  /**
   * The sentence this page used to carry — "Everything runs on your machine" —
   * read as absolute beside a default-on registry ping. The scoped form is what
   * the other two front doors already use, and it is the substance of the fix
   * rather than the footnote: a marker cannot rescue a claim the body overstates.
   */
  it('scopes the locality claim rather than claiming everything is local', () => {
    // Negative over the whole body (the absolute form must not reappear
    // anywhere a reader meets it), positive over the claim itself.
    expect(body).not.toMatch(/Everything runs on your machine/i);
    expect(CLAIM).toMatch(/Detection, enforcement, and your store run on your machine/);
  });
});
