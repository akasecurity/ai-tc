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
   * would leave "two narrow paths" reading as a complete list of what can reach
   * the network from an `aka` invocation. Neither half works alone.
   */
  it('names the aka-<name> dispatch without folding it into the count', () => {
    expect(footnote).toMatch(/Two narrow paths/);
    expect(footnote).toMatch(/aka-<name>/);
    expect(footnote).toMatch(/not one of the two/i);
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
