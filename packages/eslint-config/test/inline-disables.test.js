import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { Linter } from 'eslint';
import n from 'eslint-plugin-n';
import tseslint from 'typescript-eslint';
import { describe, expect, it } from 'vitest';

import { base, networkGuard } from '../src/index.js';
import {
  cardinalFor,
  CONVENTIONS_DOC,
  countWordIn,
  readConventions,
  sectionOf,
} from './helpers/claude-md.js';
import { lintableTrackedFiles, REPO_ROOT } from './helpers/lint-invocations.js';

// The third mechanism, and the one no other guard in this package can see.
//
// no-network.test.js and effective-config.test.js both audit CONFIGS: they
// resolve every tracked eslint config, diff its opt-outs against the tables
// CLAUDE.md §3 and §4 carry, and fail on a row that describes no exception or an
// exception no row describes. An inline `eslint-disable` is not a config, so it
// reaches neither. Nothing else looked, and `linterOptions.noInlineConfig` is
// unset — so there was no secondary signal either. It stays unset, because the
// workspace has four inline disables it genuinely needs and thirty-odd more of
// rules outside these five; what this suite adds is a review gate on the set,
// not a ban on the mechanism.
//
// The measured hole, on a tree where every other gate was green: prepend
//
//     // eslint-disable-next-line no-restricted-imports
//     import https from 'node:https';
//
// to any package's shipped source and `pnpm lint` exits 0 while the control
// (the same import without the comment) exits 1. The blanket form is worse — a
// bare `/* eslint-disable */` admits that import AND a `process.env` read at
// once, since it disables every rule in the file rather than a named one.
//
// So this suite inventories the DIRECTIVES, exactly and across the whole tracked
// tree, for the five rules the other two audits are about. An exact set is the
// point: a guard that only forbids removals lets a new disable in, which is the
// entire failure mode.
//
// Two readings, because neither alone is enough:
//
//   SYNTACTIC — what directives exist, whether or not they are suppressing
//     anything today. A directive suppressing NOTHING is caught at lint time by
//     `reportUnusedDisableDirectives`, so that is not the case this reading is
//     for. The case it is for is a blanket disable held open by a rule OUTSIDE
//     these five: the directive is in use, so lint is silent, and none of the
//     five fires, so the behavioural diff is empty — while the file is exempt
//     from all five for whatever gets written under it next. That configuration
//     is pinned below, because it is the only measurement where the two
//     readings disagree and therefore the whole reason there are two.
//   BEHAVIOURAL — what ESLint really honours, from linting each file twice and
//     diffing. It cannot be fooled by a directive spelling this file did not
//     anticipate, which is what keeps the syntactic reader honest rather than
//     trusted.
//
// The syntactic reading is the inventory; the behavioural one is asserted to be
// a subset of it, so a spelling the reader misses fails here rather than
// shipping.

/** The four network bans, taken from the shipped config rather than re-listed. */
const NETWORK_RULES = Object.keys(networkGuard[0].rules);
const ENV_RULE = 'n/no-process-env';
/** The five rules whose inline disables are inventoried. */
const GUARDED_RULES = [...NETWORK_RULES, ENV_RULE].sort();

/**
 * Every inline disable of a guarded rule the workspace carries, file -> rules.
 *
 * Exact. A file not named here may disable no guarded rule; a file named here
 * may disable no OTHER guarded rule. Every entry is an exception someone has to
 * argue for in review, which is the whole product of this suite.
 *
 * Inline disables of rules OUTSIDE the five (`no-control-regex`,
 * `@typescript-eslint/require-await`, …) are none of this suite's business and
 * are not listed.
 */
const EXPECTED_INLINE_DISABLES = {
  // CLAUDE.md §3's three inline rows. The other three sites in that table
  // (packages/plugin-sdk/src/provider.ts, packages/plugin-sdk/src/provider-codex.ts
  // and plugins/codex/src/triage/judge.ts) are file-scoped CONFIG opt-outs, so they
  // carry no directive and correctly do not appear here — effective-config
  // .test.js is what holds §3's table against the tree, including this split.
  'cli/src/commands/dashboard.ts': [ENV_RULE],
  'plugins/claude-code/src/backfill.ts': [ENV_RULE],
  'plugins/claude-code/src/triage/judge.ts': [ENV_RULE],

  // Test harnesses that spawn the real hooks as child processes and need the
  // host PATH or a redirected HOME. §3's table says "in shipped source" and puts
  // these deliberately out of its scope — which left them inventoried by
  // NOTHING, in the one part of the tree where a new one is easiest to add
  // without anyone weighing it.
  'plugins/claude-code/test/e2e/scan-worker-bundle.e2e.test.ts': [ENV_RULE],
  'plugins/claude-code/test/helpers/run-hook.ts': [ENV_RULE],
  'plugins/claude-code/test/journey/harness.ts': [ENV_RULE],
  'plugins/claude-code/test/provenance.test.ts': [ENV_RULE],
  'plugins/claude-code/test/remediation/entry-posture-close-fault.test.ts': [ENV_RULE],
  'plugins/codex/test/e2e/scan-worker-bundle.e2e.test.ts': [ENV_RULE],
  'plugins/codex/test/remediation/entry-posture-close-fault.test.ts': [ENV_RULE],
  'plugins/antigravity/test/remediation/entry-posture-close-fault.test.ts': [ENV_RULE],

  // CLAUDE.md §4's one global opt-out, tabled there as `fetch` (inline): the
  // runtime suite's deliberate fetch(), which the guard must refuse for that
  // suite to prove anything. It is an inline disable rather than a config `allow`
  // because noNetworkGlobals() takes no `allow` option. This is the ONLY inline
  // disable of a network ban in the workspace, and the network half of this
  // inventory is exactly one entry long for that reason.
  'packages/eslint-config/test/no-network-runtime.test.js': ['no-restricted-globals'],
};

// ---------------------------------------------------------------------------
// Reading the directives
// ---------------------------------------------------------------------------

// ESLint's own pattern for what makes a comment a DIRECTIVE rather than prose
// about one (`Linter`'s directivesPattern), applied to the comment's trimmed
// value. Copied deliberately rather than approximated, because the difference is
// load-bearing in both directions: this package's own suites carry comments
// reading "…is an inline `eslint-disable` (the deliberate fetch)", which a
// substring search reports as an opt-out that does not exist, and
// effective-config.test.js holds the string 'inline `eslint-disable-next-line`'
// in a const. Neither is a directive; both start with something else.
//
// `agreesWithEslint` below is what stops this being a copy that rots — every
// case in the reader's own suite is driven through ESLint too, and a spelling
// this pattern stopped recognising fails there.
const DIRECTIVE =
  /^(eslint(?:-env|-enable|-disable(?:(?:-next)?-line)?)?|exported|globals?)(?:\s|$)/u;

// Every directive kind that can switch a rule OFF. `eslint-enable` turns rules
// back ON, and `eslint-env`/`exported`/`globals` do not touch rule state at all.
const DISABLING_KINDS = new Set([
  'eslint',
  'eslint-disable',
  'eslint-disable-line',
  'eslint-disable-next-line',
]);

/**
 * The prefix every disabling directive starts with, and therefore the one text
 * pre-filter that can skip a file without risking a miss. Derived from the kinds
 * above rather than written down, and pinned by a case below: a kind that did
 * not start with it would make the pre-filter unsound, silently, on 90% of the
 * tree.
 */
const DIRECTIVE_PREFIX = 'eslint';

/** `-- justification` is ESLint's description separator, not part of the rule list. */
const JUSTIFICATION = /\s-{2,}\s/u;

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/**
 * Whether an `/* eslint … *\/` rule-config directive's body names `rule` as a key.
 *
 * Any mention counts, whatever level follows, and that is deliberate rather than
 * lazy: `/* eslint no-restricted-imports: ["error", {"paths": []}] *\/` leaves the
 * rule at `error` and empties its ban, which reads as an enabled rule in every
 * severity check this package makes and permits `node:https` exactly like an
 * `off` would. Reconfiguring one of these five inline is the reviewable event;
 * the level it lands on is not the question.
 */
const configNames = (body, rule) =>
  new RegExp(String.raw`(?:^|[\s,{])["']?${escapeRe(rule)}["']?\s*:`, 'u').test(body);

/**
 * Which guarded rules each inline directive in `comments` switches off.
 * @param {{type: string, value: string, loc: {start: {line: number}}}[]} comments
 * @returns {{kind: string, line: number, rules: string[], fileScoped: boolean}[]}
 */
function disablingDirectives(comments) {
  const found = [];
  for (const comment of comments) {
    const value = comment.value.trim();
    const kind = DIRECTIVE.exec(value)?.[1];
    if (!kind || !DISABLING_KINDS.has(kind)) continue;
    const body = value.slice(kind.length).split(JUSTIFICATION)[0].trim();
    // A rule-config directive always names its rules; a disable directive with
    // an EMPTY list names none and takes every rule with it, this file's five
    // included. That second case is the blanket form, and it is the reason the
    // rule list cannot simply be intersected with the guarded set.
    const rules =
      kind === 'eslint'
        ? GUARDED_RULES.filter((rule) => configNames(body, rule))
        : body
          ? body
              .split(',')
              .map((s) => s.trim())
              .filter((rule) => GUARDED_RULES.includes(rule))
          : [...GUARDED_RULES];
    if (rules.length === 0) continue;
    found.push({
      kind,
      line: comment.loc.start.line,
      rules: rules.sort(),
      // `-line`/`-next-line` bind to one line. A bare `eslint-disable` (and a
      // rule-config directive) applies from its comment to the end of the file
      // or the next `eslint-enable` — so it covers code that does not exist yet,
      // which is why the suite refuses those outright rather than tabling them.
      fileScoped: kind === 'eslint' || kind === 'eslint-disable',
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// Linting
// ---------------------------------------------------------------------------

/**
 * Whether the parser should read JSX in a file of this name — typescript-eslint's
 * own rule, which is a rule and not a default because the two halves conflict.
 * `.ts` must have JSX OFF: `const f = <T>(x: T) => x` is a generic arrow there
 * and a half-open JSX tag with it on, so a single flag for the whole tree costs
 * either every `.tsx` file or every `.ts` file that uses a generic arrow — and
 * costs it as a parse error, which is the one input this scan cannot read.
 * Plain `.js` keeps it on: JSX in a `.js` file is ordinary, and a generic arrow
 * cannot occur there to be confused with one.
 */
const readsJsx = (file) => !/\.[cm]?ts$/.test(file);

// No filename is passed to `verify`: flat config resolves a path against the
// linter's base path and reports "no matching configuration found" instead of
// linting, which every rule here would read as a clean file. The bans are
// path-independent, so nothing is lost — but the parser options are not, which
// is why the JSX decision is made here rather than left to ESLint's own
// per-extension defaults.
const lintConfig = (jsx) => ({
  languageOptions: {
    parser: tseslint.parser,
    ecmaVersion: 'latest',
    sourceType: 'module',
    parserOptions: { ecmaFeatures: { jsx } },
  },
  plugins: { n },
  rules: { ...networkGuard[0].rules, [ENV_RULE]: 'error' },
});

/**
 * The two readings of one source, together so they cannot be taken of different
 * bytes.
 *
 * `honoured` is an ordinary lint; `raw` is the same lint with inline config
 * ignored. A guarded rule in `raw` but not in `honoured` was suppressed by an
 * inline directive — which is ESLint's own answer to the question, arrived at
 * without reading a comment. The rules are identical across the two runs, so a
 * file-scoped config opt-out (dashboard.ts's `node:net`, provider.ts's env
 * exemption) cancels out of the DIFFERENCE and no config resolution is needed.
 *
 * A parse failure throws rather than returning nothing: a file this cannot read
 * is a file the inventory cannot cover, and a silent skip is how a guard reports
 * a clean sheet over the one file someone hid something in.
 * @param {string} source @param {string} label
 */
function read(source, label) {
  const config = lintConfig(readsJsx(label));
  const linter = new Linter();
  const honoured = linter.verify(source, config);
  const fatal = honoured.find((m) => m.fatal);
  if (fatal) {
    throw new Error(
      `${label}: could not be parsed, so its directives are unreadable — ` +
        `${fatal.message} (line ${String(fatal.line)})`,
    );
  }
  const comments = linter.getSourceCode()?.getAllComments() ?? [];
  const raw = new Linter().verify(source, config, { allowInlineConfig: false });
  const guarded = (messages) =>
    messages.filter((m) => m.ruleId && GUARDED_RULES.includes(m.ruleId));
  const fired = new Set(guarded(honoured).map((m) => m.ruleId));
  return {
    directives: disablingDirectives(comments),
    // What inline config really cost, as a set of rule ids. Counted per rule
    // rather than per message: two suppressed hits of one ban are one exception.
    suppressed: [...new Set(guarded(raw).map((m) => m.ruleId))].filter((id) => !fired.has(id)),
  };
}

/** Every rule the directives in `source` disable, sorted. */
const disabledRules = (directives) => [...new Set(directives.flatMap((d) => d.rules))].sort();

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------

// A directive that can disable a rule always starts with `eslint` (DISABLING_KINDS,
// pinned below), so a file whose bytes do not contain that string cannot carry
// one and is skipped unparsed. That takes the scan from every lintable tracked
// file to a small fraction of them; both counts are asserted, so a pre-filter
// that started matching nothing — or everything — is a failure rather than a
// speed-up nobody notices.
const SCANNED = (() => {
  const all = lintableTrackedFiles();
  /** @type {Record<string, string[]>} */
  const disables = {};
  /** @type {Record<string, string[]>} */
  const suppressed = {};
  /** @type {{file: string, kind: string, line: number, rules: string[]}[]} */
  const fileScoped = [];
  let parsed = 0;
  for (const file of all) {
    const source = readFileSync(join(REPO_ROOT, file), 'utf8');
    if (!source.includes(DIRECTIVE_PREFIX)) continue;
    parsed += 1;
    const { directives, suppressed: real } = read(source, file);
    const rules = disabledRules(directives);
    if (rules.length > 0) disables[file] = rules;
    if (real.length > 0) suppressed[file] = real.sort();
    for (const d of directives.filter((d) => d.fileScoped)) {
      fileScoped.push({ file, kind: d.kind, line: d.line, rules: d.rules });
    }
  }
  return { total: all.length, parsed, disables, suppressed, fileScoped };
})();

// ---------------------------------------------------------------------------
// The reader's own suite
// ---------------------------------------------------------------------------

// Two of the six assertions-that-could-not-fail this repository has found were
// helpers quietly weakened rather than test bodies, so the reader gets its own
// cases — and each one is put to ESLINT as well, because a reader that agrees
// with itself proves nothing. `agreesWithEslint` is the second half: it lints
// the same source twice and asks whether the suppression the reader claims is
// one ESLint actually performs.

/** What ESLint itself suppresses in `source`, via the allowInlineConfig diff. */
const eslintSuppresses = (source) => read(source, '<case>').suppressed.sort();

/** What the reader says the directives in `source` disable. */
const readerSays = (source) => disabledRules(read(source, '<case>').directives);

const ENV_READ = 'const home = process.env.HOME;\n';

describe('the directive reader', () => {
  it.each([
    ['-next-line, one rule', `// eslint-disable-next-line ${ENV_RULE}\n${ENV_READ}`, [ENV_RULE]],
    [
      '-line, one rule',
      `const h = process.env.HOME; // eslint-disable-line ${ENV_RULE}\n`,
      [ENV_RULE],
    ],
    [
      'a justification after --',
      `// eslint-disable-next-line ${ENV_RULE} -- the subprocess needs PATH\n${ENV_READ}`,
      [ENV_RULE],
    ],
    ['a block comment', `/* eslint-disable-next-line ${ENV_RULE} */\n${ENV_READ}`, [ENV_RULE]],
    [
      'two rules in one list',
      `/* eslint-disable ${ENV_RULE}, no-restricted-imports */\n${ENV_READ}`,
      [ENV_RULE, 'no-restricted-imports'],
    ],
    ['a rule-config directive', `/* eslint ${ENV_RULE}: "off" */\n${ENV_READ}`, [ENV_RULE]],
    ['a numeric rule-config level', `/* eslint ${ENV_RULE}: 0 */\n${ENV_READ}`, [ENV_RULE]],
    ['the blanket form', `/* eslint-disable */\n${ENV_READ}`, GUARDED_RULES],
    ['the blanket form, line comment', `// eslint-disable\n${ENV_READ}`, GUARDED_RULES],
  ])('reads %s', (_name, source, expected) => {
    expect(readerSays(source)).toEqual([...expected].sort());
  });

  it.each([
    ['prose mentioning a directive', '// this is an inline `eslint-disable`, not one\n'],
    ['a directive string in code', `const BY_INLINE = 'inline \`eslint-disable-next-line\`';\n`],
    ['a directive-shaped regex', 'const RE = /eslint-disable(?:-next-line)?/;\n'],
    ['eslint-enable', `/* eslint-enable ${ENV_RULE} */\n`],
    [
      'a disable of an unguarded rule',
      '// eslint-disable-next-line no-control-regex\nconst RE = /\\x1b/;\n',
    ],
    ['a globals directive', '/* globals process */\n'],
  ])('does not read %s as a disable', (_name, source) => {
    expect(readerSays(source)).toEqual([]);
  });

  it.each([
    ['a bare eslint-disable', `/* eslint-disable */\n${ENV_READ}`, true],
    ['a rule-config directive', `/* eslint ${ENV_RULE}: "off" */\n${ENV_READ}`, true],
    ['eslint-disable WITH a rule list', `/* eslint-disable ${ENV_RULE} */\n${ENV_READ}`, true],
    ['eslint-disable-next-line', `// eslint-disable-next-line ${ENV_RULE}\n${ENV_READ}`, false],
    [
      'eslint-disable-line',
      `const h = process.env.HOME; // eslint-disable-line ${ENV_RULE}\n`,
      false,
    ],
  ])('marks %s as file-scoped: %s', (_name, source, expected) => {
    // This is about a directive's REACH, not about whether it named a rule. The
    // third row is the one that says so: `eslint-disable n/no-process-env` looks
    // targeted and still runs to end-of-file, so it exempts code nobody has
    // written yet exactly as the bare form does.
    const scoped = read(source, '<case>').directives.filter((d) => d.fileScoped);
    expect(scoped.length > 0).toBe(expected);
  });

  it('agrees with ESLint on every case that suppresses something', () => {
    // The control on the copied pattern. Each source below really violates the
    // rule it disables, so ESLint's own diff has an answer — and where the two
    // disagree, this fails rather than the reader quietly winning.
    const cases = [
      `// eslint-disable-next-line ${ENV_RULE}\n${ENV_READ}`,
      `const h = process.env.HOME; // eslint-disable-line ${ENV_RULE}\n`,
      `// eslint-disable-next-line ${ENV_RULE} -- justified\n${ENV_READ}`,
      `/* eslint ${ENV_RULE}: "off" */\n${ENV_READ}`,
      `/* eslint-disable */\n${ENV_READ}`,
      `/* eslint-disable */\nimport https from 'node:https';\nexport const s = https;\n`,
      `// eslint-disable-next-line no-restricted-imports\nimport https from 'node:https';\nexport const s = https;\n`,
      `// eslint-disable-next-line no-restricted-globals\nvoid fetch('/x');\n`,
    ];
    const disagreements = cases.flatMap((source) => {
      const byEslint = eslintSuppresses(source);
      const byReader = readerSays(source);
      // Subset, not equality: the reader also sees a blanket disable's reach over
      // the four rules the case does not happen to violate.
      const missed = byEslint.filter((rule) => !byReader.includes(rule));
      return [
        ...(byEslint.length === 0
          ? [`${source}: ESLint suppressed nothing, so this proves nothing`]
          : []),
        ...missed.map((rule) => `${source}: ESLint suppressed ${rule}, the reader did not see it`),
      ];
    });
    expect(disagreements).toEqual([]);
  });

  it('is the only reading that sees a blanket disable held open by an unguarded rule', () => {
    // The one measurement where the two readings disagree, and therefore the
    // reason the suite takes two. Neither of the cheaper answers reaches this
    // file: lint is silent because the directive IS in use, and the behavioural
    // diff is empty because none of the five fires under it yet. The exemption
    // is real all the same — every one of the five is off from that comment to
    // the end of the file, for whatever is written there next.
    //
    // Drop the syntactic reading and the tree assertions stay green on exactly
    // this shape, which is what makes it worth a case of its own rather than a
    // line in a comment.
    const source = `/* eslint-disable */\nconsole.log('x');\n`;

    // Lint time: the blanket suppresses `no-console`, so it is a USED directive
    // and `reportUnusedDisableDirectives` — which only fires on one suppressing
    // nothing at all — has nothing to say.
    const config = lintConfig(false);
    const withUnguardedRule = {
      ...config,
      rules: { ...config.rules, 'no-console': 'error' },
      linterOptions: base.find((entry) => entry.linterOptions)?.linterOptions,
    };
    // The positive control on that silence, and it is not optional: an empty
    // message list is what a config with no linterOptions at all produces too,
    // so without this the assertion below passes while proving nothing. Strip
    // the line the blanket is covering and the SAME config reports the
    // directive — so the silence is a fact about this shape, not about the
    // linter being unwired.
    const latent = new Linter().verify('/* eslint-disable */\n', withUnguardedRule);
    expect(latent.map((m) => m.message)).toEqual([
      'Unused eslint-disable directive (no problems were reported).',
    ]);
    expect(latent.every((m) => m.severity === 2)).toBe(true);

    expect(new Linter().verify(source, withUnguardedRule)).toEqual([]);

    // Behavioural: nothing of the five fires either way, so the diff is empty.
    expect(eslintSuppresses(source)).toEqual([]);

    // Syntactic: the exemption is there, and it covers all five.
    expect(readerSays(source)).toEqual(GUARDED_RULES);
  });

  it('pre-filters on a prefix every disabling kind really starts with', () => {
    // The scan skips a file whose bytes lack this string. Sound only while every
    // kind that can turn a rule off begins with it — a new kind that did not
    // would leave the skipped 90% of the tree unscanned, with nothing to show
    // for it but a faster run.
    for (const kind of DISABLING_KINDS) {
      expect(
        kind.startsWith(DIRECTIVE_PREFIX),
        `${kind} does not start with ${DIRECTIVE_PREFIX}`,
      ).toBe(true);
    }
  });

  it.each([
    ['a generic arrow in .ts', 'x.ts', 'export const f = <T>(v: T): T => v;\n'],
    ['a generic arrow in .mts', 'x.mts', 'export const f = <T>(v: T): T => v;\n'],
    ['a JSX element in .tsx', 'x.tsx', 'export const El = () => <div className="a" />;\n'],
    ['a JSX element in .jsx', 'x.jsx', 'export const El = () => <div className="a" />;\n'],
    ['a JSX element in .js', 'x.js', 'export const El = () => <div className="a" />;\n'],
  ])('parses %s', (_name, file, source) => {
    // Both directions of the JSX flag, because one setting for the whole tree
    // parses one of these two and throws on the other — and a throw here is the
    // scan going blind to that file, not a visible failure in the file itself.
    expect(errorFrom(() => read(source, file))).toBeUndefined();
  });

  it('throws on a source it cannot parse rather than reporting no directives', () => {
    // An unreadable file is the one place a scan turns silently vacuous: it holds
    // whatever it holds, and a reader that returns [] for it says the tree is
    // clean.
    const err = errorFrom(() => read('const = ;\n/* eslint-disable */\n', 'broken.ts'));
    expect(err?.message).toContain('broken.ts');
    expect(err?.message).toContain('directives are unreadable');
  });
});

// ---------------------------------------------------------------------------
// The inventory
// ---------------------------------------------------------------------------

describe(`inline disables of the guarded rules (${CONVENTIONS_DOC} §3 and §4)`, () => {
  it('scans a tree that is really there', () => {
    // Everything below is an assertion about a set, and every one of them passes
    // on the empty set. `git ls-files` returning nothing, a pre-filter that
    // matched nothing, a reader that stopped recognising directives — all three
    // read as a clean workspace, and this is what separates them from one.
    expect(SCANNED.total, 'no lintable tracked files found').toBeGreaterThan(0);
    expect(SCANNED.parsed, 'no file reached the parser').toBeGreaterThan(0);
    expect(
      SCANNED.parsed,
      'the pre-filter skipped nothing, so it is not doing its job',
    ).toBeLessThan(SCANNED.total);
    expect(
      Object.keys(SCANNED.disables).length,
      'no inline disable found anywhere',
    ).toBeGreaterThan(0);
  });

  it('carries exactly the inline disables the workspace documents', () => {
    // Exact in both directions, and both matter. An unexpected entry is a new
    // opt-out nobody weighed; a missing one is an expectation outliving the
    // exception it describes, which leaves the next one free to take its place.
    const expected = Object.fromEntries(
      Object.entries(EXPECTED_INLINE_DISABLES).map(([file, rules]) => [file, [...rules].sort()]),
    );
    expect(SCANNED.disables).toEqual(expected);
  });

  it('lets no file disable a guarded rule for the rest of its length', () => {
    // The blanket `/* eslint-disable */` and the inline rule-config directive
    // both run to end-of-file, so they cover code nobody has written yet: a file
    // carrying one is exempt from these five bans forever, and the exemption
    // never appears in a diff again. There is no such directive in the workspace
    // and this suite refuses to be the place one gets tabled.
    const found = SCANNED.fileScoped.map(
      ({ file, kind, line, rules }) =>
        `${file}:${String(line)}: \`${kind}\` disables ${rules.join(', ')} to end of file`,
    );
    expect(found, 'file-scoped inline disables of a guarded rule').toEqual([]);
  });

  it('sees every disable ESLint really honours', () => {
    // The behavioural half, over the real tree. The reader is a copy of ESLint's
    // directive pattern, and this is what stops it being a copy that drifts: a
    // spelling it stopped recognising still shows up in the true-vs-false diff,
    // and shows up here as a file whose real suppressions its inventory does not
    // account for.
    const unaccounted = Object.entries(SCANNED.suppressed).flatMap(([file, rules]) =>
      rules
        .filter((rule) => !(SCANNED.disables[file] ?? []).includes(rule))
        .map((rule) => `${file}: inline config suppresses ${rule}, the reader did not see it`),
    );
    expect(unaccounted).toEqual([]);
  });

  it('fails a directive that has stopped suppressing anything', () => {
    // The lint-time companion, asserted through a real lint rather than by
    // reading the config value back. A dead disable is how an entry in the table
    // above quietly stops meaning anything: the code it covered goes, the comment
    // stays, and the next line that would have tripped the ban inherits an
    // exemption nobody granted it. ESLint's own default for this is `warn`, which
    // this workspace treats as off.
    const linterOptions = base.find((entry) => entry.linterOptions)?.linterOptions;
    const messages = new Linter().verify(
      `// eslint-disable-next-line ${ENV_RULE}\nexport const a = 1;\n`,
      {
        ...lintConfig(false),
        linterOptions,
      },
    );
    expect(messages.map((m) => m.message)).toEqual([
      "Unused eslint-disable directive (no problems were reported from 'n/no-process-env').",
    ]);
    expect(messages.every((m) => m.severity === 2)).toBe(true);
  });

  it(`states the size of the network half in ${CONVENTIONS_DOC} §4`, () => {
    // The table in §4 is pinned to `DOCUMENTED_OPT_OUTS` by no-network.test.js,
    // but the SENTENCE this suite added beside it — "that set is one entry
    // long" — was pinned by nothing, and a hand-written mirror is exactly what
    // a count sentence drifts away from. Measured: adding a second network
    // inline disable and tabling it above leaves the whole package green while
    // §4 goes on claiming one, which is the drift this file exists to stop, one
    // level up from where it stops it.
    //
    // Derived from the expectation rather than restated, so the two cannot be
    // edited apart: the doc is asserted against the same map the tree is.
    const network = Object.entries(EXPECTED_INLINE_DISABLES).filter(([, rules]) =>
      rules.some((rule) => NETWORK_RULES.includes(rule)),
    );
    const section = sectionOf(readConventions(), '### 4. No network calls');
    const stated = countWordIn(
      section,
      /That set is (\w+) entr(?:y|ies) long/gu,
      'the size of the inline-disable set for the network bans',
    );
    expect(stated).toBe(cardinalFor(network.length));
    // And that the noun agrees, which the pattern above deliberately does not
    // decide: a second entry makes the count word wrong AND "one entry" wrong,
    // and a sentence half-corrected reads as true to everyone who skims it.
    const noun = network.length === 1 ? 'entry' : 'entries';
    expect(section).toContain(`That set is ${cardinalFor(network.length)} ${noun} long`);
  });

  it('finds each tabled disable really suppressing something', () => {
    // The positive control on the table. Without it an entry could name a file
    // whose directive has gone dead — the code it covered deleted, the rule
    // renamed — and the inventory would keep asserting it, matching a reader that
    // still finds the comment. Every entry here is expected to be load-bearing:
    // remove the directive and lint fails.
    const dead = Object.entries(EXPECTED_INLINE_DISABLES).flatMap(([file, rules]) =>
      rules
        .filter((rule) => !(SCANNED.suppressed[file] ?? []).includes(rule))
        .map((rule) => `${file}: tabled as disabling ${rule}, but suppresses no such violation`),
    );
    expect(dead).toEqual([]);
  });
});

/**
 * The error `fn` throws, or undefined. Captured OUTSIDE a catch: a `try { fn();
 * throw new Error('expected') } catch (e) { expect(e.message)… }` asserts on its
 * own guard error and keeps passing after `fn` stops throwing entirely.
 */
function errorFrom(fn) {
  try {
    fn();
  } catch (err) {
    return /** @type {Error} */ (err);
  }
  return undefined;
}
