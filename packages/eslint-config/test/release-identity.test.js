import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { extname, join, matchesGlob } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  readPackageManifest,
  REPO_ROOT,
  trackedFiles,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';
import { publishedPackageNames, releaseWorkflows } from './helpers/release-workflows.js';

const require = createRequire(import.meta.url);
/** @type {import('typescript')} */
const ts = require('typescript');

// A release publishes four artifacts, and every one of them carries an identity
// in more than one file: a package name, a marketplace entry, a host manifest, a
// shell filter in a workflow. Nothing joined those copies, so each of them could
// be edited on its own — and the failures that follow are all of the kind a
// release discovers rather than a test: a marketplace entry pointing at a
// package npm does not serve, a host manifest reporting a version the tarball
// does not carry, a plugin nothing publishes but nothing marks private either.
//
// Everything here is DERIVED. There is no expected list of plugins, no version
// numeral and no tag: the sets are read out of the tree and compared with each
// other, so adding a fourth plugin needs no edit here and forgetting half of
// adding one reds. Pre-1.0 the version numbers are chosen ad hoc at the
// scheduled release, so the only version claim this makes is that the four
// shippable artifacts AGREE — never what they agree on, and never that anything
// needs bumping.
//
// It lives in this package because only this task's turbo `inputs` hash the
// whole workspace: the same audit inside `local-ops` would replay a cached green
// while a marketplace entry or a plugin manifest changed under it. The last
// describe is what keeps that reasoning true rather than assumed.

const MARKETPLACE = '.claude-plugin/marketplace.json';
const REGISTRY = 'packages/local-ops/src/registry.ts';

/** The repo whose own marketplace file this tree carries. */
const THIS_REPO_SOURCE = 'akasecurity/ai-tc';

// Where each host reads its own plugin manifest, which is not the same place
// for any two of them — these are the paths the conventions doc's Releasing
// section names as the pairs a bump has to move together. A released plugin
// whose directory is not here fails rather than being skipped: a host manifest
// this guard cannot find is a version pair nothing checks.
const HOST_MANIFESTS = Object.freeze({
  'plugins/claude-code': '.claude-plugin/plugin.json',
  'plugins/codex': '.codex-plugin/plugin.json',
  'plugins/antigravity': 'plugin.json',
});

// A marketplace name and a plugin entry name both reach a host's command line
// and a URL, so they are held to the conventional kebab-case shape rather than
// to "is a string": an entry name carrying whitespace, an underscore, or a
// bidirectional control character is one a user cannot type and a reviewer
// cannot see.
const KEBAB = /^[a-z0-9]+(-[a-z0-9]+)*$/;

/** @param {string} rel */
const readJson = (rel) => JSON.parse(readFileSync(join(REPO_ROOT, rel), 'utf8'));

/**
 * A property of a parsed object literal: whether it is there at all, its value
 * when that is a single string literal, and its member path when it is one.
 *
 * `present` is separate from `value` because the invariant below is about
 * PRESENCE for two fields whose values are not single literals — `installHint`
 * is a `+` concatenation across four lines, and reducing it to a string would
 * mean evaluating the file.
 *
 * @typedef {{ present: boolean, value: string|undefined, member: string|undefined }} Prop
 */

/**
 * Every object literal in a `const <name> = [ … ]` array, read from source
 * TEXT rather than a file — so the classifier below can be driven with a
 * fixture as well as with the real registry.
 *
 * Parsed rather than imported, deliberately: this package is a leaf that
 * nothing in the workspace may depend on, so it cannot take `@akasecurity/local-ops`
 * to read the registry — and parsing means the guard runs the module's TEXT
 * rather than its behaviour, so an entry cannot be assembled at import time in a
 * way that hides a missing coordinate from the audit.
 *
 * Every member of every entry must be a plain `key: value` assignment with an
 * identifier name. A spread, a shorthand, a computed name, a method or an
 * accessor is not one, and skipping it silently is exactly what would hide a
 * live coordinate from this audit: `has(entry, 'pluginName')` reads `false`
 * for a `pluginName` that arrived through `...ref`, which the "all present or
 * all absent" case downstream then reads as "all absent" rather than as
 * "unreadable". An entry this parser cannot classify is one it cannot vouch
 * for, so it throws instead.
 *
 * @param {string} source the file's text
 * @param {string} label repo-relative path, for the error message
 * @param {string} name the declared const
 * @returns {Record<string, Prop>[]}
 */
function parseObjectArrayConst(source, label, name) {
  const sf = ts.createSourceFile(label, source, ts.ScriptTarget.Latest, true);
  /** @type {import('typescript').ArrayLiteralExpression | undefined} */
  let array;
  /** @param {import('typescript').Node} node */
  const visit = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) {
      let init = node.initializer;
      while (init && (ts.isAsExpression(init) || ts.isParenthesizedExpression(init))) {
        init = init.expression;
      }
      if (init && ts.isArrayLiteralExpression(init)) array = init;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  if (!array) {
    throw new Error(
      `${label} no longer declares \`${name}\` as an array literal. This guard parses that file ` +
        'rather than importing it, so the declaration shape is part of what it depends on — ' +
        'building the array at runtime would put every coordinate below out of its reach.',
    );
  }
  return array.elements.filter(ts.isObjectLiteralExpression).map((object) => {
    /** @type {Record<string, Prop>} */
    const props = {};
    for (const property of object.properties) {
      if (!ts.isPropertyAssignment(property) || !ts.isIdentifier(property.name)) {
        throw new Error(
          `${label} declares a \`${name}\` entry with a ${ts.SyntaxKind[property.kind]} member — ` +
            'not a plain `key: value` assignment. This audit reads coordinates by key presence, so ' +
            'a member it cannot classify this way is one it cannot vouch for: spell it as ' +
            '`key: value` or teach this parser the new shape.',
        );
      }
      const init = property.initializer;
      props[property.name.text] = {
        present: true,
        value:
          ts.isStringLiteral(init) || ts.isNoSubstitutionTemplateLiteral(init)
            ? init.text
            : undefined,
        member:
          ts.isPropertyAccessExpression(init) && ts.isIdentifier(init.expression)
            ? `${init.expression.text}.${init.name.getText(sf)}`
            : undefined,
      };
    }
    return props;
  });
}

/**
 * The file-reading half of {@link parseObjectArrayConst}.
 * @param {string} rel repo-relative path
 * @param {string} name the declared const
 * @returns {Record<string, Prop>[]}
 */
function objectArrayConst(rel, name) {
  return parseObjectArrayConst(readFileSync(join(REPO_ROOT, rel), 'utf8'), rel, name);
}

const ENTRIES = objectArrayConst(REGISTRY, 'AGENT_PLUGINS');

/** @param {Record<string, Prop>} entry @param {string} key */
const str = (entry, key) => entry[key]?.value;
/** @param {Record<string, Prop>} entry @param {string} key */
const has = (entry, key) => entry[key]?.present === true;

// The three fields that together make a host install ref, and the field that
// stands in for them when there is none.
const COORDINATES = Object.freeze(['pluginName', 'marketplace', 'cliBin']);

/**
 * The `<plugin>@<marketplace>` ref an entry installs by, or undefined when it
 * declares no marketplace coordinates.
 * @param {Record<string, Prop>} entry
 */
const refOf = (entry) =>
  has(entry, 'pluginName') && has(entry, 'marketplace')
    ? `${str(entry, 'pluginName')}@${str(entry, 'marketplace')}`
    : undefined;

const MARKET = readJson(MARKETPLACE);
/** Safe at module scope: a broken shape must red the shape case, not the file. */
const MARKET_PLUGINS = Array.isArray(MARKET.plugins) ? MARKET.plugins : [];

const TRACKED = new Set(trackedFiles());
// A workspace package whose manifest is really in the tree. Tracked-ness is
// what separates a package from a leftover directory in somebody's checkout.
const PACKAGES = workspacePackageDirs()
  .filter((dir) => TRACKED.has(`${dir}/package.json`))
  .map((dir) => ({ dir, ...readPackageManifest(dir) }));
const BY_NAME = new Map(PACKAGES.map((p) => [p.name, p]));
const PUBLISHABLE = PACKAGES.filter((p) => p.private !== true);
const PLUGIN_PACKAGES = PACKAGES.filter((p) => p.dir.startsWith('plugins/'));

const WORKFLOWS = releaseWorkflows();
const PUBLISHED = publishedPackageNames();

describe('the release-identity audit finds what it audits', () => {
  it('reads the registry, the marketplace, the workspace and the release workflows', () => {
    // Every case below is a loop or a set comparison, and each of them reports
    // green over nothing. The AST read is the one most worth a control: a parse
    // that found the array but no property assignments yields objects with no
    // keys, which satisfies every `has(...) === false` invariant vacuously.
    expect(ENTRIES.length, `${REGISTRY} yielded no AGENT_PLUGINS entries`).toBeGreaterThanOrEqual(
      3,
    );
    const unreadable = ENTRIES.filter(
      (e) => typeof str(e, 'id') !== 'string' || str(e, 'id') === '',
    );
    expect(
      unreadable.length,
      `${REGISTRY} parsed, but ${unreadable.length} entries yielded no string \`id\` — the AST ` +
        'read is returning empty objects and every coordinate case below is vacuous',
    ).toBe(0);
    expect(Array.isArray(MARKET.plugins), `${MARKETPLACE} declares no \`plugins\` array`).toBe(
      true,
    );
    expect(MARKET_PLUGINS.length, `${MARKETPLACE} lists no plugins`).toBeGreaterThan(0);
    expect(WORKFLOWS.length, 'found no release workflows').toBeGreaterThanOrEqual(4);
    expect(
      PUBLISHED.size,
      'no release workflow publishes anything, so both directions of the shippable-set case are ' +
        'vacuous',
    ).toBeGreaterThan(0);
    expect(PUBLISHABLE.length, 'no workspace package is publishable').toBeGreaterThan(0);
    expect(PLUGIN_PACKAGES.length, 'no plugins/* workspace package').toBeGreaterThan(0);
  });
});

describe('the coordinate parser fails loudly on a member it cannot classify', () => {
  const NAME = 'AGENT_PLUGINS';
  const LABEL = 'fixture.ts';
  /** A one-entry `AGENT_PLUGINS` array carrying the given member alongside `id`. */
  const source = (member) =>
    `export const ${NAME} = [\n  {\n    id: 'fixture',\n    ${member}\n  },\n];\n`;

  // Wrapping live coordinates in a spread leaves `has(entry, 'pluginName')`
  // reading `false` for a key the entry actually carries, so the "all present
  // or all absent" case downstream is satisfied by "all absent" — a plugin can
  // ship a working install ref while this audit reports it as having none. A
  // shorthand, a computed name, a method and a getter are the same defect by a
  // different route: none of them is a `PropertyAssignment` with an
  // `Identifier` name, so a parser that silently drops what it cannot
  // classify drops all of them the same way.
  it.for([
    ['a spread', "...{ pluginName: 'aka-x', marketplace: 'ai-tc', cliBin: 'agy' },"],
    ['a shorthand', 'pluginName,'],
    ['a computed name', "['plugin' + 'Name']: 'aka-x',"],
    ['a method', "pluginName() { return 'aka-x'; },"],
    ['a getter', "get pluginName() { return 'aka-x'; },"],
  ])('%s member throws rather than being silently skipped', ([, member]) => {
    expect(() => parseObjectArrayConst(source(member), LABEL, NAME)).toThrow(
      /not a plain `key: value` assignment/,
    );
  });

  it('a plain key: value member does not throw (positive control)', () => {
    expect(() => parseObjectArrayConst(source("pluginName: 'aka-x',"), LABEL, NAME)).not.toThrow();
  });
});

describe('AGENT_PLUGINS coordinates are whole or absent', () => {
  it.each(ENTRIES.map((e) => [str(e, 'id') ?? '<unnamed>', e]))(
    '%s: pluginName, marketplace and cliBin are all present or all absent',
    (_id, entry) => {
      const present = COORDINATES.filter((key) => has(entry, key));
      expect(
        present.length === 0 || present.length === COORDINATES.length,
        `carries ${present.join(', ') || 'none'} of ${COORDINATES.join(', ')}. A half-built ref ` +
          'is a command the host rejects: the install path needs the plugin name, the ' +
          'marketplace it comes from, and which host binary to drive, and it has no fallback ' +
          'for any one of them being missing.',
      ).toBe(true);
    },
  );

  it.each(ENTRIES.map((e) => [str(e, 'id') ?? '<unnamed>', e]))(
    '%s: carries an installHint exactly when it carries no coordinates',
    (_id, entry) => {
      // The two fields answer the same question and exactly one of them has to.
      // With neither, the CLI falls back to telling the user to install from a
      // marketplace, which is wrong for a host that has none; with both, the
      // hint is dead text beside a ref that already works.
      expect(
        has(entry, 'installHint'),
        refOf(entry) === undefined
          ? 'has no install ref, so it needs an installHint — without one the CLI can only ' +
              'point at a marketplace this host does not have'
          : `installs as \`${refOf(entry)}\`, so an installHint is a second answer to a ` +
              'question the coordinates already answer',
      ).toBe(refOf(entry) === undefined);
    },
  );

  it('gives every entry a distinct id, npmPackage and install ref', () => {
    for (const key of ['id', 'npmPackage']) {
      // Counted over the values that are really there, not over the entries: a
      // key missing from ONE entry leaves a single `undefined` in the list,
      // which is distinct from every real value and satisfies the comparison
      // below. Requiring every entry to declare one is what makes the
      // distinctness claim cover all of them.
      const values = ENTRIES.map((e) => str(e, key)).filter((v) => v !== undefined && v !== '');
      expect(
        values.length,
        `${values.length} of ${ENTRIES.length} entries declare a non-empty ${key}`,
      ).toBe(ENTRIES.length);
      expect(new Set(values).size, `two entries share a ${key}: ${values.join(', ')}`).toBe(
        values.length,
      );
    }
    const refs = ENTRIES.map(refOf).filter((r) => r !== undefined);
    expect(refs.length, 'no entry declares an install ref').toBeGreaterThan(0);
    expect(
      new Set(refs).size,
      `two entries share an install ref (${refs.join(', ')}). The refs key one installed-version ` +
        "lookup, so either plugin's ledger entry would then satisfy the other's installed check.",
    ).toBe(refs.length);
  });

  it.each(ENTRIES.map((e) => [str(e, 'id') ?? '<unnamed>', e]))(
    '%s: names a tracked, publishable workspace package in npmPackage',
    (_id, entry) => {
      const name = str(entry, 'npmPackage');
      const pkg = BY_NAME.get(name);
      expect(pkg, `npmPackage \`${name}\` is not a tracked workspace package`).toBeDefined();
      expect(
        pkg.private,
        `${name} is a private package, so npm will never serve the version this entry reports`,
      ).not.toBe(true);
    },
  );
});

describe("this repo's marketplace and the registry agree", () => {
  const inRepo = ENTRIES.filter((e) => str(e, 'marketplaceSource') === THIS_REPO_SOURCE);

  it('has at least one entry served from this repo', () => {
    // Without this the per-entry cases below iterate nothing and report green,
    // which is exactly what would happen if `marketplaceSource` were respelled.
    expect(
      inRepo.length,
      `no AGENT_PLUGINS entry names \`${THIS_REPO_SOURCE}\` as its marketplaceSource, so the ` +
        `agreement between ${REGISTRY} and ${MARKETPLACE} is asserted over nothing`,
    ).toBeGreaterThan(0);
  });

  // Only entries served from THIS repo. An entry pointing at another
  // marketplace repository names a plugin this tree does not contain, so
  // widening these cases to every entry would assert against a file that is not
  // here — a deliberate limit rather than an omission, and the reason the
  // marketplaceSource filter is the thing being read rather than the entry list.
  it.each(inRepo.map((e) => [str(e, 'id') ?? '<unnamed>', e]))(
    '%s: its marketplace, its entry, and that entry’s package all line up',
    (_id, entry) => {
      expect(
        str(entry, 'marketplace'),
        `installs from marketplace \`${str(entry, 'marketplace')}\` while ${MARKETPLACE} calls ` +
          `itself \`${MARKET.name}\``,
      ).toBe(MARKET.name);
      const found = MARKET_PLUGINS.find((p) => p?.name === str(entry, 'pluginName'));
      expect(
        found,
        `no \`${str(entry, 'pluginName')}\` entry in ${MARKETPLACE}, so the install ref ` +
          `\`${refOf(entry)}\` resolves to nothing`,
      ).toBeDefined();
      expect(
        found.source?.package,
        `${MARKETPLACE} serves \`${found.name}\` from \`${found.source?.package}\` while the ` +
          `registry reports its version from \`${str(entry, 'npmPackage')}\``,
      ).toBe(str(entry, 'npmPackage'));
    },
  );
});

describe('the marketplace manifest is well formed and every entry resolves', () => {
  it('declares a kebab-case name, an owner and a plugin list', () => {
    expect(typeof MARKET.name, `${MARKETPLACE} has no string \`name\``).toBe('string');
    expect(MARKET.name, `${MARKETPLACE}'s name is not kebab-case`).toMatch(KEBAB);
    expect(typeof MARKET.owner?.name, `${MARKETPLACE} has no string \`owner.name\``).toBe('string');
    expect(Array.isArray(MARKET.plugins), `${MARKETPLACE} declares no \`plugins\` array`).toBe(
      true,
    );
  });

  it.each(MARKET_PLUGINS.map((p, i) => [p?.name ?? `plugins[${i}]`, p]))(
    '%s: names itself in kebab-case and is served by a tracked, publishable plugin package',
    (_name, plugin) => {
      expect(typeof plugin.name, 'entry has no string `name`').toBe('string');
      expect(plugin.name, 'entry name is not kebab-case').toMatch(KEBAB);
      expect(plugin.source, 'entry declares no `source`').toBeDefined();
      // Every entry this repo serves is an npm source, which is what makes
      // `source.package` a workspace package at all. A different source kind is
      // a deliberate change and has to decide here what resolving means for it.
      expect(plugin.source.source, 'entry is not an npm source').toBe('npm');
      // A `source.version` pin is tolerated and not asserted either way: it is
      // the npm SPEC the host fetches, which is a release decision rather than
      // an identity this audit can check from the tree.
      const pkg = BY_NAME.get(plugin.source.package);
      expect(
        pkg,
        `served from \`${plugin.source.package}\`, which is not a tracked workspace package — ` +
          'the marketplace would resolve it from npm and this tree does not build it',
      ).toBeDefined();
      expect(pkg.dir.startsWith('plugins/'), `${pkg.name} lives at ${pkg.dir}`).toBe(true);
      expect(pkg.private, `${pkg.name} is private, so npm will never serve it`).not.toBe(true);
    },
  );
});

describe('the shippable set and the one version line', () => {
  it('agrees with the release workflows about what ships, in both directions', () => {
    // Both directions, because each failure is its own kind. A package that is
    // publishable and published by nothing never reaches npm however green the
    // release run looks; a package a workflow publishes while the manifest says
    // private fails the publish itself, at the end of a release.
    expect([...PUBLISHED].sort()).toEqual(PUBLISHABLE.map((p) => p.name).sort());
  });

  it('puts every shippable artifact on ONE version', () => {
    // EQUALITY ONLY. No numeral, no comparison with a tag, no notion of which
    // way a version should move: the numbers are chosen by hand at the
    // scheduled release, so the only thing that can be asserted between
    // releases is that the artifacts a release moves together have moved
    // together.
    const versions = PUBLISHABLE.map((p) => `${p.name}@${p.version}`);
    expect(
      new Set(PUBLISHABLE.map((p) => p.version)).size,
      `the shippable artifacts are on more than one version line: ${versions.join(' ')}`,
    ).toBe(1);
  });
});

describe('every plugin is released or private, never half of each', () => {
  it.each(PLUGIN_PACKAGES.map((p) => [p.dir, p]))('%s', (dir, pkg) => {
    if (!PUBLISHED.has(pkg.name)) {
      expect(
        pkg.private,
        `${pkg.name} is published by no release workflow, so it must be private — a plugins/* ` +
          'package that is neither is one a release silently leaves behind',
      ).toBe(true);
      return;
    }
    const manifest = HOST_MANIFESTS[dir];
    expect(
      manifest,
      `${dir} is released but this guard knows no host manifest path for it, so its version pair ` +
        'is checked by nothing',
    ).toBeDefined();
    expect(
      readJson(`${dir}/${manifest}`).version,
      `${dir}/${manifest} reports a different version from ${dir}/package.json — the host reads ` +
        'the first and npm serves the second',
    ).toBe(pkg.version);
  });
});

describe('this task hashes the files this audit reads', () => {
  // The checks here read turbo.json as TEXT, which is a model of turbo's
  // hashing rather than turbo's hashing — the same caveat effective-config.test.js
  // states beside its own. Without them a marketplace entry, a plugin manifest
  // or a publish step could be edited with this task's hash untouched, turbo
  // would replay the cached pass, and every case above would be skipped at the
  // one moment it exists to fire.
  const READS = [
    MARKETPLACE,
    REGISTRY,
    'turbo.json',
    ...PACKAGES.map((p) => `${p.dir}/package.json`),
    ...Object.entries(HOST_MANIFESTS).map(([dir, manifest]) => `${dir}/${manifest}`),
    ...WORKFLOWS,
  ];

  const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
  const block = /"@akasecurity\/eslint-config#test"[\s\S]*?"inputs"\s*:\s*\[([\s\S]*?)\]/.exec(
    turbo,
  );
  const declared = block ? [...block[1].matchAll(/"([^"]*)"/g)].map((m) => m[1]) : [];
  /** @param {string} prefix */
  const rooted = (prefix) =>
    declared.filter((g) => g.startsWith(prefix)).map((g) => g.slice(prefix.length));

  // `path.matchesGlob`'s `**` does not traverse a dot-directory and turbo's does
  // — measured both ways: turbo's resolved input set carries
  // `.claude-plugin/marketplace.json`, while
  // `matchesGlob('.claude-plugin/marketplace.json', '**/*.json')` is false. A
  // glob that spells the dot segment LITERALLY is a different matter and matches
  // either way, which is measured too:
  // `matchesGlob('.github/workflows/release-cli.yml', '.github/workflows/*.yml')`
  // is true. So the dot-directory limit is not a property of the path, it is a
  // property of the glob reaching it — and a read under a dot-directory is
  // covered when EITHER a declared glob matches it outright or the wildcard for
  // its own extension is declared.
  //
  // Both halves are load-bearing and each carries a different read. Modelling
  // dot-directory paths not at all is what left the release workflows asserted
  // by nothing here: they live under `.github/`, so a rule scoped to `.json`
  // covered the three manifests and none of the YAML, and the routing guard
  // beside this one has the workflow TEXT as its entire subject. Measured:
  // narrowing the workflow glob to the one filename another suite in this
  // directory pins, and dropping the `**/*.yml` that also reached the directory,
  // left this package's whole suite green with every release workflow hashed by
  // nothing at all.
  //
  // What neither half reads is an EXCLUSION spelled with a wildcard over a
  // dot-directory: `matchesGlob` cannot see that one either, so a `!` entry of
  // that shape would take a read back out of the hash silently. There is none
  // today and this reading cannot prove there is none tomorrow.
  const DOT_DIRECTORY = /(^|\/)\.[^/]+\//;
  /** The wildcard that reaches a path under a dot-directory by extension. */
  const anyOfExtension = (file) => `$TURBO_ROOT$/**/*${extname(file)}`;

  const included = rooted('$TURBO_ROOT$/');
  const excluded = rooted('!$TURBO_ROOT$/');
  /** @param {string} file */
  const matchedOutright = (file) =>
    included.some((glob) => matchesGlob(file, glob)) &&
    !excluded.some((glob) => matchesGlob(file, glob));
  /** @param {string} file */
  const hashed = (file) =>
    matchedOutright(file) || (DOT_DIRECTORY.test(file) && declared.includes(anyOfExtension(file)));

  it('declares inputs at all', () => {
    expect(block, '@akasecurity/eslint-config#test declares no `inputs`').not.toBeNull();
    expect(declared.length, 'the inputs block parsed to no globs').toBeGreaterThan(0);
    expect(
      READS.length,
      'this audit reads no files, so the cases below assert nothing',
    ).toBeGreaterThan(5);
  });

  it('reaches every file this audit reads', () => {
    const unhashed = READS.filter((file) => !hashed(file));
    expect(
      unhashed,
      'These files are read by this suite and hashed by none of the task’s turbo inputs, so ' +
        `editing one alone replays a cached green:\n  ${unhashed.join('\n  ')}`,
    ).toEqual([]);
  });

  it('declares the wildcard reaching the reads no literal glob can match', () => {
    // The reads that need the second half of `hashed` — under a dot-directory
    // and matched by no declared glob outright. Non-vacuity first: with none of
    // them, the case above is modelling every read and this one states nothing.
    const needsWildcard = READS.filter((f) => DOT_DIRECTORY.test(f) && !matchedOutright(f));
    expect(
      needsWildcard.length,
      'every read is matched by a glob outright, so this case is asserting nothing — the check ' +
        'above covers whatever moved',
    ).toBeGreaterThan(0);
    const missing = [...new Set(needsWildcard.map(anyOfExtension))].filter(
      (glob) => !declared.includes(glob),
    );
    expect(
      missing,
      `${needsWildcard.join(', ')} live under a dot-directory, which turbo traverses and ` +
        'path.matchesGlob does not, so these wildcards are what hash them and each has to be ' +
        `declared by name:\n  ${missing.join('\n  ')}`,
    ).toEqual([]);
  });
});
