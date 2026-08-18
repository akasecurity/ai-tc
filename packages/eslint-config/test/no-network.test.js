import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, posix } from 'node:path';
import { pathToFileURL } from 'node:url';

import { ESLint, Linter } from 'eslint';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  base,
  networkGuard,
  noEnterpriseImports,
  noNetworkGlobals,
  noNetworkImports,
  noNetworkProperties,
  noNetworkSyntax,
} from '../src/index.js';
import {
  cardinalFor,
  codeSpansOf,
  CONVENTIONS_DOC,
  countWordIn,
  ordinalFor,
  readConventions,
  sectionOf,
  tableOf,
} from './helpers/claude-md.js';
import {
  lintPassInvocations,
  REPO_ROOT,
  resolveInvocationConfig,
  rootScripts,
  trackedEslintConfigFiles,
  trackedFiles,
  workspaceLintScripts,
} from './helpers/lint-invocations.js';

// These tests lint snippets with the SHIPPED rule values (imported from the
// config, not re-declared here), so a regression that weakens the ban — a
// dropped specifier, a lost merge, a silenced message — fails the suite. They
// assert observable lint output (ruleId + message), not the config's shape.

const linter = new Linter();
const LANG = { ecmaVersion: 'latest', sourceType: 'module' };

/** Lint `code` with the network-ban rules, wired from the config helpers. */
function lintNetwork(code, importOpts) {
  return linter.verify(code, {
    languageOptions: LANG,
    rules: {
      'no-restricted-globals': noNetworkGlobals(),
      'no-restricted-properties': noNetworkProperties(),
      'no-restricted-imports': noNetworkImports(importOpts),
      'no-restricted-syntax': noNetworkSyntax(importOpts),
    },
  });
}

/** Lint `code` with a single rule value (for the merge / base-surface checks). */
function lintWithRules(code, rules) {
  return linter.verify(code, { languageOptions: LANG, rules });
}

// The exact ban set base must enforce — hard-coded so ANY add/drop in the
// shipped list (src/index.js) forces a matching, reviewed change here rather
// than silently shrinking coverage.
const EXPECTED_MODULES = [
  'node:http',
  'http',
  'node:https',
  'https',
  'node:http2',
  'http2',
  'node:net',
  'net',
  'node:dgram',
  'dgram',
  'node:tls',
  'tls',
  'node:dns',
  'dns',
  'node:dns/promises',
  'dns/promises',
  'axios',
  'undici',
  'got',
  'node-fetch',
];
const EXPECTED_GLOBALS = ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'WebTransport'];
// The npm HTTP clients whose subpaths must also be banned (`paths` is exact, so
// a deep import like `axios/lib/adapters/http.js` slips the root ban). Pinned so
// dropping a `<client>/*` group is a reviewed change, not a silent shrink.
const EXPECTED_MODULE_PATTERNS = ['axios/*', 'undici/*', 'got/*', 'node-fetch/*'];

describe('ban set (drift guards)', () => {
  it('no-restricted-imports bans exactly the expected module set', () => {
    const actual = noNetworkImports()[1].paths.map((p) => p.name);
    expect([...actual].sort()).toEqual([...EXPECTED_MODULES].sort());
  });

  it('no-restricted-imports bans exactly the expected subpath patterns', () => {
    const actual = noNetworkImports()[1].patterns.map((p) => p.group[0]);
    expect([...actual].sort()).toEqual([...EXPECTED_MODULE_PATTERNS].sort());
  });

  it('no-restricted-globals bans exactly the expected global set', () => {
    const actual = noNetworkGlobals()
      .slice(1)
      .map((g) => g.name);
    expect([...actual].sort()).toEqual([...EXPECTED_GLOBALS].sort());
  });
});

describe('base config (the real enforcement surface)', () => {
  // Every workspace package lints with `...base`, so the rules must be wired
  // HERE, not merely returned by the helpers. Deleting the wiring from base
  // fails these tests — the helper-only tests would stay green.
  const ruleBlock = base.find((c) => c.rules?.['no-restricted-globals']);
  const KEYS = [
    'no-restricted-globals',
    'no-restricted-properties',
    'no-restricted-imports',
    'no-restricted-syntax',
  ];

  it('wires all four network rules', () => {
    expect(ruleBlock).toBeDefined();
    for (const key of KEYS) expect(ruleBlock?.rules?.[key], key).toBeDefined();
  });

  it('actually fires every rule on real code', () => {
    const rules = Object.fromEntries(KEYS.map((k) => [k, ruleBlock?.rules?.[k]]));
    const code = [
      "import http from 'node:http';",
      "fetch('/x');",
      "await import('node:https');",
      'globalThis.fetch();',
    ].join('\n');
    const fired = new Set(lintWithRules(code, rules).map((m) => m.ruleId));
    for (const key of KEYS) expect(fired, key).toContain(key);
  });
});

describe('no-network globals', () => {
  it('flags a bare fetch() call with a local-first message', () => {
    const messages = lintNetwork("const r = fetch('https://api.example.com/v1');");
    expect(messages).toHaveLength(1);
    expect(messages[0].ruleId).toBe('no-restricted-globals');
    expect(messages[0].message).toContain('local-first');
  });

  it.each(EXPECTED_GLOBALS)('flags the %s global', (name) => {
    // `new X()` covers the constructor globals; `fetch` is called instead.
    const code = name === 'fetch' ? `${name}('/x');` : `new ${name}('/x');`;
    expect(lintNetwork(code).map((m) => m.ruleId)).toContain('no-restricted-globals');
  });

  it('does NOT flag a property named fetch (member access, not the global)', () => {
    const messages = lintNetwork('const db = { fetch() { return 1; } };\ndb.fetch();\n');
    expect(messages).toHaveLength(0);
  });

  it('does NOT flag a locally declared binding named fetch', () => {
    const messages = lintNetwork('function fetch() { return 1; }\nfetch();\n');
    expect(messages).toHaveLength(0);
  });
});

describe('no-network container-global properties', () => {
  it.each([
    'globalThis.fetch()',
    'window.fetch("/x")',
    'self.fetch("/x")',
    'new global.WebSocket("/x")',
    'new globalThis.EventSource("/x")',
    'new window.XMLHttpRequest()',
    'new globalThis.WebTransport("/x")',
  ])('flags %s (the member-access bypass)', (code) => {
    const messages = lintNetwork(code);
    expect(messages.map((m) => m.ruleId)).toContain('no-restricted-properties');
    expect(messages[0].message).toContain('local-first');
  });

  it('flags navigator.sendBeacon (a fire-and-forget POST)', () => {
    const messages = lintNetwork('navigator.sendBeacon("/x", data);');
    expect(messages.map((m) => m.ruleId)).toContain('no-restricted-properties');
  });

  it('does NOT flag an unrelated container-global property (window.location)', () => {
    const messages = lintNetwork('const href = window.location.href;');
    expect(messages).toHaveLength(0);
  });

  it('does NOT flag an unrelated navigator property (navigator.clipboard)', () => {
    const messages = lintNetwork('await navigator.clipboard.readText();');
    expect(messages).toHaveLength(0);
  });
});

describe('no-network static imports', () => {
  it.each(EXPECTED_MODULES)('flags a static import of %s', (mod) => {
    const messages = lintNetwork(`import x from '${mod}';`);
    expect(messages).toHaveLength(1);
    expect(messages[0].ruleId).toBe('no-restricted-imports');
    expect(messages[0].message).toContain('local-first');
  });

  it('flags a namespace import (import * as http)', () => {
    const messages = lintNetwork("import * as http from 'node:http';");
    expect(messages.map((m) => m.ruleId)).toContain('no-restricted-imports');
  });

  it('does NOT flag a local-store import', () => {
    const messages = lintNetwork("import { openLocalDatabase } from '@akasecurity/persistence';");
    expect(messages).toHaveLength(0);
  });

  describe('file-scoped allow opt-out', () => {
    it('permits an allowed specifier (the dashboard bind probe)', () => {
      const messages = lintNetwork("import { createServer } from 'node:net';", {
        allow: ['node:net'],
      });
      expect(messages).toHaveLength(0);
    });

    it('still bans every other module under the same opt-out', () => {
      const messages = lintNetwork("import http from 'node:http';", { allow: ['node:net'] });
      expect(messages.map((m) => m.ruleId)).toContain('no-restricted-imports');
    });

    it('bans node:net by default (justifying the dashboard opt-out)', () => {
      const messages = lintNetwork("import { createServer } from 'node:net';");
      expect(messages).toHaveLength(1);
      expect(messages[0].ruleId).toBe('no-restricted-imports');
    });
  });
});

describe('no-network subpath imports (npm HTTP clients)', () => {
  // `paths` is exact-match, so the root ban misses a deep import; a `<client>/*`
  // pattern closes it. These pin that the subpath ban fires in every import form.
  it.each([
    'axios/lib/adapters/http.js',
    'undici/types/dispatcher',
    'got/dist/source',
    'node-fetch/lib/index.js',
  ])('flags a deep static import of %s', (mod) => {
    const messages = lintNetwork(`import x from '${mod}';`);
    expect(messages.map((m) => m.ruleId)).toContain('no-restricted-imports');
  });

  it('flags a deep dynamic import and a deep require of a client subpath', () => {
    expect(
      lintNetwork("await import('axios/lib/adapters/http.js');").map((m) => m.ruleId),
    ).toContain('no-restricted-syntax');
    expect(lintNetwork("require('undici/types/dispatcher');").map((m) => m.ruleId)).toContain(
      'no-restricted-syntax',
    );
  });

  it('does NOT flag a package that merely shares a name prefix, or a local subpath', () => {
    // `got/*` must not match `got-cha`; a local-store subpath is fine.
    expect(lintNetwork("import g from 'got-cha/client';")).toHaveLength(0);
    expect(lintNetwork("import { x } from '@akasecurity/persistence/read';")).toHaveLength(0);
  });

  it('the subpath ban is allow-aware (opting out a client clears its subpaths)', () => {
    expect(
      lintNetwork("import x from 'axios/lib/adapters/http.js';", { allow: ['axios'] }),
    ).toHaveLength(0);
    expect(lintNetwork("await import('axios/lib/x.js');", { allow: ['axios'] })).toHaveLength(0);
    // but a different client stays banned under the same opt-out
    expect(
      lintNetwork("import u from 'undici/x.js';", { allow: ['axios'] }).map((m) => m.ruleId),
    ).toContain('no-restricted-imports');
  });
});

describe('no-network dynamic imports and require', () => {
  it.each(EXPECTED_MODULES)("flags a dynamic import('%s')", (mod) => {
    const messages = lintNetwork(`await import('${mod}');`);
    expect(messages.map((m) => m.ruleId)).toContain('no-restricted-syntax');
    expect(messages[0].message).toContain('local-first');
  });

  it.each(EXPECTED_MODULES)("flags a require('%s')", (mod) => {
    const messages = lintNetwork(`require('${mod}');`);
    expect(messages.map((m) => m.ruleId)).toContain('no-restricted-syntax');
  });

  it.each([
    // Non-literal specifier — the runtime dashboard server import.
    'await import(serverUrl.href);',
    // require.resolve is a path lookup, not a module load.
    "require.resolve('next/dist/bin/next');",
    // Local / workspace modules are fine.
    "await import('@akasecurity/web-ui');",
    "require('./local.js');",
  ])('does NOT flag %s', (code) => {
    const messages = lintNetwork(code);
    expect(messages).toHaveLength(0);
  });

  it('opt-out is symmetric: allowing node:net clears the dynamic form too', () => {
    expect(lintNetwork("await import('node:net');", { allow: ['node:net'] })).toHaveLength(0);
    expect(lintNetwork("require('node:net');", { allow: ['node:net'] })).toHaveLength(0);
    // but a different module stays banned under the same opt-out
    expect(lintNetwork("await import('node:http');", { allow: ['node:net'] })).toHaveLength(1);
  });
});

describe('networkGuard (the scripts/ pass)', () => {
  // networkGuard is the standalone config used to lint dev/CI scripts. It must
  // catch every network form but NOT the source-only conventions (no-console,
  // n/no-process-env, import sorting), which would be noise on dev tooling.
  it.each([
    ['static import', "import http from 'node:http';", 'no-restricted-imports'],
    ['dynamic import', "await import('undici');", 'no-restricted-syntax'],
    ['require', "require('got');", 'no-restricted-syntax'],
    ['global', "fetch('/x');", 'no-restricted-globals'],
    ['container global', 'globalThis.fetch();', 'no-restricted-properties'],
  ])('flags a %s', (_label, code, ruleId) => {
    const messages = linter.verify(code, networkGuard);
    expect(messages.map((m) => m.ruleId)).toContain(ruleId);
  });

  it('does NOT enforce source-only conventions (console / process.env / import order)', () => {
    const code = [
      "import b from 'b';",
      "import a from 'a';",
      'console.log(process.env.HOME);',
      'const unused = 1;',
    ].join('\n');
    const messages = linter.verify(code, networkGuard);
    expect(messages).toHaveLength(0);
  });
});

describe('noEnterpriseImports merge', () => {
  // The enterprise config is layered on top of `base` in some packages. Flat
  // config does not merge two no-restricted-imports entries, so this config must
  // carry the network bans forward or those packages would silently lose them.
  const entry = noEnterpriseImports.find((c) => c.rules?.['no-restricted-imports']);
  const ruleValue = entry?.rules?.['no-restricted-imports'];

  it('is present', () => {
    expect(ruleValue).toBeDefined();
  });

  it('still bans network modules (the merge preserved base coverage)', () => {
    const messages = lintWithRules("import axios from 'axios';", {
      'no-restricted-imports': ruleValue,
    });
    expect(messages).toHaveLength(1);
    expect(messages[0].ruleId).toBe('no-restricted-imports');
  });

  it('also bans the enterprise HTTP client', () => {
    const messages = lintWithRules("import c from '@akasecurity/client';", {
      'no-restricted-imports': ruleValue,
    });
    expect(messages).toHaveLength(1);
    expect(messages[0].message).toContain('enterprise-only');
  });

  it('keeps BOTH pattern groups (network subpaths + enterprise) after the merge', () => {
    // The network `<client>/*` groups are prepended to noEnterpriseImports' own
    // `patterns` (drizzle-orm/*, schema-enterprise/*). A regressed merge that
    // declared only enterprise patterns would drop the network subpath ban.
    const deep = lintWithRules("import x from 'axios/lib/adapters/http.js';", {
      'no-restricted-imports': ruleValue,
    });
    expect(deep.map((m) => m.ruleId)).toContain('no-restricted-imports');
    const ent = lintWithRules("import s from 'drizzle-orm/sqlite-core';", {
      'no-restricted-imports': ruleValue,
    });
    expect(ent.map((m) => m.ruleId)).toContain('no-restricted-imports');
  });
});

// ---------------------------------------------------------------------------
// The documented opt-out allowlist
// ---------------------------------------------------------------------------

// CLAUDE.md §4 lists the files allowed to import a network module, and tells the
// next author "adding a third site means updating this table". Nothing enforced
// that: the table is prose, the opt-outs are `allow:` options in eslint configs,
// and the two could drift apart silently — the same containment problem the
// egress copy guards exist to solve, one layer down.
//
// This resolves each config as a MODULE and inspects the rule values it actually
// produces, rather than grepping its bytes. Reading the resolved value is what
// makes the audit hold up: an opt-out written `allow: NET_ALLOW` (a hoisted const
// shared by the two rule calls — the natural way to write it) is invisible to a
// literal-array regex, so a byte-level collector would report the documented set
// and stay green with a third site present. It also cannot false-positive on the
// unrelated rules that happen to take an `allow:` option (`no-empty-function`
// among them), because it only ever diffs the network-module ban.
//
// The set is asserted EXACTLY, not as a superset: a guard that only forbids
// removals would let a third site in.
//
// WHICH configs it inspects is derived the same way: from the eslint invocations
// a green `pnpm lint` really runs — each one's `-c`/`--config` override, and for
// an invocation carrying none, the config ordinary flat-config lookup finds from
// the directory that invocation runs in. A filename glob was the earlier answer
// and is a hole one rename wide: ESLint honours `-c eslint.extra.config.js`
// exactly like the two conventional names, so a config under any other name was
// referenced by a lint script, applied on every pass, and inspected by nobody —
// while the suite's own count went UP, because the extra invocation generates
// more probe targets elsewhere. The reverse drift is reported too: a config
// sitting in the tree that no invocation runs enforces nothing while looking
// exactly like the ones that do, and silently ignoring it reopens the same hole
// from the other side.
//
// Budget for the one-off config load below. Deliberately generous: it bounds a
// hang, it is not a performance assertion. The load measured ~4.7s on a CI
// runner under full workspace parallelism against ~0.25s on a developer
// machine, so the headroom absorbs a slower or more contended one without
// loosening the per-test default that guards every other test in this file.
const CONFIG_LOAD_TIMEOUT_MS = 60_000;

// Keyed by CONFIG, not by site, and deliberately so: what it mirrors is the
// SPECIFIER claim, which a config grants once for every site it scopes to, so
// site-level keying here would duplicate a value rather than assert a new one.
// The site claim — WHICH files each exception reaches — is asserted directly
// against the configs by `scopes every opt-out to a site the table names`, in
// both directions, so it needs no mirror to drift from. Read the two together:
// this constant is the specifier half, that check is the site half.
const DOCUMENTED_OPT_OUTS = {
  'cli/eslint.config.mjs': ['node:net'],
  'cli/eslint.scripts.config.mjs': ['node:http'],
  // The repo-root config lints the vitest no-network guard (which imports all
  // three transports it patches) and the CI egress probe (node:net). Both are
  // file-scoped; see CLAUDE.md §4.
  'eslint.root.config.mjs': ['node:dgram', 'node:dns', 'node:net'],
  // The eslint-config package's own second `lint` pass gives its no-network suites
  // network-only coverage; it opts out no-network-runtime.test.js, which imports
  // the three transports it drives at runtime. File-scoped; see CLAUDE.md §4.
  'packages/eslint-config/eslint.guard.config.mjs': ['node:dgram', 'node:dns', 'node:net'],
  // The installer suite stands a loopback HTTP server so the shipped
  // install.sh / install.ps1 can be driven against a local base. File-scoped
  // to the one helper that binds it; see CLAUDE.md §4.
  'tools/installer/eslint.config.mjs': ['node:http'],
};

/** The module names a resolved `no-restricted-imports` value bans, or null if absent. */
function bannedNamesOf(ruleEntry) {
  if (!Array.isArray(ruleEntry)) return null;
  const opts = ruleEntry[1];
  if (typeof opts !== 'object' || opts === null || !Array.isArray(opts.paths)) return null;
  return new Set(opts.paths.map((entry) => entry.name));
}

/**
 * The network specifiers a config entry PERMITS that the shipped default bans.
 * Derived by differencing against `noNetworkImports()` with no allow list, so it
 * keeps no copy of the module list and cannot drift from it.
 */
function networkSpecifiersPermittedBy(rules) {
  const banned = bannedNamesOf(rules?.['no-restricted-imports']);
  if (banned === null) return [];
  const shipped = bannedNamesOf(noNetworkImports());
  return [...shipped].filter((name) => !banned.has(name));
}

/**
 * The `files:` patterns of every entry in a flat config that PERMITS a network
 * specifier — that is, the sites the config's exception actually reaches.
 *
 * The patterns are taken verbatim rather than expanded against the tree, and
 * that is the whole point of this derivation. Expanding would compare the files
 * that exist TODAY: widening `tools/ci/egress-probe.mjs` to `tools/ci/*.mjs`
 * expands to the same single file while silently granting the exception to every
 * `.mjs` added there afterwards, which is the edit §4's "file-scoped, never
 * package-wide" promise exists to forbid. Comparing the pattern catches it at
 * the moment it is written, not at the moment someone lands a second file.
 *
 * `files` entries may nest (flat config reads an inner array as AND), so the
 * list is flattened before comparison.
 * @param {{ files?: unknown, rules?: Record<string, unknown> }[]} entries
 * @returns {string[]}
 */
const optOutFilePatterns = (entries) =>
  entries
    .filter((entry) => networkSpecifiersPermittedBy(entry.rules).length > 0)
    .flatMap((entry) => {
      // No `files` at all is the package-wide opt-out §4 forbids outright.
      // Reported as `undefined` rather than as no pattern: contributing nothing
      // would leave the entry invisible here and every tabled site for its
      // config then named as one the config "no longer scopes" — one edit, two
      // complaints, and the actionable one missing.
      if (entry.files === undefined) return [undefined];
      return /** @type {(string | undefined)[]} */ (
        [entry.files].flat().map((f) =>
          // Flat config reads a NESTED array as AND — a file must match every
          // element — which this resolution cannot model. Joined into one token
          // so it is refused as unscoped rather than flattened into two
          // independent site claims, neither of which ESLint actually applies.
          Array.isArray(f) ? f.join(' + ') : f,
        )
      );
    });

/**
 * Whether a `files:` pattern is FILE-scoped in §4's sense: its final segment is
 * a literal filename. This is the property the section actually promises — "All
 * are file-scoped, never package-wide" — and the one the existing audit cannot
 * express, because that check only asks whether `files` is present at all, which
 * a directory glob satisfies just as well as a filename.
 *
 * A leading `**\/` or directory glob is fine and is how three real opt-outs are
 * written; what must stay literal is the basename, because that is the segment
 * deciding whether the exception can reach a file nobody has written yet.
 * `tools/ci/egress-probe.mjs` names one file for ever; `tools/ci/*.mjs` grants
 * the exception to every `.mjs` added to that directory afterwards.
 * @param {string} pattern
 */
const isFileScopedPattern = (pattern) => !/[*?[{]/.test(posix.basename(pattern));

/**
 * The tracked files a file-scoped opt-out pattern designates, repo-relative.
 *
 * A pattern with no glob at all names exactly one path under the config's own
 * directory. One carrying a directory glob (`**\/x.ts`) is resolved by BASENAME
 * against the tracked tree beneath that directory — a lookup, not a second glob
 * engine, which is why this is deliberately limited to the leading-directory-glob
 * shape the workspace actually uses. A pattern whose directory part is anything
 * more elaborate would resolve too widely here, and `isFileScopedPattern` is what
 * keeps the interesting axis (the basename) exact.
 * @param {string} via config path, repo-relative posix
 * @param {string} pattern
 * @param {string[]} tracked
 */
function sitesDesignatedBy(via, pattern, tracked) {
  const dir = dirname(via);
  const base = dir === '.' ? '' : `${dir}/`;
  if (!/[*?[{]/.test(pattern)) return [`${base}${pattern}`];
  const name = posix.basename(pattern);
  return tracked.filter((f) => f.startsWith(base) && posix.basename(f) === name);
}

/**
 * Everything wrong between the opt-outs the CONFIGS carry and the sites §4
 * tables, in both directions. Pure over its inputs, so the failure paths are
 * drivable with synthetic configs the way the sibling suite's `configViolations`
 * is — a healthy tree produces none of them by construction, which would
 * otherwise leave every branch here unexecuted and a deleted check green.
 * @param {{ patternsByConfig: Map<string, string[]>,
 *   tabledSitesByConfig: Map<string, string[]>, tracked: string[] }} input
 * @returns {string[]}
 */
function optOutSiteProblems({ patternsByConfig, tabledSitesByConfig, tracked }) {
  const problems = [];
  for (const [via, patterns] of patternsByConfig) {
    const tabled = tabledSitesByConfig.get(via) ?? [];
    const reached = [];
    // Whether any pattern here is unresolvable — see the tabled-site loop below.
    let unscoped = false;
    for (const pattern of patterns) {
      if (pattern === undefined) {
        problems.push(
          `${via} carries a network opt-out with no \`files:\` scope at all, so it applies ` +
            `package-wide. ${CONVENTIONS_DOC} §4 requires every opt-out to be file-scoped — ` +
            'scope it to the file that needs it.',
        );
        unscoped = true;
        continue;
      }
      // §4: "All are file-scoped, never package-wide." A basename carrying a
      // glob is the edit that quietly widens an exception to files nobody has
      // written, and it is invisible to a resolved-file comparison: the set it
      // reaches TODAY is unchanged, so that check passes and only fails once
      // somebody lands a second file.
      if (!isFileScopedPattern(pattern)) {
        problems.push(
          `${via} scopes a network opt-out to \`${pattern}\`, whose final segment is a glob. ` +
            `${CONVENTIONS_DOC} §4 requires each opt-out to be file-scoped, never package-wide — ` +
            'this one also covers every matching file added later. Name the file.',
        );
        unscoped = true;
        continue;
      }
      reached.push(...sitesDesignatedBy(via, pattern, tracked));
    }
    for (const site of reached) {
      if (!tabled.includes(site)) {
        problems.push(
          `${via} opts \`${site}\` out of the network ban and no ${CONVENTIONS_DOC} §4 row ` +
            'names it. §4 closes with "Adding another opt-out site means updating this table" — ' +
            'add the row.',
        );
      }
    }
    // Skipped once any pattern was rejected above: a globbed basename cannot be
    // resolved to the files it covers (the resolution is a basename lookup, not
    // a glob engine), so `reached` under-reports and every tabled site would be
    // named a second time as dropped — two complaints for one edit, the second
    // of them false. The glob complaint is the actionable one; let it stand
    // alone, and this direction returns as soon as the pattern is a filename.
    for (const site of unscoped ? [] : tabled) {
      if (!reached.includes(site)) {
        problems.push(
          `${CONVENTIONS_DOC} §4 tables \`${site}\` as opted out via ${via}, but that config ` +
            'no longer scopes its network opt-out to it. Remove the row, or restore the pattern.',
        );
      }
    }
  }
  return problems;
}

/**
 * Every config a green `pnpm lint` really points ESLint at, repo-relative posix
 * and deduplicated, plus the ones a lint invocation names that are not on disk.
 * @param {{ rootScripts?: Record<string, unknown>, packages: { dir: string, lintScript: string }[] }} manifests
 * @param {string} repoRoot
 */
async function configsInPlay({ rootScripts: scripts, packages }, repoRoot = REPO_ROOT) {
  const inPlay = [];
  const missing = [];
  const seen = new Set();
  for (const entry of lintPassInvocations({ rootScripts: scripts, packages })) {
    const file = await resolveInvocationConfig(entry, repoRoot);
    if (file === undefined || seen.has(file)) continue;
    seen.add(file);
    // A `-c` naming a file that is not there means that invocation exits 2 and
    // lints nothing. Reported on its own rather than folded into a load failure,
    // which would name the same file for a much less obvious reason.
    (existsSync(join(repoRoot, ...file.split('/'))) ? inPlay : missing).push(file);
  }
  return { inPlay: inPlay.sort(), missing: missing.sort() };
}

describe('documented no-network opt-outs (CLAUDE.md §4)', () => {
  /** The configs a green `pnpm lint` runs — the set this suite audits. */
  let configs = [];
  /** Configs a lint invocation names that are not on disk. */
  let missingConfigs = [];
  /**
   * Configs whose NAME reads as an ESLint flat config, whatever runs them. The
   * discovery half, kept separate from the derivation above so the two can be
   * differenced: what one finds and the other does not is the drift.
   */
  const trackedConfigs = trackedEslintConfigFiles();

  /** Each audited config's module, resolved once below. */
  const configModules = new Map();
  /** Load failures, kept per file so a broken config names itself. */
  const loadFailures = new Map();

  // Importing every flat config pulls the whole typescript-eslint stack and is
  // filesystem- and resolution-bound, so on a contended runner it costs many
  // times what it does on a developer machine — past a default per-test timeout.
  // Resolve once here under the hook's own budget; the tests below are then fast
  // assertions on the cached result and keep vitest's tight per-test default,
  // which still guards them. Mirrors effective-config.test.js's
  // RESOLVE_TIMEOUT_MS, for the same reason.
  //
  // Settled individually rather than through Promise.all's fail-fast: one broken
  // config should name itself instead of hiding the other 17 behind whichever
  // happened to reject first.
  beforeAll(async () => {
    ({ inPlay: configs, missing: missingConfigs } = await configsInPlay({
      rootScripts: rootScripts(),
      packages: workspaceLintScripts(),
    }));
    const results = await Promise.allSettled(
      configs.map((file) => import(pathToFileURL(join(REPO_ROOT, file)).href)),
    );
    results.forEach((result, i) => {
      const file = configs[i];
      if (result.status === 'fulfilled') configModules.set(file, result.value);
      else loadFailures.set(file, result.reason);
    });
  }, CONFIG_LOAD_TIMEOUT_MS);

  // A guard that found no configs would pass every assertion below vacuously.
  it('found the workspace ESLint configs to audit', () => {
    expect(configs.length).toBeGreaterThanOrEqual(Object.keys(DOCUMENTED_OPT_OUTS).length);
    for (const documented of Object.keys(DOCUMENTED_OPT_OUTS)) {
      expect(
        configs,
        `${documented} carries a documented opt-out but no eslint invocation reachable from ` +
          '`pnpm lint` runs it, so nothing here inspects it',
      ).toContain(documented);
    }
    // A config that failed to load contributes nothing to `found`, so an
    // undocumented opt-out inside it would be invisible below — the same
    // vacuous pass this guard exists to prevent. Name every failure.
    expect(
      [...loadFailures].map(([file, cause]) => `${file}: ${String(cause)}`),
      'workspace ESLint configs failed to load, so the audit below is partial',
    ).toEqual([]);
  });

  it('every config a lint invocation names is on disk', () => {
    expect(
      missingConfigs,
      missingConfigs.length
        ? 'A `lint` script points eslint at these config files with -c/--config and they are not ' +
            `there. That invocation exits 2 having linted nothing:\n  ${missingConfigs.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });

  it('runs every ESLint config the tree ships — none is dead, none is unnamed', () => {
    // Both directions of the same drift, asserted together because each is only
    // half the property. A config the tree ships that no invocation runs
    // enforces nothing while reading like a lint surface; a config an invocation
    // runs whose name no convention matches enforces everything while being
    // findable by nobody looking for configs. The first is caught by
    // differencing the tracked set against the derived one, the second by the
    // derived set being what the audit below actually inspects.
    const dead = trackedConfigs.filter((file) => !configs.includes(file));
    expect(
      dead,
      dead.length
        ? 'These files are named like ESLint flat configs and no eslint invocation reachable from ' +
            '`pnpm lint` runs any of them. A dead config enforces nothing while looking exactly ' +
            'like the ones that do — point a `lint` script at it, or delete it:\n  ' +
            dead.join('\n  ')
        : undefined,
    ).toEqual([]);
    // The other side is not an error — a config may legitimately be named
    // anything — but it is worth seeing, so it is asserted as the empty set the
    // tree has today rather than left unobserved.
    const unnamed = configs.filter((file) => !trackedConfigs.includes(file));
    expect(
      unnamed,
      unnamed.length
        ? 'These configs are run by a `lint` script under a name no filename convention matches. ' +
            'They ARE audited (the derivation finds them through the invocation that names them), ' +
            'but nothing looking for configs by name will find them — rename to `*eslint*.config.*` ' +
            `or accept this list deliberately:\n  ${unnamed.join('\n  ')}`
        : undefined,
    ).toEqual([]);
  });

  it('has exactly the opt-out sites CLAUDE.md §4 documents, each file-scoped', () => {
    /** @type {Record<string, string[]>} */
    const found = {};
    for (const [file, mod] of configModules) {
      for (const entry of mod.default) {
        const permitted = networkSpecifiersPermittedBy(entry.rules);
        if (permitted.length === 0) continue;
        // §4: "Both are file-scoped, never package-wide". Asserted on the entry
        // that actually carries the exception, so a config growing an unrelated
        // `files:` block elsewhere cannot satisfy it by proximity.
        expect(entry.files, `${file}: network opt-out is package-wide`).toBeDefined();
        found[file] = [...new Set([...(found[file] ?? []), ...permitted])].sort();
      }
    }
    expect(found).toEqual(DOCUMENTED_OPT_OUTS);
  });

  // §4 also claims each opt-out "drop[s] the static and dynamic bans together so
  // the exception holds whichever import form the file uses". Asserted
  // behaviourally through the real linter rather than by matching the generated
  // esquery selector, whose escaping is an implementation detail.
  it('permits its specifier in both the static and the dynamic form', () => {
    for (const [file, specifiers] of Object.entries(DOCUMENTED_OPT_OUTS)) {
      const mod = configModules.get(file);
      expect(mod, `${file}: config was not loaded`).toBeDefined();
      const optOut = mod.default.find(
        (entry) => networkSpecifiersPermittedBy(entry.rules).length > 0,
      );
      expect(optOut, `${file}: no opt-out entry found`).toBeDefined();
      for (const specifier of specifiers) {
        const rules = {
          'no-restricted-imports': optOut.rules['no-restricted-imports'],
          'no-restricted-syntax': optOut.rules['no-restricted-syntax'],
        };
        expect(
          lintWithRules(`import x from '${specifier}';`, rules),
          `${file}: static import of ${specifier} still banned`,
        ).toHaveLength(0);
        expect(
          lintWithRules(`await import('${specifier}');`, rules),
          `${file}: dynamic import of ${specifier} still banned`,
        ).toHaveLength(0);
      }
    }
  });
});

describe('which configs the audit inspects (tested on synthetic manifests)', () => {
  // The real tree is healthy, so the derivation above only ever sees the shape
  // that works. Drive it directly on the shapes that broke it.
  const invocationsOf = (packages, scripts) =>
    lintPassInvocations({ rootScripts: scripts, packages });
  const configsOf = (packages, scripts) =>
    invocationsOf(packages, scripts).map((e) => [e.cwd, e.invocation.configName]);

  it('reads a config named outside the two conventional names', () => {
    // The hole this derivation closes. `eslint.extra.config.js` is referenced by
    // the lint script and honoured by ESLint exactly like its two neighbours,
    // and matches neither the name effective-config.test.js requires nor the
    // `*eslint*.config.mjs` glob that used to decide what got audited.
    expect(
      configsOf([
        {
          dir: 'cli',
          lintScript:
            'eslint src test *.config.* && ' +
            'eslint --no-config-lookup -c eslint.extra.config.js scripts',
        },
      ]),
    ).toEqual([
      ['cli', undefined],
      ['cli', 'eslint.extra.config.js'],
    ]);
  });

  it('reads the `--config=<file>` spelling as well as `-c <file>`', () => {
    // Three spellings of one flag. An unread one does not cost a lint target —
    // it costs the whole question of which rules that invocation enforced, and
    // the config drops out of the audit while ESLint honours it.
    for (const flag of ['-c x.config.js', '--config x.config.js', '--config=x.config.js']) {
      expect(configsOf([{ dir: 'pkg', lintScript: `eslint ${flag} src` }]), flag).toEqual([
        ['pkg', 'x.config.js'],
      ]);
    }
    // The quoted `=` form tokenizes as the flag with a trailing `=` plus the
    // quoted value, so it takes the next token.
    expect(configsOf([{ dir: 'pkg', lintScript: "eslint --config='x.config.js' src" }])).toEqual([
      ['pkg', 'x.config.js'],
    ]);
  });

  it('records --no-config-lookup, so an invocation that runs under no config is not credited one', () => {
    const [bare] = invocationsOf([{ dir: 'pkg', lintScript: 'eslint src' }]);
    expect(bare.invocation.noConfigLookup).toBe(false);
    const [suppressed] = invocationsOf([
      { dir: 'pkg', lintScript: 'eslint --no-config-lookup src' },
    ]);
    expect(suppressed.invocation.noConfigLookup).toBe(true);
  });

  it('pairs each invocation with the directory it runs in', () => {
    // `turbo run lint` runs each package's script with that package as the
    // working directory, which is what decides where a bare `eslint src` looks
    // for its config. The root pass runs at the repo root, spelled ''.
    expect(
      configsOf(
        [
          { dir: 'cli', lintScript: 'eslint src' },
          { dir: 'packages/schema', lintScript: 'eslint -c eslint.scripts.config.mjs scripts' },
        ],
        {
          lint: 'turbo run lint && pnpm lint:root',
          'lint:root': 'eslint -c eslint.root.config.mjs .',
        },
      ),
    ).toEqual([
      ['', 'eslint.root.config.mjs'],
      ['cli', undefined],
      ['packages/schema', 'eslint.scripts.config.mjs'],
    ]);
  });

  it('does NOT credit a config to an invocation a green run never reaches', () => {
    // The same rule the coverage check applies, and for the same reason: behind
    // a `||` the second call runs only once the first has failed, so a green
    // pass never enforces whatever that config says. Auditing it would report a
    // ruleset nothing runs; the loud direction is to leave it uncredited, where
    // the dead-config check names it.
    for (const lintScript of [
      'eslint src || eslint -c eslint.extra.config.js scripts',
      'eslint -c eslint.extra.config.js scripts || true',
      'eslint src ; eslint -c eslint.extra.config.js scripts',
    ]) {
      expect(
        configsOf([{ dir: 'pkg', lintScript }]).map(([, config]) => config),
        lintScript,
      ).not.toContain('eslint.extra.config.js');
    }
    // The control: chained with `&&`, the same call IS credited — otherwise
    // every case above would pass on a derivation that had stopped reading
    // config flags at all.
    expect(
      configsOf([
        { dir: 'pkg', lintScript: 'eslint src && eslint -c eslint.extra.config.js scripts' },
      ]),
    ).toEqual([
      ['pkg', undefined],
      ['pkg', 'eslint.extra.config.js'],
    ]);
  });

  it('finds nothing when no script invokes eslint', () => {
    expect(configsOf([{ dir: 'pkg', lintScript: "echo 'no self-lint'" }], {})).toEqual([]);
  });
});

describe('an odd-named config carrying an undocumented opt-out is audited (throwaway tree)', () => {
  // The end of the chain, run against real ESLint in a tree of its own. The two
  // suites either side of this one reason about strings; this one plants the
  // exact shape the filename glob missed — a config the lint script references
  // under a third name, carrying a network opt-out nothing documents — and
  // asserts the derivation reaches it AND that the rule it replaced does not.
  //
  // Built outside the repo rather than in a package root: the tree's own
  // derivations read `git ls-files`, and a planted sibling would race the suites
  // that walk it.
  let dir = '';
  const SHARED = pathToFileURL(join(REPO_ROOT, 'packages/eslint-config/src/index.js')).href;
  const config = (allow) =>
    `import { networkGuard, noNetworkImports, noNetworkSyntax } from ${JSON.stringify(SHARED)};\n` +
    'export default [\n' +
    '  ...networkGuard,\n' +
    '  {\n' +
    "    files: ['**/*.mjs'],\n" +
    '    rules: {\n' +
    `      'no-restricted-imports': noNetworkImports({ allow: ${JSON.stringify(allow)} }),\n` +
    `      'no-restricted-syntax': noNetworkSyntax({ allow: ${JSON.stringify(allow)} }),\n` +
    '    },\n' +
    '  },\n' +
    '];\n';

  const PACKAGES = [
    {
      dir: 'pkg',
      lintScript:
        'eslint src test *.config.* && eslint --no-config-lookup -c eslint.extra.config.js scripts',
    },
  ];

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-lint-config-audit-'));
    const pkgDir = join(dir, 'pkg');
    mkdirSync(pkgDir, { recursive: true });
    // The two configs the package really runs: the conventional one ordinary
    // lookup finds, and the odd-named one the lint script names with `-c`. Only
    // the second carries an opt-out.
    writeFileSync(join(pkgDir, 'eslint.config.mjs'), config([]));
    writeFileSync(join(pkgDir, 'eslint.extra.config.js'), config(['undici']));
  });

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('finds exactly the two configs the lint script runs', async () => {
    const { inPlay, missing } = await configsInPlay({ rootScripts: {}, packages: PACKAGES }, dir);
    // Both branches of the derivation at once: the first invocation carries no
    // `-c` and resolves through ordinary lookup, the second names a file no
    // filename convention matches.
    expect(inPlay).toEqual(['pkg/eslint.config.mjs', 'pkg/eslint.extra.config.js']);
    expect(missing).toEqual([]);
  });

  it('reports its undocumented opt-out, where the filename glob reported nothing', async () => {
    const { inPlay } = await configsInPlay({ rootScripts: {}, packages: PACKAGES }, dir);

    /** The opt-out map the audit above builds, over an arbitrary file list. */
    const optOutsOf = async (files) => {
      /** @type {Record<string, string[]>} */
      const found = {};
      for (const file of files) {
        const mod = await import(pathToFileURL(join(dir, ...file.split('/'))).href);
        for (const entry of mod.default) {
          const permitted = networkSpecifiersPermittedBy(entry.rules);
          if (permitted.length) found[file] = permitted.sort();
        }
      }
      return found;
    };

    expect(await optOutsOf(inPlay)).toEqual({ 'pkg/eslint.extra.config.js': ['undici'] });

    // The control, and the whole point: the rule this derivation replaced —
    // `git ls-files '*eslint*.config.mjs'` — matches the conventional config and
    // not the one carrying the opt-out, so it reports an empty map and the
    // suite goes green with a live, unreviewed exception in the tree. Without
    // this half, the assertion above would also pass on a derivation that
    // happened to inspect everything for some unrelated reason.
    const byFilenameGlob = ['pkg/eslint.config.mjs', 'pkg/eslint.extra.config.js'].filter((f) =>
      /(?:^|\/)[^/]*eslint[^/]*\.config\.mjs$/.test(f),
    );
    expect(byFilenameGlob).toEqual(['pkg/eslint.config.mjs']);
    expect(await optOutsOf(byFilenameGlob)).toEqual({});

    // …and ESLint really does honour the odd-named config, so the opt-out above
    // is a live exception rather than a rule value nothing applies.
    const found = await resolveInvocationConfig(
      { cwd: 'pkg', invocation: { configName: 'eslint.extra.config.js', noConfigLookup: true } },
      dir,
    );
    expect(found).toBe('pkg/eslint.extra.config.js');
  });
});

// ---------------------------------------------------------------------------
// The table the allowlist above is documented in
// ---------------------------------------------------------------------------

// DOCUMENTED_OPT_OUTS is a hand-written MIRROR of §4's table, and the audit
// above never opens the document: delete the table, the intro sentence and the
// "adding another site" promise from CLAUDE.md, leave every ESLint config
// untouched, and this whole package stays green. The direction that matters most
// was already closed — a third opt-out cannot land silently, because the
// contributor has to edit DOCUMENTED_OPT_OUTS to get green — but at the moment
// they do, nothing then required them to edit the table, and the document a
// reader opens first would name two sites while three existed.
//
// So the table is read, and asserted twice over. Once against the mirror, which
// is what the ACs above are stated in terms of and what keeps the two from
// drifting apart in either direction. And once against the CONFIGS THEMSELVES,
// through the same linter the workspace runs: a mirror can only ever be as true
// as the thing it mirrors, and the site column carries a claim — WHICH file the
// exception is for — that the mirror does not hold at all and so cannot check.
const SECTION_4 = '### 4. No network calls';
const OPT_OUT_TABLE_HEADER = ['Site', 'Allowed specifier', 'Why'];
/** "Five files carry a genuine local-only opt-out:" */
const SITE_COUNT_SENTENCE = /(\w+) files carry a genuine local-only opt-out/g;
/** "Adding another opt-out site means updating this table." */
const ADDING_SENTENCE = /Adding (?:an? )?(\w+)(?: opt-out)? site means updating this table/g;

describe('optOutSiteProblems (the site check, tested on synthetic configs)', () => {
  // The real tree is healthy, so every branch above returns nothing against it —
  // deleting any one of them keeps the workspace green. Drive them directly.
  const TRACKED = ['tools/ci/egress-probe.mjs', 'tools/ci/second-probe.mjs', 'cli/src/a.ts'];
  const run = (patterns, tabled, tracked = TRACKED) =>
    optOutSiteProblems({
      patternsByConfig: new Map([['eslint.root.config.mjs', patterns]]),
      tabledSitesByConfig: new Map([['eslint.root.config.mjs', tabled]]),
      tracked,
    });

  it('clears a config whose opt-out is exactly the tabled site', () => {
    // The control. Without it every case below would pass on a function that
    // reported a problem for absolutely everything.
    expect(run(['tools/ci/egress-probe.mjs'], ['tools/ci/egress-probe.mjs'])).toEqual([]);
  });

  it('rejects a pattern whose final segment is a glob, even when it reaches only tabled files', () => {
    // The widening edit, and the reason the check is on the PATTERN rather than
    // on the files it resolves: `tools/ci/*.mjs` reaches egress-probe.mjs and
    // second-probe.mjs here, but even against a tree holding only the tabled one
    // it must fail — the exception would silently cover whatever lands next.
    const problems = run(['tools/ci/*.mjs'], ['tools/ci/egress-probe.mjs'], [TRACKED[0]]);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('whose final segment is a glob');
    expect(problems[0]).toContain('file-scoped, never package-wide');
  });

  it('names a site the config opts out that no row tables', () => {
    const problems = run(
      ['tools/ci/egress-probe.mjs', 'tools/ci/second-probe.mjs'],
      ['tools/ci/egress-probe.mjs'],
    );
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('tools/ci/second-probe.mjs');
    expect(problems[0]).toContain('§4');
  });

  it('names a tabled site the config no longer opts out', () => {
    // The direction the specifier comparison structurally cannot see: a config
    // shared by two rows keeps its key from the sibling row, whose specifiers are
    // a superset, so deleting a row moves that comparison not at all.
    const problems = run(
      ['tools/ci/egress-probe.mjs'],
      ['tools/ci/egress-probe.mjs', 'tools/ci/second-probe.mjs'],
    );
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('tools/ci/second-probe.mjs');
    expect(problems[0]).toContain('no longer scopes');
  });

  it('names a package-wide opt-out as itself, not as a dropped row', () => {
    // `files: undefined` is the violation §4 forbids outright. Contributing no
    // pattern would make it invisible here AND report every tabled site for the
    // config as one it "no longer scopes" — the wrong complaint, twice over.
    const problems = run([undefined], ['tools/ci/egress-probe.mjs']);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('no `files:` scope at all');
    expect(problems[0]).not.toContain('no longer scopes');
  });

  it('reads a package-wide entry and a nested AND-array out of a config', () => {
    // The two shapes optOutFilePatterns must not silently drop or split. A real
    // opt-out is included as its pattern; an entry with no `files` becomes
    // `undefined` (refused above); a nested array is one AND-pattern this
    // resolution cannot model, joined so it is refused rather than split into two
    // independent site claims ESLint never applies.
    const permitting = {
      rules: { 'no-restricted-imports': noNetworkImports({ allow: ['node:net'] }) },
    };
    expect(optOutFilePatterns([{ ...permitting, files: ['a/b.ts'] }])).toEqual(['a/b.ts']);
    expect(optOutFilePatterns([permitting])).toEqual([undefined]);
    expect(optOutFilePatterns([{ ...permitting, files: [['src/**', '**/*.ts']] }])).toEqual([
      'src/** + **/*.ts',
    ]);
    // The control: an entry permitting nothing contributes no pattern at all.
    expect(optOutFilePatterns([{ files: ['a/b.ts'], rules: {} }])).toEqual([]);
  });

  it('resolves a directory-glob pattern by basename, under that config only', () => {
    // `**/x.mjs` is legitimately file-scoped and three real opt-outs use it, so
    // it must resolve rather than be rejected — and must not reach an identically
    // named file under a different config's tree.
    expect(sitesDesignatedBy('eslint.root.config.mjs', '**/second-probe.mjs', TRACKED)).toEqual([
      'tools/ci/second-probe.mjs',
    ]);
    expect(sitesDesignatedBy('cli/eslint.config.mjs', '**/second-probe.mjs', TRACKED)).toEqual([]);
    expect(sitesDesignatedBy('cli/eslint.config.mjs', 'src/a.ts', TRACKED)).toEqual([
      'cli/src/a.ts',
    ]);
  });
});

describe(`the opt-out table itself (${CONVENTIONS_DOC} §4)`, () => {
  /** The section's text, and one entry per table row. */
  let section = '';
  /** @type {{site: string, via: string, specifiers: string[], other: string[], cell: string}[]} */
  let rows = [];
  /** @type {Error | undefined} */
  let setupError;
  /** Specifiers each row's config really permits for that row's site. */
  const permittedBySite = new Map();
  /** The `files:` patterns each tabled config scopes its network opt-out to. */
  const scopedPatternsByConfig = new Map();

  // Resolving five configs through ESLint costs what the audit above costs, and
  // for the same reason; it shares that budget rather than the per-test default.
  //
  // EVERYTHING here is caught, not just the parse. An uncaught throw aborts the
  // hook, and vitest then SKIPS every test in this describe — zero failures, no
  // name, and a guard that silently stopped running. Captured, it is reported by
  // the first assertion each test makes.
  beforeAll(async () => {
    try {
      section = sectionOf(readConventions(), SECTION_4);
      const shipped = bannedNamesOf(noNetworkImports());
      rows = tableOf(section, OPT_OUT_TABLE_HEADER).map(([site, allowed], i) => {
        const spans = codeSpansOf(site);
        if (spans.length !== 2) {
          throw new Error(
            `Row ${i + 1}: the Site cell must name the file and the config that scopes it, as ` +
              `\`<site>\` (via \`<config>\`). Found ${spans.length} code span(s) in ${site}.`,
          );
        }
        const spelled = codeSpansOf(allowed);
        return {
          site: spans[0],
          via: spans[1],
          specifiers: spelled.filter((s) => shipped.has(s)),
          other: spelled.filter((s) => !shipped.has(s)),
          cell: allowed,
        };
      });

      // Every config a green `pnpm lint` runs, not just the ones the table
      // already names. Scoping this to tabled configs would make the whole
      // reality -> table direction blind to the case it exists for: a NEW config
      // carrying an opt-out that no row mentions is exactly a site that never
      // reached the table, and it would have been iterated by nothing.
      const { inPlay } = await configsInPlay({
        rootScripts: rootScripts(),
        packages: workspaceLintScripts(),
      });
      for (const via of new Set([...inPlay, ...rows.map((r) => r.via)])) {
        const mod = await import(pathToFileURL(join(REPO_ROOT, via)).href);
        const patterns = optOutFilePatterns(mod.default);
        // Configs carrying no opt-out at all are left out — they have nothing to
        // compare. A TABLED config is kept even when empty, so a row whose
        // exception has been removed is still reported against it.
        if (patterns.length || rows.some((r) => r.via === via)) {
          scopedPatternsByConfig.set(via, patterns);
        }
      }

      for (const { site, via } of rows) {
        // The config's own directory is its cwd, which is what `--no-config-lookup
        // -c <config>` gives it in the lint script. calculateConfigForFile then runs
        // the real flat-config cascade — so a `files:` glob is matched by ESLint's
        // own matcher rather than by a re-implementation of it here.
        const cwd = join(REPO_ROOT, dirname(via));
        const eslint = new ESLint({ cwd, overrideConfigFile: join(REPO_ROOT, via) });
        const config = await eslint.calculateConfigForFile(join(REPO_ROOT, site));
        permittedBySite.set(site, networkSpecifiersPermittedBy(config?.rules).sort());
      }
    } catch (cause) {
      setupError = /** @type {Error} */ (cause);
    }
  }, CONFIG_LOAD_TIMEOUT_MS);

  /** The parsed rows, or a failure naming why the table could not be read. */
  const parsed = () => {
    if (setupError) throw setupError;
    return rows;
  };

  it('reads a non-empty opt-out table out of the document', () => {
    // Every assertion below walks `rows`, so an empty parse would pass all of
    // them. The parser throws rather than yielding [] for a section, table or
    // row set it could not find; this is where that throw is reported.
    expect(parsed().length).toBeGreaterThan(0);
  });

  it('documents exactly the opt-out sites the audit asserts', () => {
    /** @type {Record<string, string[]>} */
    const tabled = {};
    for (const { via, specifiers } of parsed()) {
      tabled[via] = [...new Set([...(tabled[via] ?? []), ...specifiers])].sort();
    }
    expect(tabled).toEqual(DOCUMENTED_OPT_OUTS);
  });

  it('scopes every opt-out to a site the table names, and no other', () => {
    // The reality -> table direction, at SITE granularity. Everything else here
    // reads the table and checks it against the workspace; this reads the
    // WORKSPACE and checks it against the table, which is the direction §4's
    // closing promise — "Adding another opt-out site means updating this table" —
    // actually makes. §3's parallel sentence has carried this since it was
    // written; §4's did not, so an ordinary edit could grant the exception more
    // ground with every gate green.
    const tracked = trackedFiles();
    const tabledSitesByConfig = new Map();
    for (const { site, via } of parsed()) {
      tabledSitesByConfig.set(via, [...(tabledSitesByConfig.get(via) ?? []), site]);
    }

    // A derivation that resolved nothing would report no problem for any config
    // and pass this whole check vacuously — the same rule the parse above applies
    // to the table itself.
    const derived = [...scopedPatternsByConfig.values()].flat();
    expect(
      derived.length,
      'no tabled config scopes a network opt-out to any file, so this check compares two empty ' +
        'sets — the derivation has regressed rather than the workspace having no opt-outs',
    ).toBeGreaterThan(0);

    const problems = optOutSiteProblems({
      patternsByConfig: scopedPatternsByConfig,
      tabledSitesByConfig,
      tracked,
    });
    expect(problems, `${CONVENTIONS_DOC} §4 site column does not describe the workspace`).toEqual(
      [],
    );
  });

  it('names a real file and a real config in every row, the file under the config', () => {
    const tracked = new Set(trackedFiles());
    const wrong = parsed().flatMap(({ site, via }) => [
      ...(tracked.has(site) ? [] : [`${site}: tabled site is not a tracked file`]),
      ...(tracked.has(via) ? [] : [`${via}: tabled config is not a tracked file`]),
      // A config only ever lints its own tree, so a row pairing a site with a
      // config that could not reach it is a claim about an exception nobody has.
      ...(dirname(via) === '.' || site.startsWith(`${dirname(via)}/`)
        ? []
        : [`${site}: sits outside ${dirname(via)}/, so ${via} never applies to it`]),
    ]);
    expect(wrong, `${CONVENTIONS_DOC} §4 rows that do not describe the workspace`).toEqual([]);
  });

  it('gives each site the specifiers its config really permits it', () => {
    // The true-claim half: resolved through ESLint against the config the row
    // itself names, so the table cannot say `node:net` where the workspace grants
    // `node:http`, nor keep a row for a file whose exception has been removed.
    const wrong = parsed().flatMap(({ site, via, specifiers }) => {
      const real = permittedBySite.get(site) ?? [];
      const tabled = [...specifiers].sort();
      return JSON.stringify(real) === JSON.stringify(tabled)
        ? []
        : [
            `${site} (via ${via}): table says ${JSON.stringify(tabled)}, config grants ${JSON.stringify(real)}`,
          ];
    });
    expect(wrong, `${CONVENTIONS_DOC} §4's Allowed specifier column vs the real configs`).toEqual(
      [],
    );
  });

  it('marks any entry the module audit cannot see as the inline global it is', () => {
    // §4's fifth row lists `fetch` alongside three modules, and says in prose why
    // it is different: it is an inline eslint-disable, not a config `allow`, so
    // the audit above — which diffs `no-restricted-imports` paths — is
    // structurally blind to it. Without this, ANY unrecognised token in that
    // column would be silently dropped by the `shipped.has` filter above and the
    // set comparison would still pass: a typo'd `node:nett` would read as a
    // documented opt-out and be enforced by nothing.
    const globals = new Set(
      noNetworkGlobals()
        .slice(1)
        .map((g) => g.name),
    );
    const unexplained = parsed().flatMap(({ site, other, cell }) =>
      other
        .filter((token) => !(globals.has(token) && cell.includes(`\`${token}\` (inline)`)))
        .map(
          (token) =>
            `${site}: \`${token}\` is neither a banned module nor a banned global marked ` +
            '`(inline)`, so no guard here covers it',
        ),
    );
    expect(unexplained).toEqual([]);
  });

  it('states a count that follows from the table rather than from memory', () => {
    const n = parsed().length;
    expect(countWordIn(section, SITE_COUNT_SENTENCE, 'how many files carry an opt-out')).toBe(
      cardinalFor(n),
    );
    // The promise to the next author. It may stay countless ("another"), but it
    // must not name a WRONG one — "adding a third site" while five are tabled is
    // the drift this pins, and deleting the sentence fails countWordIn outright.
    expect(['another', ordinalFor(n + 1)]).toContain(
      countWordIn(section, ADDING_SENTENCE, 'what the next author must update'),
    );
  });
});
