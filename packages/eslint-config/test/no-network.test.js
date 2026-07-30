import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { Linter } from 'eslint';
import { describe, expect, it } from 'vitest';

import {
  base,
  networkGuard,
  noEnterpriseImports,
  noNetworkGlobals,
  noNetworkImports,
  noNetworkProperties,
  noNetworkSyntax,
} from '../src/index.js';

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

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

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
const DOCUMENTED_OPT_OUTS = {
  'cli/eslint.config.mjs': ['node:net'],
  'cli/eslint.scripts.config.mjs': ['node:http'],
  // The repo-root config lints the vitest no-network guard (which imports all
  // three transports it patches) and the CI egress probe (node:net). Both are
  // file-scoped; see CLAUDE.md §4.
  'eslint.root.config.mjs': ['node:dgram', 'node:dns', 'node:net'],
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

describe('documented no-network opt-outs (CLAUDE.md §4)', () => {
  /** Every tracked ESLint flat config in the workspace. */
  const configs = (() => {
    try {
      return execFileSync('git', ['ls-files', '*eslint*.config.mjs'], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
      })
        .split('\n')
        .filter(Boolean);
    } catch (cause) {
      throw new Error(
        'Could not list tracked files with `git ls-files`. This guard audits the real workspace ' +
          'configs, so it must run inside a git checkout.',
        { cause },
      );
    }
  })();

  // A guard that found no configs would pass every assertion below vacuously.
  it('found the workspace ESLint configs to audit', () => {
    expect(configs.length).toBeGreaterThanOrEqual(Object.keys(DOCUMENTED_OPT_OUTS).length);
    for (const documented of Object.keys(DOCUMENTED_OPT_OUTS)) {
      expect(configs).toContain(documented);
    }
  });

  it('has exactly the opt-out sites CLAUDE.md §4 documents, each file-scoped', async () => {
    /** @type {Record<string, string[]>} */
    const found = {};
    // Loaded concurrently rather than in an await-loop: these are 18 independent
    // module reads whose cost is resolution and I/O, and serializing them
    // multiplies under the parallel load turbo puts on a CI runner. Node's module
    // cache makes the order irrelevant, and each config writes only its own key.
    const loaded = await Promise.all(
      configs.map(async (file) => [file, await import(pathToFileURL(join(REPO_ROOT, file)).href)]),
    );
    for (const [file, mod] of loaded) {
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
  it('permits its specifier in both the static and the dynamic form', async () => {
    for (const [file, specifiers] of Object.entries(DOCUMENTED_OPT_OUTS)) {
      const mod = await import(pathToFileURL(join(REPO_ROOT, file)).href);
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
