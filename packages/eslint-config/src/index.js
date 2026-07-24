// @ts-check
import js from '@eslint/js';
import pluginN from 'eslint-plugin-n';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

// ai-tc is local-first: the OSS surface makes no network calls and talks to no
// AKA service — all data lives in the local SQLite store under ~/.aka. Banning
// the network primitives keeps that guarantee enforced by lint instead of by
// convention. A genuinely local-only use (e.g. a 127.0.0.1 bind probe) may add
// a narrow, file-scoped opt-out in its own eslint config.
const NO_NETWORK_MESSAGE =
  'ai-tc is local-first and makes no network calls — all data lives in the local SQLite store under ~/.aka. ' +
  'Do not use network primitives here; a genuinely local-only use (e.g. a 127.0.0.1 bind probe) may add a ' +
  'file-scoped opt-out. See CLAUDE.md "No network calls".';

// Client-side network globals. `no-restricted-globals` flags only a bare
// reference that resolves to the global — never a property access such as
// `db.fetch()` or a local variable of the same name — so ordinary method names
// are unaffected.
const NETWORK_GLOBALS = ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'WebTransport'];

// The container-global objects those primitives also hang off of. Banning the
// bare global alone would let `globalThis.fetch(...)` slip through, so the
// member forms are restricted too. Only the network properties below are
// touched — `window.location` and friends are unaffected.
const NETWORK_GLOBAL_CONTAINERS = ['globalThis', 'window', 'self', 'global'];

// Host-object egress methods that do not fit the container-by-primitive grid
// above: navigator.sendBeacon is a fire-and-forget POST (a genuine exfil path).
const NETWORK_MEMBER_CALLS = [{ object: 'navigator', property: 'sendBeacon' }];

// Node network builtins plus the common third-party HTTP clients. Both the
// `node:`-prefixed and the bare specifier are listed so `import 'http'` cannot
// slip past the ban that `import 'node:http'` would trip.
const NETWORK_MODULES = [
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

// Escape a specifier for embedding in the esquery attribute regexes below. The
// character class includes `/` so a subpath specifier like `node:dns/promises`
// cannot close the `/…/` regex literal early.
/** @param {string} specifier */
const escapeForSelector = (specifier) => specifier.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/**
 * The `no-restricted-globals` rule value that bans the network client globals.
 * @returns {import('eslint').Linter.RuleEntry}
 */
export function noNetworkGlobals() {
  return /** @type {import('eslint').Linter.RuleEntry} */ ([
    'error',
    ...NETWORK_GLOBALS.map((name) => ({ name, message: NO_NETWORK_MESSAGE })),
  ]);
}

/**
 * The `no-restricted-properties` rule value that bans container-global access to
 * the network primitives (e.g. `globalThis.fetch`, `window.WebSocket`), closing
 * the member-access bypass that `no-restricted-globals` cannot see.
 * @returns {import('eslint').Linter.RuleEntry}
 */
export function noNetworkProperties() {
  return /** @type {import('eslint').Linter.RuleEntry} */ ([
    'error',
    ...NETWORK_GLOBAL_CONTAINERS.flatMap((object) =>
      NETWORK_GLOBALS.map((property) => ({ object, property, message: NO_NETWORK_MESSAGE })),
    ),
    ...NETWORK_MEMBER_CALLS.map(({ object, property }) => ({
      object,
      property,
      message: NO_NETWORK_MESSAGE,
    })),
  ]);
}

/**
 * The `no-restricted-imports` rule value that bans the network modules, merged
 * with any caller-supplied `paths`/`patterns`. Flat config never merges two
 * `no-restricted-imports` entries — the last one matching a file wins outright —
 * so a config layered on top of `base` must fold its extra restrictions in here
 * rather than declaring a second entry. `allow` drops specific specifiers so a
 * file with a genuine local-only use can opt out of just those.
 * @param {{
 *   allow?: readonly string[],
 *   paths?: { name: string, message: string }[],
 *   patterns?: { group: string[], message: string }[],
 * }} [opts]
 * @returns {import('eslint').Linter.RuleEntry}
 */
export function noNetworkImports(opts = {}) {
  const { allow = [], paths = [], patterns = [] } = opts;
  return /** @type {import('eslint').Linter.RuleEntry} */ ([
    'error',
    {
      paths: [
        ...NETWORK_MODULES.filter((name) => !allow.includes(name)).map((name) => ({
          name,
          message: NO_NETWORK_MESSAGE,
        })),
        ...paths,
      ],
      patterns,
    },
  ]);
}

/**
 * The `no-restricted-syntax` rule value that bans *dynamic* access to the
 * network modules — `import('node:http')` and `require('axios')` — which the
 * static `no-restricted-imports` rule cannot see. A non-literal specifier
 * (`import(url)`) and `require.resolve(...)` are intentionally not matched.
 * `allow` drops specific specifiers, symmetric with `noNetworkImports`, so a
 * file that opts out of a static import can opt out of the dynamic form too.
 * @param {{ allow?: readonly string[] }} [opts]
 * @returns {import('eslint').Linter.RuleEntry}
 */
export function noNetworkSyntax(opts = {}) {
  const { allow = [] } = opts;
  const pattern = NETWORK_MODULES.filter((name) => !allow.includes(name))
    .map(escapeForSelector)
    .join('|');
  return /** @type {import('eslint').Linter.RuleEntry} */ ([
    'error',
    {
      selector: `ImportExpression[source.value=/^(${pattern})$/]`,
      message: NO_NETWORK_MESSAGE,
    },
    {
      selector: `CallExpression[callee.name='require'] > Literal[value=/^(${pattern})$/]`,
      message: NO_NETWORK_MESSAGE,
    },
  ]);
}

/** @type {import('typescript-eslint').ConfigArray} */
export const base = tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    plugins: {
      n: pluginN,
      'simple-import-sort': simpleImportSort,
    },
    rules: {
      // Forbid direct process.env access by default; packages that must read env
      // (e.g. the plugin's provider resolution) opt out in their own eslint config.
      'n/no-process-env': 'error',

      // Enforce the no-network guarantee: ban the client-side network globals
      // (bare and container-global forms), the HTTP/socket modules (static and
      // dynamic import / require), across the whole workspace. Files with a
      // genuine local-only use opt out in their own eslint config (see cli's
      // dashboard bind probe).
      'no-restricted-globals': noNetworkGlobals(),
      'no-restricted-properties': noNetworkProperties(),
      'no-restricted-imports': noNetworkImports(),
      'no-restricted-syntax': noNetworkSyntax(),

      // Import discipline
      'simple-import-sort/imports': 'error',
      'simple-import-sort/exports': 'error',

      // TypeScript strictness extras
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',

      // No warnings — everything is error or off
      'no-console': 'error',
    },
  },
  prettier,
);

// OSS/enterprise dependency wall (see CLAUDE.md "Package dependency rules"):
// packages that ship in the public oss/ tree must never import enterprise-only
// modules — @akasecurity/client (the tenant-aware HTTP client), drizzle-orm and
// @akasecurity/schema-enterprise (the Postgres/tenancy layer). Apply this to
// every OSS package except the plugin, which is the documented exception
// allowed to use @akasecurity/client to sync to a backend when attached.
const ENTERPRISE_IMPORT_MESSAGE =
  'OSS packages must never import enterprise-only modules (this keeps tenancy/auth/Postgres code out of the public oss/ tree). See CLAUDE.md "Package dependency rules".';

// This carries the network import bans forward alongside the enterprise ones.
// `no-restricted-imports` does not merge across flat-config entries, and this is
// layered on top of `base` in the packages that use it, so declaring the
// enterprise restrictions on their own would silently drop base's network bans
// for exactly those packages.
/** @type {import('typescript-eslint').ConfigArray} */
export const noEnterpriseImports = tseslint.config({
  rules: {
    'no-restricted-imports': noNetworkImports({
      paths: [
        { name: '@akasecurity/client', message: ENTERPRISE_IMPORT_MESSAGE },
        { name: 'drizzle-orm', message: ENTERPRISE_IMPORT_MESSAGE },
        { name: '@akasecurity/schema-enterprise', message: ENTERPRISE_IMPORT_MESSAGE },
      ],
      patterns: [
        { group: ['drizzle-orm/*'], message: ENTERPRISE_IMPORT_MESSAGE },
        { group: ['@akasecurity/schema-enterprise/*'], message: ENTERPRISE_IMPORT_MESSAGE },
      ],
    }),
  },
});

// A standalone config that enforces ONLY the no-network guarantee — the four
// bans above and nothing else. Point a second lint pass at it (see cli's
// `eslint.scripts.config.mjs`) to cover files that are not compiled sources:
// the dev/CI scripts under `scripts/`, which `src`/`test` linting never reaches
// and where the full `base` ruleset (type-aware rules, import sorting,
// no-console, no-process-env) would only produce noise. It carries no
// TypeScript-project requirement, so it lints plain .js/.mjs/.cjs directly.
/** @type {import('eslint').Linter.Config[]} */
export const networkGuard = [
  {
    rules: {
      'no-restricted-globals': noNetworkGlobals(),
      'no-restricted-properties': noNetworkProperties(),
      'no-restricted-imports': noNetworkImports(),
      'no-restricted-syntax': noNetworkSyntax(),
    },
  },
];

export default base;
