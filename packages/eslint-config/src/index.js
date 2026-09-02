// @ts-check
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import pluginN from 'eslint-plugin-n';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import tseslint from 'typescript-eslint';

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

// The npm HTTP clients from NETWORK_MODULES. `no-restricted-imports` `paths`
// matches only the exact specifier, so a deep import (`axios/lib/adapters/http.js`)
// would slip the root ban; a `<client>/*` pattern closes every subpath. Node
// builtins need no equivalent — they expose no deep network specifier beyond the
// `node:dns/promises` form already listed above.
const NETWORK_PACKAGE_CLIENTS = ['axios', 'undici', 'got', 'node-fetch'];

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
 * the member-access bypass that `no-restricted-globals` cannot see. It also
 * covers computed indexing (`globalThis['fetch']`) and destructuring
 * (`const { fetch } = globalThis`) — `no-restricted-properties` matches those
 * forms too. The one residual is a false positive, not a bypass: the rule keys
 * on the identifier name, so a local variable named `window`/`self`/`global`/
 * `globalThis`/`navigator` carrying a `.fetch`/`.sendBeacon` property would be
 * flagged (none exist today).
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
 * rather than declaring a second entry — including caller `patterns`, which the
 * npm-client subpath bans below are prepended to. `allow` drops specific
 * specifiers (and the matching `<client>/*` subpath group) so a file with a
 * genuine local-only use can opt out of just those.
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
      patterns: [
        ...NETWORK_PACKAGE_CLIENTS.filter((name) => !allow.includes(name)).map((name) => ({
          group: [`${name}/*`],
          message: NO_NETWORK_MESSAGE,
        })),
        ...patterns,
      ],
    },
  ]);
}

/**
 * The `no-restricted-syntax` rule value that bans *dynamic* access to the
 * network modules — `import('node:http')` and `require('axios')`, plus any npm-
 * client subpath (`import('axios/lib/adapters/http.js')`) — which the static
 * `no-restricted-imports` rule cannot see. Intentionally NOT matched, since an
 * esquery selector cannot follow a binding and the ban targets accidents rather
 * than deliberate evasion: a non-literal specifier (`import(url)`, a template
 * literal), `require.resolve(...)`, and an aliased/indirected require
 * (`const req = createRequire(...); req('node:http')`). `allow` drops specific
 * specifiers, symmetric with `noNetworkImports`, so a file that opts out of a
 * static import can opt out of the dynamic form too.
 * @param {{ allow?: readonly string[] }} [opts]
 * @returns {import('eslint').Linter.RuleEntry}
 */
export function noNetworkSyntax(opts = {}) {
  return /** @type {import('eslint').Linter.RuleEntry} */ ([
    'error',
    ...networkSyntaxSelectors(opts),
  ]);
}

/**
 * Just the selector entries `noNetworkSyntax` wraps in a severity, so a config that
 * has to add selectors of its own can carry these forward without unwrapping a
 * `RuleEntry` union. `tonalInkTokens` below is the one caller that needs that; a
 * flat-config `rules` entry REPLACES the rule's options rather than merging them,
 * so anything overriding `no-restricted-syntax` must re-list these or silently drop
 * the dynamic-import ban for its packages.
 * @param {{ allow?: readonly string[] }} [opts]
 * @returns {{ selector: string, message: string }[]}
 */
function networkSyntaxSelectors(opts = {}) {
  const { allow = [] } = opts;
  const exact = NETWORK_MODULES.filter((name) => !allow.includes(name)).map(escapeForSelector);
  // The npm clients also match any subpath, mirroring the `<client>/*` static
  // ban. `escapeForSelector` escapes the trailing `/` so it cannot close the
  // `/…/` regex literal early.
  const clientSubpaths = NETWORK_PACKAGE_CLIENTS.filter((name) => !allow.includes(name)).map(
    (name) => `${escapeForSelector(`${name}/`)}.*`,
  );
  const pattern = [...exact, ...clientSubpaths].join('|');
  return [
    {
      selector: `ImportExpression[source.value=/^(${pattern})$/]`,
      message: NO_NETWORK_MESSAGE,
    },
    {
      selector: `CallExpression[callee.name='require'] > Literal[value=/^(${pattern})$/]`,
      message: NO_NETWORK_MESSAGE,
    },
  ];
}

// Drizzle plus the companion packages that take it as a peer dependency. Banning
// `drizzle-orm` alone is not enough: `drizzle-zod` and its siblings pull the same
// runtime into a bundle without the banned name ever appearing in the source.
// `drizzle-kit` is a schema-generation CLI and belongs to @akasecurity/schema's
// tooling only.
const DRIZZLE_MODULES = [
  'drizzle-orm',
  'drizzle-zod',
  'drizzle-typebox',
  'drizzle-valibot',
  'drizzle-kit',
];

/**
 * The `no-restricted-syntax` selector entries that ban *dynamic* access to the
 * Drizzle modules — `import('drizzle-orm/pg-core')` and `require('drizzle-zod')`
 * — which the static `no-restricted-imports` rule cannot see. Same shape, and the
 * same acknowledged limits, as `networkSyntaxSelectors` above: a non-literal
 * specifier and an indirected `require` are not matched, because an esquery
 * selector cannot follow a binding.
 * @returns {{ selector: string, message: string }[]}
 */
function drizzleSyntaxSelectors() {
  const pattern = DRIZZLE_MODULES.map(
    (name) => `${escapeForSelector(name)}(${escapeForSelector('/')}.*)?`,
  ).join('|');
  return [
    {
      selector: `ImportExpression[source.value=/^(${pattern})$/]`,
      message: DRIZZLE_IMPORT_MESSAGE,
    },
    {
      selector: `CallExpression[callee.name='require'] > Literal[value=/^(${pattern})$/]`,
      message: DRIZZLE_IMPORT_MESSAGE,
    },
  ];
}

// The store-reading wall (see CLAUDE.md "Package dependency rules"): Drizzle is
// imported ONLY by @akasecurity/schema, which uses it to DEFINE the local-store
// and registry schemas. Every other package reads that store through
// @akasecurity/persistence, which wraps node:sqlite — so a Drizzle import
// anywhere else is a package-wall crossing. Spread this in every package except
// @akasecurity/schema itself.
//
// The `drizzle-orm/*` group is what makes the ban hold: `no-restricted-imports`
// `paths` matches only the exact specifier, so the root ban alone leaves every
// dialect entry (`drizzle-orm/pg-core`, `drizzle-orm/sqlite-core`) reachable.
const DRIZZLE_IMPORT_MESSAGE =
  'Drizzle is imported only by @akasecurity/schema, which uses it to define the local-store and ' +
  'registry schemas. Read the store through @akasecurity/persistence (node:sqlite) instead. ' +
  'See CLAUDE.md "Package dependency rules".';

// This carries the network import bans forward alongside the Drizzle one.
// `no-restricted-imports` does not merge across flat-config entries, and this is
// layered on top of `base` in the packages that use it, so declaring the Drizzle
// restriction on its own would silently drop base's network bans for exactly
// those packages.
/**
 * The wall's two rule VALUES, exposed so a file-scoped entry that has to relax
 * the NETWORK ban can restate the wall in the same breath.
 *
 * That is not a convenience. Flat config REPLACES a rule rather than merging it,
 * so a later `files:` entry setting either of these drops the wall for the files
 * it matches — and a lost ban still exits 0, which is the failure this whole
 * module is shaped around. Spreading `noDrizzleImports` and then relaxing
 * `no-restricted-imports` for one file is exactly that mistake.
 *
 * `allow` drops a network module from base's bans, exactly as `noNetworkImports`
 * takes it. The Drizzle half deliberately takes NO allow list: `@akasecurity/schema`
 * is the one package that may import Drizzle, and it carries no wall to relax.
 * @param {{ allow?: string[] }} [opts]
 */
export function drizzleWallRules(opts = {}) {
  return {
    'no-restricted-imports': noNetworkImports({
      ...opts,
      paths: DRIZZLE_MODULES.map((name) => ({ name, message: DRIZZLE_IMPORT_MESSAGE })),
      patterns: DRIZZLE_MODULES.map((name) => ({
        group: [`${name}/*`],
        message: DRIZZLE_IMPORT_MESSAGE,
      })),
    }),
    // The dynamic half. `no-restricted-imports` sees only a written specifier,
    // so without this a code-split `await import('drizzle-orm/pg-core')` reaches
    // a bundle with lint green. Carries base's network selectors forward for the
    // same replace-not-merge reason the imports ban does.
    'no-restricted-syntax': /** @type {import('eslint').Linter.RuleEntry} */ ([
      'error',
      ...networkSyntaxSelectors(opts),
      ...drizzleSyntaxSelectors(),
    ]),
  };
}

/** @type {import('typescript-eslint').ConfigArray} */
export const noDrizzleImports = [{ rules: drizzleWallRules() }];

// Every tonal family in @akasecurity/ui-kit's theme.css carries two foregrounds:
// `--color-X` is the HUE (chart series, status dots, bar segments) and
// `--color-X-ink` is TEXT on that family's tint. The hue is deliberately too light
// to read as text on a pale surface — that is what keeps the severities tellable
// apart in a chart — so a hue reached through `text-*` renders at around 2:1 and
// fails WCAG 1.4.3 while compiling, rendering and passing review without complaint.
//
// `--color-primary` reads the other way round (it IS the ink, `--color-primary-solid`
// is its fill), which is exactly why this is worth enforcing rather than
// remembering: `text-primary` is right and `text-sev-critical` is wrong, and nothing
// in the names says which.
const TONAL_HUE_FAMILIES = [
  'sev-critical',
  'sev-high',
  'sev-medium',
  'sev-low',
  'ok',
  'teal',
  'violet',
];

const TONAL_INK_MESSAGE =
  'This is the HUE half of a tonal token pair and is too light to read as text (~2:1). ' +
  'Use the -ink form for a foreground — text-sev-critical-ink, text-ok-ink — and keep the bare ' +
  'hue for non-text marks (bg-* dots, bars, chart series). See the token comments in ' +
  '@akasecurity/ui-kit/theme.css.';

/**
 * The `no-restricted-syntax` entries that reject a tonal HUE token used as a
 * `text-*` utility, in both a plain string and a template literal.
 *
 * Scope, stated plainly: this catches the class-name form, which is where nearly
 * all of these live. It cannot see a hue passed as a CSS variable string — an
 * `iconColor="var(--color-ok)"` prop and an `iconBg="var(--color-ok-fill)"` prop are
 * the same node to a selector — nor a class assembled from a non-literal
 * (`` `text-${tone}` ``). Those stay a reading job.
 *
 * @returns {{ selector: string, message: string }[]}
 */
function tonalInkSelectors() {
  // A leading non-word boundary so `text-ok` is caught bare, after a variant
  // (`hover:text-ok`) and mid-class-list, but not as the tail of a longer word. The
  // trailing lookahead is what lets `text-ok-ink` and `text-sev-low-fill` through.
  const pattern = `(?:^|[^\\w-])text-(?:${TONAL_HUE_FAMILIES.join('|')})(?![\\w-])`;
  return [
    { selector: `Literal[value=/${pattern}/]`, message: TONAL_INK_MESSAGE },
    { selector: `TemplateElement[value.raw=/${pattern}/]`, message: TONAL_INK_MESSAGE },
  ];
}

const AMBIENT_CLOCK_MESSAGE =
  'A component under a `use client` directive is rendered TWICE — once on the server, ' +
  'once when the browser hydrates it — and reading the clock makes those two renders ' +
  'disagree whenever a rounding boundary falls between them, which React resolves by ' +
  'discarding the server HTML for the subtree. Take the instant as a prop (`renderedAt`) ' +
  'from the server component that captured it, or track it with `useRenderClock`, which ' +
  'returns that instant for the hydration render and the live clock afterwards. ' +
  '`new Date(someIso)` and `Date.parse(someIso)` are unaffected — they read no clock.';

/**
 * The `no-restricted-syntax` entries that reject an ambient clock read inside a
 * module carrying the `use client` directive.
 *
 * The scoping is the whole trick: `Program:has(> ExpressionStatement[directive=…])`
 * matches only where the directive is a real directive-prologue statement, so a
 * SERVER component — which is where an instant is legitimately captured, and must
 * stay legitimate — is untouched, and so is a file that merely mentions the string
 * `use client` as a value. Only `Date.now()` and a zero-argument `new Date()` are
 * clock reads; `new Date(iso)` and `Date.parse(iso)` parse a value the caller
 * already had and are deliberately left alone.
 *
 * Known limits, in the shape `tonalInkSelectors` states its own: an alias
 * (`const n = Date.now; n()`), a clock reached through a helper the client
 * component calls, and `performance.now()` — which is not a wall clock and cannot
 * produce a date label — are not matched. This bans the accident, not the evasion.
 *
 * @returns {{ selector: string, message: string }[]}
 */
function ambientClockSelectors() {
  const CLIENT = "Program:has(> ExpressionStatement[directive='use client'])";
  return [
    {
      selector: `${CLIENT} CallExpression[callee.object.name='Date'][callee.property.name='now']`,
      message: AMBIENT_CLOCK_MESSAGE,
    },
    {
      selector: `${CLIENT} NewExpression[callee.name='Date'][arguments.length=0]`,
      message: AMBIENT_CLOCK_MESSAGE,
    },
  ];
}

// The assembled `no-restricted-syntax` value for the packages that render in a
// browser: ui-kit, dashboard-ui and web-ui. Named for the tonal guard it was
// introduced to carry; it is the ONE entry these packages get, so it also carries
// the ambient-clock ban and, below, the two bans it must not drop.
//
// It re-lists the network AND drizzle selectors rather than only its own, because
// a flat-config `rules` entry REPLACES the rule's options instead of merging them
// — setting `no-restricted-syntax` bare here would silently drop both bans for
// exactly these three packages, and this is spread after `noDrizzleImports` in
// every one of them. `reactUiPackage` below is what keeps that ordering from
// being re-derived per package.
/**
 * The whole `no-restricted-syntax` value one of those packages gets, assembled
 * from every group rather than composed by spreading — because a later flat-config
 * entry REPLACES this rule's options, so a config that sets it a second time and
 * names a subset silently drops the rest.
 *
 * That is exactly what a per-file opt-out has to do, which is why the only
 * supported way to write one is to call this with the group turned off:
 *
 *   { files: ['src/lib/useRenderClock.ts'],
 *     rules: { 'no-restricted-syntax': reactSyntaxBans({ allowAmbientClock: true }) } }
 *
 * The other three groups come along by construction, so an opt-out for one ban
 * cannot become an opt-out for four by omission.
 *
 * @param {{ allowAmbientClock?: boolean }} [opts]
 * @returns {import('eslint').Linter.RuleEntry}
 */
export function reactSyntaxBans(opts = {}) {
  const { allowAmbientClock = false } = opts;
  return /** @type {import('eslint').Linter.RuleEntry} */ ([
    'error',
    ...networkSyntaxSelectors(),
    ...drizzleSyntaxSelectors(),
    ...tonalInkSelectors(),
    ...(allowAmbientClock ? [] : ambientClockSelectors()),
  ]);
}

/** @type {import('eslint').Linter.Config[]} */
export const tonalInkTokens = [
  {
    rules: {
      'no-restricted-syntax': reactSyntaxBans(),
    },
  },
];

// A plain flat-config array, like `rootConfigFiles` and `networkGuard` below.
// `tseslint.config()` used to wrap this; with no `extends` key anywhere in the
// list that helper returned the same entries by identity and added no keys, so
// it bought nothing, and it is now deprecated in favour of ESLint core's
// `defineConfig()`. Spelling the array out drops the deprecated call without
// taking on `defineConfig()`'s stricter `plugins` typing, which react.js cannot
// satisfy — see the note there.
/** @type {import('typescript-eslint').ConfigArray} */
export const base = [
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    linterOptions: {
      // A disable directive that no longer suppresses anything is a failure, not
      // a warning. ESLint's own default here is `warn`, which this workspace
      // treats as off — and the thing it silences is specific: an inline disable
      // is an exception someone argued for once, and a dead one is that argument
      // outliving the code it was about. It then sits in the file reading like a
      // live exemption, and the next line that needs it inherits it without
      // anyone deciding. `inline-disables.test.js` inventories the directives
      // that disable a network or process.env ban; this covers every OTHER rule's
      // directives the same way, at lint time.
      reportUnusedDisableDirectives: 'error',
    },
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
];

// Every package keeps its build and tooling config at its own root —
// tsup.config.ts, vitest.config.ts, eslint.config.mjs, drizzle.config.local.ts.
// Those files are OSS source and belong behind the network ban, but they sit
// outside the tsconfig `include`, which lists only the compiled source dirs. The
// type-aware parser rejects a file no project owns ("was not found by the
// project service") and reports nothing else about it, so pointing `lint` at
// them means switching the type-aware rules off for exactly those paths. That
// costs the type-aware rules on a handful of config files and buys the
// no-network ban on all of them: every network rule is syntactic — restricted
// globals, member access, static imports, dynamic import/require — so all four
// still fire here.
//
// The glob is root-anchored (no `**/`), so a config file under src/ or test/ is
// left alone and keeps full type-aware linting. Spread this AFTER the block that
// turns `projectService` on: flat config resolves last-wins, so the order is
// what disables it for these paths.
/** @type {import('eslint').Linter.Config[]} */
export const rootConfigFiles = [
  {
    files: ['*.config.*'],
    ...tseslint.configs.disableTypeChecked,
  },
];

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
