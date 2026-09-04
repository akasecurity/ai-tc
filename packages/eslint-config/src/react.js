// @ts-check
import pluginReact from 'eslint-plugin-react';
import pluginReactHooks from 'eslint-plugin-react-hooks';

import { base, noDrizzleImports, reactSyntaxBans, tonalInkTokens } from './index.js';

// A plain flat-config array, for the reason spelled out over `base` in
// index.js: the `tseslint.config()` wrapper this used to carry returned the
// same entries by identity and is now deprecated. The annotation stays
// typescript-eslint's `ConfigArray` rather than ESLint's own `Linter.Config[]`:
// the latter types `plugins` strictly enough to reject eslint-plugin-react-hooks'
// declarations (its `configs.flat` does not fit the `Plugin['configs']` index
// signature), which is a gap in that plugin's types, not in this config.
/** @type {import('typescript-eslint').ConfigArray} */
export const react = [
  ...base,
  {
    plugins: {
      react: pluginReact,
      'react-hooks': pluginReactHooks,
    },
    settings: {
      react: { version: 'detect' },
    },
    rules: {
      ...pluginReact.configs.recommended.rules,
      ...pluginReactHooks.configs.recommended.rules,
      'react/react-in-jsx-scope': 'off',
      'react/prop-types': 'off',
    },
  },
];

// The full preset for a package that renders Tailwind classes in a browser:
// ui-kit, dashboard-ui and web-ui. Composed here rather than spread three times
// per package because the ORDER is load-bearing and invisible at the call site.
// `no-restricted-imports` and `no-restricted-syntax` are both REPLACED rather
// than merged by a later flat-config entry, so:
//   - `noDrizzleImports` must come after `react` (whose `base` sets the network
//     bans), or its own entry is the one that gets dropped;
//   - `tonalInkTokens` comes last and re-lists the network AND drizzle selectors,
//     because it sets `no-restricted-syntax` too.
// Spread this, add the package's own `parserOptions`, then `rootConfigFiles`.
/** @type {import('typescript-eslint').ConfigArray} */
export const reactUiPackage = [...react, ...noDrizzleImports, ...tonalInkTokens];

// The same preset, LAYERED with a `src/**`-scoped widening of the clock ban,
// for a package with no legitimate ambient-clock reader anywhere in it:
// `dashboard-ui` and `ui-kit`, which never capture a render instant themselves
// (that is `web-ui`'s `renderInstant()`) and only ever take one as a prop.
// `web-ui` keeps `reactUiPackage` unchanged — its Server Components are
// exactly where an instant is legitimately captured, so the clock ban there
// must stay scoped to `use client` modules.
//
// Built ON `reactUiPackage` rather than replacing it, because
// `tonalInkTokensPresentational` sets the WHOLE `no-restricted-syntax` value —
// network, drizzle and tonal included — so scoping THAT object to `src/**`
// would silently drop all three from every `test/**` file in the package, the
// same "a later entry replaces rather than merges" trap this module's other
// comments warn about. Layering a THIRD, `files`-scoped entry after
// `reactUiPackage` keeps the base (directive-scoped) ban as the floor
// everywhere and replaces it with the wider one only inside `src/**` — so
// `test/**` fixtures keep an unrestricted `Date.now()`, since asserting "this
// instant is far from now" is not the hydration-mismatch class this ban exists
// for. See `tonalInkTokensPresentational`'s doc for what the widening itself
// buys: a presentational helper module (no component, so no directive of its
// own — `relativeTime.ts` and `exceptions/meta.ts` are the two this repo
// ships) is invisible to the directive-anchored selector no matter how many
// client components import it, so reverting its required `now` argument back
// to a `Date.now()` default trips nothing there today.
/** @type {import('typescript-eslint').ConfigArray} */
export const presentationalUiPackage = [
  ...reactUiPackage,
  {
    files: ['src/**'],
    rules: { 'no-restricted-syntax': reactSyntaxBans({ ambientClockEveryModule: true }) },
  },
];

export default react;
