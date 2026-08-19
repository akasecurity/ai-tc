// @ts-check
import pluginReact from 'eslint-plugin-react';
import pluginReactHooks from 'eslint-plugin-react-hooks';

import { base, noDrizzleImports, tonalInkTokens } from './index.js';

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

export default react;
