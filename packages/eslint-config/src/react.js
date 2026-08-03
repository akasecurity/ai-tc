// @ts-check
import pluginReact from 'eslint-plugin-react';
import pluginReactHooks from 'eslint-plugin-react-hooks';

import { base } from './index.js';

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

export default react;
