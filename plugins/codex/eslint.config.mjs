// @ts-check
import {
  base,
  drizzleWallRules,
  noDrizzleImports,
  rootConfigFiles,
} from '@akasecurity/eslint-config';

// The selectors the package wall carries: the entry below sets
// `no-restricted-syntax` for the hooks, which replaces the wall's value for
// those files, so it lists them again beside its own.
const wallRule = drizzleWallRules()['no-restricted-syntax'];
const wallSelectors = Array.isArray(wallRule) ? wallRule.slice(1) : [];

// A hook reaches the capture runtime, the governance question and the refusal
// row only through src/hooks/stamped-capture.ts. Each name is refused as a member
// call (by name, by a computed literal, or by a template with no expression); a
// runtime method is also refused as a destructured member, and an imported
// function as an import specifier or a plain call. A plain call of `capture` is
// allowed, because a function may take a callback of that name. A selector cannot
// follow a binding, so a call through a renamed binding, one whose name is held
// in a variable, and an indirect call (`runtime.capture.call(...)`) are not seen.
const memberCalls = (name) => [
  `CallExpression[callee.property.name='${name}']`,
  `CallExpression[callee.property.value='${name}']`,
  `CallExpression[callee.property.type='TemplateLiteral'][callee.property.expressions.length=0][callee.property.quasis.0.value.cooked='${name}']`,
];
const destructured = (name) => [
  `ObjectPattern > Property[key.name='${name}']`,
  `ObjectPattern > Property[key.value='${name}']`,
];
const importedCalls = (name) => [
  `CallExpression[callee.name='${name}']`,
  `ImportSpecifier[imported.name='${name}']`,
  `ImportSpecifier[imported.value='${name}']`,
];
const stampedOnlySelectors = [
  ...['capture', 'captureDeferred'].flatMap((name) =>
    [...memberCalls(name), ...destructured(name)].map((selector) => ({
      selector,
      message: 'Capture through stamped-capture.ts (captureStamped), with a stamped key.',
    })),
  ),
  ...[...memberCalls('governanceApplies'), ...importedCalls('governanceApplies')].map(
    (selector) => ({
      selector,
      message: 'Ask through stamped-capture.ts (governedAt), with a stamped key.',
    }),
  ),
  ...[...memberCalls('buildModelRefusalEvent'), ...importedCalls('buildModelRefusalEvent')].map(
    (selector) => ({
      selector,
      message: 'Build the refusal row through stamped-capture.ts (modelRefusalAt).',
    }),
  ),
];

export default [
  ...base,
  ...noDrizzleImports,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    // The ephemeral judge subprocess inherits the host environment untouched:
    // `codex` must resolve on PATH and its auth (CODEX_HOME / ~/.codex
    // credentials) must survive the spawn.
    files: ['src/triage/judge.ts'],
    rules: {
      'n/no-process-env': 'off',
    },
  },
  {
    // A hook reaches the capture runtime, the governance question and the
    // refusal row only through src/hooks/stamped-capture.ts, which takes the key
    // the account scope stamped.
    files: ['src/hooks/**/*.ts'],
    ignores: ['src/hooks/stamped-capture.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...wallSelectors, ...stampedOnlySelectors],
    },
  },
  ...rootConfigFiles,
];
