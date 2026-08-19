// @ts-check
import { base, noDrizzleImports, rootConfigFiles } from '@akasecurity/eslint-config';

export default [
  // Test fixture corpora are scanner INPUT, not compiled sources: they are
  // excluded from the tsconfig project, so the type-aware rules cannot resolve
  // them, and their contents are deliberately shaped for the extractor rather
  // than for the lint rules.
  { ignores: ['test/fixtures/**'] },
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
  ...rootConfigFiles,
];
