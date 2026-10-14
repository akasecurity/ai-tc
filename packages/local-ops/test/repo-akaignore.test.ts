import { fileURLToPath } from 'node:url';

import { describeRepoAkaignore } from '../../../test/helpers/repo-akaignore.ts';
import { collectFiles } from '../src/fs-scan.ts';

// The repository's own root `.akaignore`, under the walker every folder scan
// uses (`aka scan`, the dashboard's Scan page). The guard itself is shared
// with packages/scanner, which runs it under the other walker.
describeRepoAkaignore(
  'collectFiles',
  fileURLToPath(new URL('..', import.meta.url)),
  function* (root, home) {
    // A scratch home, so the protected credential roots name nothing in the copy.
    for (const file of collectFiles(root, { home, akaHome: `${home}/.aka` })) yield file.path;
  },
);
