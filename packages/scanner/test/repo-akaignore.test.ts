import { fileURLToPath } from 'node:url';

import { describeRepoAkaignore } from '../../../test/helpers/repo-akaignore.ts';
import { walkTree } from '../src/walk.ts';

// The repository's own root `.akaignore`, under the walker `/aka:scan` and the
// plugins' worktree scan use. The guard itself is shared with
// packages/local-ops, which runs it under the folder-scan walker.
describeRepoAkaignore('walkTree', fileURLToPath(new URL('..', import.meta.url)), function* (root) {
  for (const file of walkTree(root)) yield file.path;
});
