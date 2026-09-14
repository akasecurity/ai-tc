import { afterEach } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';

/**
 * NEVER RUN. A fixture for the temp-home guard's positive control: a helper
 * module on disk that registers a teardown removing a tree, which the guard
 * requires the scan to find through a real import. Its file name does not end
 * in `.test.ts`, so vitest never collects it, and no suite imports it.
 */
export function installRemovingTeardown(dir: string): void {
  afterEach(() => {
    removeTree(dir);
  });
}
