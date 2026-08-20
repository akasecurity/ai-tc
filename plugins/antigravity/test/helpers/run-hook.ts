import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';

// An isolated ~/.aka for one hook run: os.homedir() — which every hook
// resolves its data dir through — honors $HOME on POSIX, so overriding it
// points the whole chain at a throwaway temp home instead of a developer's
// real store. Windows resolves the home dir from USERPROFILE instead of HOME,
// so a caller sets both in lockstep, e.g. `{ HOME: home, USERPROFILE: home }`.
//
// `prefix` defaults to a generic tag; pass a case-specific one (e.g.
// `aka-agy-ptu-pointer-`) so a directory a failed teardown leaves behind on
// disk still names the case that leaked it.
export function withTempHome<T>(fn: (home: string) => T, prefix = 'aka-agy-hook-e2e-'): T {
  const home = mkdtempSync(join(tmpdir(), prefix));
  try {
    return fn(home);
  } finally {
    removeTree(home);
  }
}
