import { resolve } from 'node:path';

import { defaultDataDir } from '@akasecurity/plugin-sdk';

// Every command accepts `--home <dir>` to point at an alternate AKA home (the
// ~/.aka base). Default is ~/.aka. NOT an env var — an explicit flag is testable
// and keeps the home path out of process.env.
export const HOME_OPTION = { home: { type: 'string' } } as const;

// Resolved, not taken verbatim: a trailing separator changes what the path
// MEANS to the filesystem. `statSync('<a regular file>/')` raises ENOTDIR
// rather than describing the file, so a guard that asks "is this path a
// non-directory?" is answered "no" and waves the path through — `aka init`
// then failed with exactly the bare mkdir error its guard exists to replace.
// `resolve` also makes a relative --home absolute, so every path derived from
// it is stable against a later chdir.
export function homeBase(home: string | undefined): string {
  return home === undefined ? defaultDataDir() : resolve(home);
}
