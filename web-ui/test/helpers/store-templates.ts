// The pre-built stores this package's suites copy from, instead of migrating a
// fresh one per test.
//
// `createStoreTemplate` is at the repo root because several packages need the
// same shape; what belongs here is the build step. Two are worth having,
// because the two costs a web-ui suite pays are separable:
//
//   `emptyStore`      — the schema alone, for a suite that seeds its own rows.
//   `withBundledPacks` — the schema plus the installed ruleset, for the action
//                        suites: `addException` scans against the DB snapshot
//                        rather than the engine's process-global registry, so
//                        every one of them needs `installed_packs` populated,
//                        and doing it per test re-reads the whole bundled set.
//
// Both are module-scope, so each is built once per worker and every suite
// loaded into that worker shares it. Per-test isolation is untouched: each test
// still gets its own file under its own mkdtemp home, and no handle is shared.
//
// `@akasecurity/plugin-sdk` is a dev-only dependency of this package for
// `bundledDetections()`, which is what it is already taken for elsewhere in
// these suites — a dev-only test dependency is not a runtime package-wall
// crossing.
import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';

import { createStoreTemplate } from '../../../test/helpers/store-template.ts';

/** Schema and default policies only — what `openLocalDatabase` writes itself. */
export const emptyStore = createStoreTemplate((dataDir) => {
  openLocalDatabase(dataDir).close();
});

/** The same, plus the bundled ruleset in `installed_packs`. */
export const withBundledPacks = createStoreTemplate((dataDir) => {
  const db = openLocalDatabase(dataDir);
  try {
    db.installedPacks.recordInventory(bundledDetections());
  } finally {
    db.close();
  }
});
