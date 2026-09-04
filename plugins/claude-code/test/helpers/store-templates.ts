// The pre-migrated store this package's suites copy from, instead of running
// every migration on a fresh store per test.
//
// `createStoreTemplate` lives at the repo root because several packages need
// the same shape and `@akasecurity/persistence`'s own harness is behind a
// package wall; what belongs here is the build step, plus a single
// module-scope instance so every suite loaded into a worker shares one build.
//
// Per-test isolation is unchanged: each test still gets its own file, in its
// own directory, with no handle shared between them.
import { openLocalDatabase } from '@akasecurity/persistence';

import { createStoreTemplate } from '../../../../test/helpers/store-template.ts';

export const migratedStore = createStoreTemplate((dataDir) => {
  openLocalDatabase(dataDir).close();
});
