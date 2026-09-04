// The one pre-migrated store every suite in this worker copies from.
//
// `createStoreTemplate` is at the repo root because six packages need this
// shape; what belongs here is the build step — the persistence-specific half —
// and a single module-scope instance, so every suite loaded into a worker
// shares one build rather than one each.
//
// Deliberately empty beyond what `openLocalDatabase` itself writes (the schema,
// the migration ledger, the default policies). A template carrying fixture rows
// would make every suite that copies it depend on rows it never seeded, which
// is the order-dependence per-test isolation exists to prevent.
import { createStoreTemplate } from '../../../../test/helpers/store-template.ts';
import { openLocalDatabase } from '../../src/database.ts';

export const migratedStore = createStoreTemplate((dataDir) => {
  openLocalDatabase(dataDir).close();
});
