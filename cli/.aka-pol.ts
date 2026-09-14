// Temporarily lower ONE pack's policy so a capture reaches the store unmasked.
// Content is redacted for any finding resolving to at least `redact`
// (plugin-sdk/src/runtime.ts), so `warn` is the weakest change that stops it
// while still recording the finding. NO try/catch: a PolicyFloorError must
// surface rather than be swallowed into a false success.
import { defaultDataDir, openLocalDatabase } from '@akasecurity/persistence';

const want = process.argv[2];
const db = openLocalDatabase(defaultDataDir());
const written = db.installedPacks.setPolicy('aka', 'secrets-infra', want);
console.log('setPolicy wrote:', written, '-> requested', want);
