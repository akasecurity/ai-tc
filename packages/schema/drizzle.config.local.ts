import { defineConfig } from 'drizzle-kit';

// Local SQLite store — the drizzle-kit config for the single-node local store.
// `pnpm --filter @akasecurity/schema gen:sqlite-ddl` runs `drizzle-kit generate` against
// this config, then bundles the emitted SQL into src/drizzle/sqlite-ddl.ts
// (SQLITE_MIGRATIONS) for the plugin/CLI to self-apply via node:sqlite.
export default defineConfig({
  dialect: 'sqlite',
  schema: './src/drizzle/local/sqlite.ts',
  out: './drizzle/local-sqlite',
});
