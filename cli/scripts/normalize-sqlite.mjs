import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// esbuild on some releases strips the `node:` prefix from `node:sqlite` down to a
// bare `sqlite` specifier (a nonexistent npm package), so we restore it on the
// emitted bundle. Shared by the published-CLI build (tsup.config.ts) and the SEA
// bundle (tsup.sea.config.ts); the claude-code plugin carries its own copy.
const SPECIFIER_SOURCE = String.raw`(\bfrom\s*|\b(?:import|require)\(\s*)(['"])sqlite\2`;

export function normalizeSqliteSpecifier(outDir) {
  for (const name of readdirSync(outDir)) {
    if (!/\.(?:js|mjs|cjs)$/.test(name)) continue;
    const file = join(outDir, name);
    const before = readFileSync(file, 'utf8');
    const after = before.replace(
      new RegExp(SPECIFIER_SOURCE, 'g'),
      (_match, prefix, quote) => `${prefix}${quote}node:sqlite${quote}`,
    );
    if (after !== before) writeFileSync(file, after);
    if (new RegExp(SPECIFIER_SOURCE).test(after)) {
      throw new Error(
        `normalize-sqlite: ${name} still imports a bare "sqlite" specifier after ` +
          `node:sqlite normalization — esbuild's emit format may have changed; failing the build.`,
      );
    }
  }
}
