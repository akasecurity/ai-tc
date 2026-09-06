// The esbuild entry the CLI shim (scripts/sanitize-capture.mjs) bundles. This
// directory is a DEV TOOL — nothing under src/ outside src/sanitize/ may import
// it, so the sanitiser never rides along in the page bundle.
export * from './classify.ts';
export * from './detector.ts';
export * from './sanitize-capture.ts';

import { ADAPTERS } from '../providers/registry.ts';

/** The adapter's own hostnames, or [] for a site no adapter drives. */
export function hostnamesForSite(site: string): readonly string[] {
  const adapter = ADAPTERS.find((a) => a.id === site);
  return adapter ? adapter.hostnames : [];
}
