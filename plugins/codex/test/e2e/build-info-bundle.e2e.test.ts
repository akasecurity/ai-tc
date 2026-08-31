/**
 * The posture identity's manifest path has to resolve from the PUBLISHED
 * plugin, and that is the one thing source-level tests cannot show: the plugin
 * ships `scripts/` and nothing else, so `build-info.ts`'s sibling-relative URL
 * is evaluated against the emitted entry's own location — never the source
 * file the unit tests import. If the emitted layout drifts (a nested outDir, a
 * splitting change, a relocated manifest), `pluginBuild()` catches the ENOENT
 * and every installed plugin silently resumes posture-reporting with no
 * plugin block, while the source-level suites stay green.
 *
 * So this suite reads the BUILT scripts, finds every emitted file that carries
 * the manifest URL, and resolves that URL from the file's real location — the
 * exact computation the shipped code performs at runtime.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

// test/e2e -> plugins/codex
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');
const MANIFEST_PATH = join(PLUGIN_ROOT, '.codex-plugin', 'plugin.json');

// The emit form of build-info.ts's manifest URL — quote-style tolerant, since
// that is the printer's choice, not ours.
const MANIFEST_URL_RE =
  /new URL\((['"])(\.\.\/\.codex-plugin\/plugin\.json)\1, import\.meta\.url\)/;

function emittedCarriers(): string[] {
  return readdirSync(SCRIPTS_DIR).filter(
    (name) =>
      name.endsWith('.js') && MANIFEST_URL_RE.test(readFileSync(join(SCRIPTS_DIR, name), 'utf8')),
  );
}

describe('the emitted scripts resolve the manifest from where they actually sit', () => {
  it('the session hook carries the manifest URL (the positive control)', () => {
    // Without this, a renamed or re-shaped emit empties the carrier set and
    // the resolution case below passes over nothing.
    expect(emittedCarriers()).toContain('session-start.js');
  });

  it('every emitted carrier resolves the URL to the real manifest', () => {
    for (const name of emittedCarriers()) {
      const resolved = new URL(
        '../.codex-plugin/plugin.json',
        pathToFileURL(join(SCRIPTS_DIR, name)),
      );
      expect(fileURLToPath(resolved), name).toBe(MANIFEST_PATH);
      const manifest = JSON.parse(readFileSync(resolved, 'utf8')) as { version?: unknown };
      expect(manifest.version, name).toBeTypeOf('string');
    }
  });
});
