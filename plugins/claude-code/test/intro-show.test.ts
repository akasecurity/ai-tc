/**
 * scripts/intro.js — the setup-wizard intro card emitter. Runs the BUILT script
 * the wizard actually shells out to (passing the real plugin manifest path, as
 * the wizard does) and asserts its stdout is a single SHOW region carrying the
 * fenced card — the honest end-to-end check that intro.ts's emit is wrapped
 * through present.ts's show(), not just that show()+fenced() compose correctly
 * in isolation.
 */
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { parseSurface } from '../src/setup-show.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test -> plugins/claude-code
const PLUGIN_ROOT = join(HERE, '..');
const SCRIPT = join(PLUGIN_ROOT, 'scripts', 'intro.js');
const MANIFEST = join(PLUGIN_ROOT, '.claude-plugin', 'plugin.json');

describe('scripts/intro.js', () => {
  const stdout = execFileSync(process.execPath, [SCRIPT, MANIFEST], { encoding: 'utf8' });
  const surface = parseSurface(stdout);

  it('emits the intro card inside exactly one SHOW region, with no untagged status output', () => {
    expect(surface.shows).toHaveLength(1);
    expect(surface.shows[0]).toContain('● AKA Security');
    expect(surface.status.trim()).toBe('');
  });
});
