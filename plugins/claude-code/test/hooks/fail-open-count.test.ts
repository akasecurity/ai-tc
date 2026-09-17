import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// test/hooks -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOKS_DIR = join(PLUGIN_ROOT, 'src', 'hooks');

/**
 * Every hook entry tsup builds, DERIVED from the build config rather than
 * listed here: a ninth hook lands in `entry` first, and this suite has to
 * reach it without anyone remembering to add it below. The pattern accepts any
 * file name, so a digit or an underscore in a new entry's name cannot hide it.
 */
function hookEntries(): string[] {
  const config = readFileSync(join(PLUGIN_ROOT, 'tsup.config.ts'), 'utf8');
  return [...config.matchAll(/'src\/hooks\/([^'/]+)\.ts'/g)]
    .map((match) => match[1])
    .filter((name): name is string => name !== undefined);
}

/**
 * Every file in `src/hooks` shaped like an entry — one that ends by exiting —
 * read from the directory rather than from the build config, so the two
 * derivations check each other.
 */
function entryShapedFiles(): string[] {
  return readdirSync(HOOKS_DIR)
    .filter((file) => file.endsWith('.ts'))
    .filter((file) => /\nprocess\.exit\(0\);\n?$/.test(readFileSync(join(HOOKS_DIR, file), 'utf8')))
    .map((file) => file.slice(0, -'.ts'.length));
}

// The top-level fail-open guard every entry ends in, capturing the catch body.
const FAIL_OPEN_GUARD =
  /\ntry \{\n {2}await main\(\);\n\} catch \{\n([\s\S]*?)\n\}\nprocess\.exit\(0\);\n?$/;

describe('every hook entry counts its fail-open exit', () => {
  // Failing open is the ABSENCE of output, so nothing a built hook prints can
  // show whether this call is wired — the e2e fail-open matrix asserts an
  // empty stdout either way. The shape is pinned at the source instead: the
  // catch that swallows the throw is also the only place that can count it.
  const entries = hookEntries();

  it('derives EXACTLY the entry-shaped files in src/hooks from tsup.config.ts', () => {
    // An exact set, not a floor: an entry the config pattern misses, or a hook
    // wired some other way, fails here instead of generating no case below.
    // The named member keeps two empty derivations from agreeing vacuously.
    expect(entries).toContain('session-start');
    expect(new Set(entries)).toEqual(new Set(entryShapedFiles()));
  });

  it.each(entries)('%s calls countFailOpen() inside its top-level catch', (name) => {
    const source = readFileSync(join(HOOKS_DIR, `${name}.ts`), 'utf8');
    const guard = FAIL_OPEN_GUARD.exec(source);
    expect(guard, `${name}.ts must end in the try { await main() } catch guard`).not.toBeNull();
    expect(guard?.[1]).toMatch(/\bcountFailOpen\(\);/);
  });
});
