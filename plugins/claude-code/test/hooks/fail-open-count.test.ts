import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// test/hooks -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/**
 * Every hook entry tsup builds, DERIVED from the build config rather than
 * listed here: a ninth hook lands in `entry` first, and this suite has to
 * reach it without anyone remembering to add it below.
 */
function hookEntries(): string[] {
  const config = readFileSync(join(PLUGIN_ROOT, 'tsup.config.ts'), 'utf8');
  return [...config.matchAll(/'src\/hooks\/([a-z-]+)\.ts'/g)]
    .map((match) => match[1])
    .filter((name): name is string => name !== undefined);
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

  it('derives a non-empty entry set from tsup.config.ts (positive control)', () => {
    expect(entries.length).toBeGreaterThanOrEqual(8);
    expect(entries).toContain('session-start');
  });

  it.each(entries)('%s calls countFailOpen() inside its top-level catch', (name) => {
    const source = readFileSync(join(PLUGIN_ROOT, 'src', 'hooks', `${name}.ts`), 'utf8');
    const guard = FAIL_OPEN_GUARD.exec(source);
    expect(guard, `${name}.ts must end in the try { await main() } catch guard`).not.toBeNull();
    expect(guard?.[1]).toMatch(/\bcountFailOpen\(\);/);
  });
});
