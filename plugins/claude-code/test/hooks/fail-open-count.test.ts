import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';

import type * as Shared from '../../src/hooks/shared.ts';

// The fail-open path, run in-process: every entry's main() starts by reading
// stdin, so a read that rejects sends each entry straight into its top-level
// catch. countFailOpen is replaced by a spy so the case can see the call.
const failOpen = vi.hoisted(() => ({ count: vi.fn() }));
vi.mock('../../src/hooks/shared.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof Shared>()),
  readStdin: () => Promise.reject(new Error('stdin unavailable')),
  countFailOpen: failOpen.count,
}));

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

describe('every hook entry counts its fail-open exit when main() throws', () => {
  // The source-shape cases above pin WHERE the call sits; these run it. Each
  // entry is imported once, which executes its top-level try/catch with a stdin
  // read that rejects, so the only way to satisfy the spy is the real catch body.
  const entries = hookEntries();
  let exit: MockInstance<typeof process.exit>;

  beforeEach(() => {
    failOpen.count.mockClear();
    exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as typeof process.exit);
  });

  afterEach(() => {
    exit.mockRestore();
  });

  it.each(entries)('%s counts one exit and still exits 0', async (name) => {
    await import(`../../src/hooks/${name}.ts`);
    expect(failOpen.count).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(0);
  });
});
