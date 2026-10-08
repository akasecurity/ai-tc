import { readFileSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';

import { describe, expect, it } from 'vitest';

import * as root from '../src/index.ts';
import * as entry from '../src/sqlite-free.ts';

const SRC = resolve(import.meta.dirname, '../src');
const ENTRY = resolve(SRC, 'sqlite-free.ts');

// A value import or re-export, with its specifier. `import type` and
// `export type` are erased and load nothing, so they are skipped; anything
// else loads its module, including `import { type A } from 'x'` under
// `verbatimModuleSyntax`.
const VALUE_EDGE = /^\s*(?:import|export)\s+(?!type\b)[^;]*?from\s+'([^']+)'/gm;
const BARE_IMPORT = /^\s*import\s+'([^']+)'/gm;

function valueSpecifiers(file: string): string[] {
  const source = readFileSync(file, 'utf8');
  return [...source.matchAll(VALUE_EDGE), ...source.matchAll(BARE_IMPORT)].map((m) => m[1] ?? '');
}

/** Every module of this package the entry loads, and the builtins they import. */
function closure(): { modules: string[]; builtins: Set<string> } {
  const seen = new Set<string>();
  const builtins = new Set<string>();
  const queue = [ENTRY];
  for (let file = queue.shift(); file; file = queue.shift()) {
    if (seen.has(file)) continue;
    seen.add(file);
    for (const specifier of valueSpecifiers(file)) {
      if (specifier.startsWith('.')) queue.push(resolve(dirname(file), specifier));
      else if (specifier.startsWith('node:')) builtins.add(specifier);
    }
  }
  const modules = [...seen].map((f) => relative(SRC, f).split(sep).join('/')).sort();
  return { modules, builtins };
}

describe('the ./sqlite-free entry', () => {
  it('serves the bindings the root entry exports, not copies', () => {
    const names = Object.keys(entry);
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      expect(name in root, `${name} is not exported from the root entry`).toBe(true);
      expect((entry as Record<string, unknown>)[name]).toBe(
        (root as Record<string, unknown>)[name],
      );
    }
  });

  it('loads no module that imports node:sqlite', () => {
    const { modules, builtins } = closure();
    // The positive control: the walk really followed the entry's re-exports,
    // so an empty result below is not an empty graph.
    expect(modules).toContain('fingerprint.ts');
    expect(builtins.has('node:crypto')).toBe(true);

    expect(builtins.has('node:sqlite')).toBe(false);
    expect(modules).not.toContain('index.ts');
    expect(modules).not.toContain('database.ts');
  });
});
