// build/engine.mjs, driven in-process: the shipped build, and the checks that
// fail it rather than ship a module the mod runtime cannot load.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
// @ts-expect-error build/engine.mjs is plain JavaScript
import { buildEngine } from '../../build/engine.mjs';

interface Built {
  file: string;
  bytes: number;
  source: string;
}
const build = buildEngine as (options?: { stdin?: string; outFile?: string }) => Promise<Built>;

const out = mkdtempSync(join(tmpdir(), 'aka-build-engine-'));
afterAll(() => {
  removeTree(out);
});

describe('buildEngine', () => {
  it('bundles the entry into a module with no imports', async () => {
    const built = await build({ outFile: join(out, 'engine.js') });
    expect(built.bytes).toBeGreaterThan(1000);
    expect(built.source).toContain('registerBundledPacks');
  });

  it.each([
    [
      'a node: import',
      `import { sep } from 'node:path'; export const x = sep;`,
      'Could not resolve',
    ],
    ['a require shim', `export const x = typeof require;`, 'require shim'],
    ['import.meta', `export const x = import.meta.url;`, 'import.meta'],
  ])('fails the build on %s', async (_name, stdin, problem) => {
    await expect(build({ stdin, outFile: join(out, 'bad.js') })).rejects.toThrow(problem);
  });
});
