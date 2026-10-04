import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { sourceTwin } from '../src/isolated-scan.ts';

// Static file tracers (@vercel/nft, and bundlers that copy asset URLs) follow
// `new URL('<literal>', import.meta.url)` exactly. A worker URL built from a
// variable, or written as an arrow function's expression body (which nft does
// not walk for this pattern), ships a bundle without its worker, and every rule
// that needs isolation is then dropped. A template string is traced as a file
// pattern, which can pull in unrelated files, so it is rejected too. Webpack follows the same literal and fails the build when the file
// is not beside the source, so the call also carries `webpackIgnore`. Only the
// built worker is spelled: the source-run fallback is derived from it at
// runtime, so no bundle that inlines this module carries a `.ts` worker path.
// This pins the form, not just the result: the runtime tests below the
// resolver cannot see what a tracer sees.
const raw = readFileSync(new URL('../src/isolated-scan.ts', import.meta.url), 'utf8');

/** The source with comments removed, so a commented-out literal cannot pass. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"])\/\/.*$/gm, '$1');
}

const code = stripComments(raw);
const IMPORT_META_URLS = /new URL\(\s*([^,]+?)\s*,\s*import\.meta\.url\s*\)/g;
const firstArguments = [...code.matchAll(IMPORT_META_URLS)].map((match) => match[1] ?? '');

describe('scan worker URL is statically traceable', () => {
  it('names the built worker, and only the built worker, with a literal relative URL', () => {
    expect(firstArguments).toEqual([`'./scan-worker.js'`]);
  });

  it('spells no source worker path in code', () => {
    expect(code).not.toContain('scan-worker.ts');
  });

  it('gives every direct new URL(<argument>, import.meta.url) call a quoted string literal', () => {
    // Catches a template string, `names[i]`, `opts.name`, `String(name)`. Not a
    // full parser: a first argument containing a comma, or a base aliased away
    // from `import.meta.url`, is not seen here. The first test still pins the
    // worker literal exactly, which is the property that ships.
    expect(firstArguments.length).toBeGreaterThan(0);
    for (const argument of firstArguments) expect(argument).toMatch(/^'[^'`$]*'$/);
  });

  it('writes no worker URL as an arrow function expression body', () => {
    expect(code).not.toMatch(/=>\s*new URL\(/);
  });

  it('probes the built worker before its source twin', () => {
    // No runtime case can tell the two orders apart: in each environment only
    // one of the two files exists. Reversed, an install with a stray
    // `scan-worker.ts` beside the bundle would load the source through type
    // stripping, the worker would fail to resolve its imports, and every rule
    // that needs isolation would be dropped.
    expect(code).toMatch(/\[\s*built\s*,\s*sourceTwin\(\s*built\s*\)\s*\]/);
    expect(code).not.toMatch(/\[\s*sourceTwin\(\s*built\s*\)\s*,\s*built\s*\]/);
  });

  it('tells webpack to leave the worker URL alone', () => {
    expect(raw).toContain(`new URL(/* webpackIgnore: true */ './scan-worker.js', import.meta.url)`);
  });
});

describe('sourceTwin', () => {
  it('swaps the trailing .js for .ts', () => {
    const twin = sourceTwin(pathToFileURL(resolve('repo', 'src', 'scan-worker.js')));
    expect(twin.href).toBe(pathToFileURL(resolve('repo', 'src', 'scan-worker.ts')).href);
  });

  it('leaves a .js elsewhere in the path alone', () => {
    const twin = sourceTwin(pathToFileURL(resolve('a.js', 'dir.js', 'scan-worker.js')));
    expect(twin.href).toBe(pathToFileURL(resolve('a.js', 'dir.js', 'scan-worker.ts')).href);
  });

  it('swaps the extension on the path, keeping the query and the fragment', () => {
    const built = pathToFileURL(resolve('repo', 'src', 'scan-worker.js'));
    built.search = '?v=1';
    built.hash = '#x';
    const expected = pathToFileURL(resolve('repo', 'src', 'scan-worker.ts'));
    expected.search = '?v=1';
    expected.hash = '#x';
    expect(sourceTwin(built).href).toBe(expected.href);
  });

  it('does not change the URL it is given', () => {
    const built = pathToFileURL(resolve('repo', 'src', 'scan-worker.js'));
    const before = built.href;
    sourceTwin(built);
    expect(built.href).toBe(before);
  });
});
