import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

// Static file tracers (@vercel/nft, and bundlers that copy asset URLs) follow
// `new URL('<literal>', import.meta.url)` exactly. A worker URL built from a
// variable, or written as an arrow function's expression body (which nft does
// not walk for this pattern), ships a bundle without its worker, and every rule
// that needs isolation is then dropped. A template string is traced as a file
// pattern, which can pull in unrelated files, so it is rejected too. Webpack follows the same literal and fails the build when the file
// is not beside the source, so each call also carries `webpackIgnore`.
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
  it('names the built worker, then the source fallback, with literal relative URLs', () => {
    expect(firstArguments).toEqual([`'./scan-worker.js'`, `'./scan-worker.ts'`]);
  });

  it('gives every direct new URL(<argument>, import.meta.url) call a quoted string literal', () => {
    // Catches a template string, `names[i]`, `opts.name`, `String(name)`. Not a
    // full parser: a first argument containing a comma, or a base aliased away
    // from `import.meta.url`, is not seen here. The first test still pins the
    // two worker literals exactly, which is the property that ships.
    expect(firstArguments.length).toBeGreaterThan(0);
    for (const argument of firstArguments) expect(argument).toMatch(/^'[^'`$]*'$/);
  });

  it('writes no worker URL as an arrow function expression body', () => {
    expect(code).not.toMatch(/=>\s*new URL\(/);
  });

  it('tells webpack to leave each worker URL alone', () => {
    for (const name of ['./scan-worker.js', './scan-worker.ts']) {
      expect(raw).toContain(`new URL(/* webpackIgnore: true */ '${name}', import.meta.url)`);
    }
  });
});
