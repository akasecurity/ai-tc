import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

// Static file tracers (@vercel/nft, and bundlers that copy asset URLs) follow
// `new URL('<literal>', import.meta.url)` and nothing computed. A worker URL
// built from a variable, or written inside an arrow function (which nft does
// not walk for this pattern), ships a bundle without its worker, and every
// rule that needs isolation is then dropped. This pins the form, not just the result:
// the runtime tests below the resolver cannot see what a tracer sees.
const source = readFileSync(new URL('../src/isolated-scan.ts', import.meta.url), 'utf8');

describe('scan worker URL is statically traceable', () => {
  it('names the built worker with a literal relative URL', () => {
    expect(source).toContain(`new URL('./scan-worker.js', import.meta.url)`);
  });

  it('keeps the source fallback, after the built worker', () => {
    const built = source.indexOf(`new URL('./scan-worker.js', import.meta.url)`);
    const fallback = source.indexOf(`new URL('./scan-worker.ts', import.meta.url)`);
    expect(fallback).toBeGreaterThan(built);
  });

  it('builds no worker URL from a variable', () => {
    expect(source).not.toMatch(/new URL\(\s*[A-Za-z_$][\w$]*\s*,\s*import\.meta\.url\s*\)/);
  });

  it('writes no worker URL inside an arrow function', () => {
    expect(source).not.toMatch(/=>\s*new URL\('\.\/scan-worker/);
  });
});
