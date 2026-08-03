import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// Every route under (app) needs its own loading.tsx.
//
// The pages are force-dynamic, so a <Link> prefetch has nothing to fetch until a
// loading boundary exists — without one, clicking a sidebar item leaves the old
// page on screen with no feedback until the whole server render lands. A route
// added without a boundary regresses that silently, and there is no DOM test
// infrastructure here to catch it by rendering, so this reads the tree.
//
// The route set is derived (every directory holding a page.tsx), never a
// hardcoded list — a route added tomorrow has to be in it.
const APP_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'app', '(app)');

function routeDirs(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const child = join(dir, entry.name);
    const names = readdirSync(child);
    if (names.includes('page.tsx')) found.push(child);
    found.push(...routeDirs(child));
  }
  return found;
}

const ROUTES = routeDirs(APP_DIR);

describe('(app) route loading boundaries', () => {
  it('finds the routes to check', () => {
    // A traversal that silently matched nothing would pass every case below.
    expect(ROUTES.length).toBeGreaterThanOrEqual(12);
  });

  it.each(ROUTES.map((r) => [r.slice(APP_DIR.length + 1), r] as const))(
    '%s has a loading.tsx',
    (_label, dir) => {
      expect(readdirSync(dir)).toContain('loading.tsx');
    },
  );
});

describe('(app) error boundary', () => {
  const source = readFileSync(join(APP_DIR, 'error.tsx'), 'utf8');
  // Strip comments before asserting: the file's own doc comment names the field
  // it must not render, and a guard that reads prose would fail on the
  // explanation rather than on the code.
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

  it('is a client component taking error and reset', () => {
    expect(code).toContain("'use client'");
    expect(code).toMatch(/reset:\s*\(\)\s*=>\s*void/);
  });

  it('renders the digest, never the message', () => {
    // These pages read a store holding scanned content, and an error message can
    // carry the value that tripped the failure. The digest identifies the same
    // error in the server log without putting store content on screen.
    expect(code).toContain('error.digest');
    expect(code).not.toContain('error.message');
  });

  it('would catch a message render (the stripper keeps code intact)', () => {
    // Without this, a stripper bug that emptied `code` would make the absence
    // assertion above pass vacuously.
    expect(code).toContain('AppError');
    expect(code.replace(/\s/g, '').length).toBeGreaterThan(200);
  });
});
