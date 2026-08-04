import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
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

/**
 * A route directory as its posix-style path relative to (app). `path.relative`
 * yields the platform separator, so on Windows a nested route reads
 * `exceptions\\new` and matches nothing in the list below — the route set is
 * a URL vocabulary, not a filesystem detail, so it is normalised here.
 */
function routeName(dir: string): string {
  return relative(APP_DIR, dir).split(sep).join('/');
}

// Every route under (app), pinned. The ACTUAL set is derived from the tree
// above; this is the EXPECTED set, and the two are compared — the same
// derived-vs-pinned pairing EXPECTED_WORKSPACE_PACKAGE_NAMES uses in
// packages/eslint-config/test/effective-config.test.js.
//
// A count floor is not enough. A traversal that stopped recursing would drop
// the two nested routes and still clear any floor low enough to be safe,
// leaving them unchecked while the suite stayed green with fewer cases. Adding
// a route means adding it here, which is the point: a human has to notice.
const EXPECTED_ROUTES = [
  'activity',
  'data-shares',
  'detections',
  'exceptions',
  'exceptions/[id]',
  'exceptions/new',
  'findings',
  'inventory',
  'policies',
  'scan',
  'security',
  'settings',
  'updates',
  'vault',
];

describe('(app) route loading boundaries', () => {
  it('sees exactly the routes it expects', () => {
    expect(ROUTES.map(routeName).sort()).toEqual(EXPECTED_ROUTES);
  });

  it.each(ROUTES.map((r) => [routeName(r), r] as const))('%s has a loading.tsx', (_label, dir) => {
    expect(readdirSync(dir)).toContain('loading.tsx');
  });
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
    // Any read of `message`, not just the `error.message` spelling: a
    // destructure (`const { message } = error`) or a computed access
    // (`error['message']`) puts the same string on screen, so pinning one
    // spelling would let the other through. This is a boundary file with no
    // legitimate use of the word, so matching broadly costs nothing.
    expect(code).not.toMatch(/\bmessage\b/);
  });

  it('would catch a message render (the stripper keeps code intact)', () => {
    // Without this, a stripper bug that emptied `code` would make the absence
    // assertion above pass vacuously.
    expect(code).toContain('AppError');
    expect(code.replace(/\s/g, '').length).toBeGreaterThan(200);
  });
});

describe('exceptions page pending regions', () => {
  // The exceptions page drives TWO regions from two different params — ?window=
  // re-queries recentBlocked (the blocked ledger) and ?all= re-queries
  // exceptions.list (the table). Wrapping only one of them dims a region whose
  // data the change does not touch while leaving the other with no feedback,
  // which is exactly what shipped in the first draft of this change.
  const source = readFileSync(join(APP_DIR, 'exceptions', 'ExceptionsClient.tsx'), 'utf8');
  const code = source.replace(/\{\/\*[\s\S]*?\*\/\}/g, '').replace(/\/\/.*$/gm, '');

  it('dims both regions', () => {
    expect(code.match(/aria-busy=\{navPending\}/g) ?? []).toHaveLength(2);
  });

  it('routes the same-route audit toggle through the shared transition', () => {
    // A <Link> to ?all= is a same-route searchParams change, and no loading
    // boundary re-shows for one — without going through the transition it gets
    // no pending signal at all.
    expect(code).toMatch(/pushUrl\(auditHref\)/);
  });

  it('keeps the audit toggle a real link', () => {
    // The click interception must not cost open-in-new-tab or copy-link, so the
    // href stays and the modifier/secondary-button cases fall through.
    expect(code).toMatch(/href=\{auditHref\}/);
    expect(code).toContain('metaKey');
  });
});
