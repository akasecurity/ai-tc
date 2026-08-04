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
    // The rule above only catches a spelling that NAMES the field, and the
    // likeliest accidental edit does not: `String(error)` renders
    // `Error: <the message>` and `error.stack` opens with that same line, so
    // both put the store value on screen while reading nothing called
    // `message`.
    //
    // So pin the reads instead of the spellings: strip the three occurrences
    // this file is entitled to — the prop type, the destructure, and the one
    // allowed read — and require that no mention of `error` survives. Scoping
    // this to the JSX body would be narrower than the hole: `const e = error`
    // sits ABOVE the return, so an aliased `{String(e)}` names neither `error`
    // nor `message` anywhere the body can see.
    //
    // Each strip fails closed. A rename that stops one matching leaves its
    // `error` in place and reddens this line, rather than quietly widening it.
    const reads = code
      .replace(/error:\s*Error\s*&\s*\{[^}]*\}/, '')
      .replace(/\{\s*error,\s*reset,?\s*\}/, '')
      .replace(/error\.digest/g, '');
    expect(reads).not.toMatch(/\berror\b/);
  });

  it('would catch a message render (the stripper keeps code intact)', () => {
    // Without this, a stripper bug that emptied `code` would make the absence
    // assertion above pass vacuously.
    expect(code).toContain('AppError');
    expect(code.replace(/\s/g, '').length).toBeGreaterThan(200);
  });

  it('is not made redundant by the production build', () => {
    // Next replaces a SERVER component's error message with a generic string
    // before it reaches this boundary in production, which can read as though
    // the guard above has nothing left to catch. It does: dev passes the real
    // message through always, and a CLIENT component that throws during render
    // arrives here with its message intact in production too. This case exists
    // to carry that reason next to the assertion it justifies.
    expect(code).toContain("'use client'");
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
    // Match the pair as a unit, not `aria-busy` alone. The visible half of this
    // is `className={dim}`, so counting only the ARIA attribute pins the half
    // nobody can see and misses the half everyone can: drop one region's
    // `className={dim}` and keep its `aria-busy` and the region silently stops
    // dimming while the count still reads 2.
    expect(code.match(/aria-busy=\{navPending\}\s+className=\{dim\}/g) ?? []).toHaveLength(2);
  });

  it('dims while pending rather than at rest', () => {
    // The case above pins that both regions carry `className={dim}`; it says
    // nothing about what `dim` resolves to, and that is one operator away from
    // being exactly backwards. `cn` drops a boolean argument, so `&&` -> `||`
    // makes the class list `opacity-60` at rest and bare while a navigation is
    // pending: both regions sit permanently faded and brighten precisely when
    // their data is being replaced. Both call sites stay byte-identical, so
    // the pair count above still reads 2.
    //
    // Pinning the definition covers the same line's other one-token failures —
    // dropping the second `cn` argument, or `opacity-60` -> `opacity-100`,
    // which is emitted, survives tailwind-merge, and means fully opaque.
    expect(code).toMatch(
      /const dim = cn\(\s*'transition-opacity duration-150',\s*navPending && 'opacity-60',?\s*\)/,
    );
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
    // Pin the whole interception as one whitespace-free string rather than
    // checking that the five property names appear somewhere. Naming them
    // individually pins the vocabulary and not the logic, and every way this
    // handler actually breaks leaves the vocabulary intact:
    //
    //   e.button   -> e.buttons     `toContain('e.button')` is SATISFIED by the
    //                               longer spelling, and `buttons` is the mask
    //                               of buttons HELD, which is 0 during a click
    //                               — so the secondary-button escape is dead.
    //   !== 0      -> === 0         the bail fires on the plain left-click it
    //                               exists to let through; `pushUrl` is then
    //                               unreachable and no region ever dims.
    //   a||b||c||d -> !a||!b||!c||!d  a De Morgan slip: all five names still
    //                               present, but the bail only fires when all
    //                               four modifiers are held at once.
    //
    // Pinning the trailing `e.preventDefault(); pushUrl(auditHref);` in the
    // same string additionally fixes their ORDER: hoisting `preventDefault`
    // above the bail keeps every token but turns each modifier click into a
    // dead click — the browser never opens the tab and the handler returns
    // without pushing.
    //
    // Whitespace-free so a reformat cannot redden it; a real edit to this
    // handler is meant to redden it, and the shape is short enough to re-read.
    expect(code.replace(/\s+/g, '')).toContain(
      'if(e.defaultPrevented||e.button!==0||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)' +
        '{return;}e.preventDefault();pushUrl(auditHref);',
    );
  });
});
