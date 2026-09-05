import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { RESPONSE_TEXT_MAX_BYTES } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { TAP_CHANNEL } from '../src/tap-protocol.ts';

// The tap runs in the PAGE's own JS context, with the page's own authority. The
// manifest cannot express that constraint and no permission names it, so what
// bounds it is this file: the built bundle is read back and held to what a
// network tap needs and nothing more, and the two copies of the wire vocabulary
// — the tap's local mirror and the module the bridge imports — are pinned
// against each other.
//
// Read the BUILT file, not only the source: what ships is what esbuild emitted,
// and an import pulled in transitively would be invisible in the source.
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const MIN_BUNDLE_BYTES = 200;
// Generous, and still an order of magnitude under anything with a dependency in
// it. The point is to catch a bundle that grew a library, not to police bytes.
const SIZE_CEILING_BYTES = 24 * 1024;

// A build that did not run, or ran and emitted nothing, satisfies every absence
// check below — `''` contains no banned name at all. Ordering the emptiness
// check first among the `it`s does not gate the ones after it, because a failed
// case does not stop its siblings; so the floor is enforced HERE, at module
// scope, where breaching it takes the whole file down instead of leaving the
// vacuous checks reporting green beside one red.
function readBuiltBundle(): string {
  const path = join(PACKAGE_ROOT, 'dist', 'tap.js');
  const text = readFileSync(path, 'utf8');
  if (text.length < MIN_BUNDLE_BYTES) {
    throw new Error(
      `${path} is ${String(text.length)} bytes, under the ${String(MIN_BUNDLE_BYTES)}-byte ` +
        'floor — every absence check in this file is vacuous on a bundle this small. Build first.',
    );
  }
  return text;
}

const BUILT = readBuiltBundle();
const SOURCE = readFileSync(join(PACKAGE_ROOT, 'src', 'tap.ts'), 'utf8');
const PROTOCOL = readFileSync(join(PACKAGE_ROOT, 'src', 'tap-protocol.ts'), 'utf8');

// Every name a page-context script would reach for to do something a network
// tap has no business doing. Grouped by what each one buys an attacker who has
// landed code in this file, because "no network primitive" was far too narrow:
// a script that is already inside the page does not need a socket to exfiltrate
// — it has the DOM, the page's storage, other windows, and, if it can name
// `chrome`, the extension's own APIs.
//
// This is a SUBSTRING scan over the emitted text, so a name that legitimately
// appears anywhere in the bundle cannot go on the list. From the point the
// build injects real URL patterns, a pattern containing one of these tokens
// will fail this check for a benign reason; the answer then is to scan the
// bundle's code region rather than to drop the token.
const FORBIDDEN_NAMES = [
  // Transports other than the two the tap captures. A tap that opens one of
  // these is originating traffic rather than observing it.
  'WebSocket',
  'EventSource',
  'WebTransport',
  'RTCPeerConnection',
  'sendBeacon',
  // The extension surface. Bare, not `chrome.`, so a bracket-notation or
  // aliased reach (`globalThis['chrome']`, `const c = chrome`) is caught too —
  // that is an extension running inside the page, which is the escalation this
  // file exists to make impossible to land quietly.
  'chrome',
  'browser',
  // Page data at rest, and the DOM. The tap reads request and response bytes
  // off two functions it captured; it never needs to read what the user is
  // looking at, what the site stored, or the cookie jar — and it never needs to
  // put anything into the page.
  'document',
  'navigator',
  'localStorage',
  'sessionStorage',
  'indexedDB',
  'cookie',
  'innerHTML',
  'outerHTML',
  'insertAdjacent',
  // Other windows. A page-context script needs no socket to get bytes off the
  // machine: one postMessage to an opener, a parent frame or a window it named
  // hands every captured chunk to somebody else's code, and `window.name`
  // survives a cross-origin navigation. `postMessage` itself cannot be banned —
  // the handshake is one — so it is pinned by COUNT below instead.
  'parent',
  'top',
  'opener',
  // The minified form: esbuild emits no spaces around an assignment.
  '.name=',
  // `location` is NOT on this list and cannot be: the tap reads
  // `win.location.href` as the base for resolving a relative request URL, which
  // is what lets a target name a host at all.
  // Ways to run code the bundle does not contain, which would make every check
  // in this file describe the wrong program.
  'eval(',
  'Function(',
  'importScripts',
  'Worker',
];

// Extracts the string literals of the TapToPage union out of a source file, so
// the tap's hand-copied mirror can be compared with the module the bridge
// imports. Comments go first: a member name quoted in prose would otherwise
// count as a declaration.
function unionLiterals(source: string): string[] {
  const start = source.indexOf('type TapToPage =');
  expect(start, 'TapToPage is not declared in this source').toBeGreaterThan(-1);
  const end = source.indexOf('};', start);
  expect(end, 'the TapToPage declaration does not terminate').toBeGreaterThan(start);
  const declaration = source.slice(start, end).replace(/\/\/[^\n]*/g, '');
  return [
    ...new Set([...declaration.matchAll(/'([^']+)'/g)].map((match) => match[1] ?? '')),
  ].sort();
}

describe('the built tap bundle', () => {
  it('was emitted, and its floor gates every check in this file', () => {
    // Not the guard itself — readBuiltBundle() above is, and it throws before
    // any case runs. This states the floor where a reader will look for it.
    expect(BUILT.length).toBeGreaterThan(MIN_BUNDLE_BYTES);
  });

  it('carries no module imports', () => {
    expect(BUILT).not.toMatch(/\bimport\s*\(/);
    expect(BUILT).not.toMatch(/\bfrom\s*["']/);
    expect(BUILT).not.toMatch(/\brequire\s*\(/);
  });

  it('has no import in its own source either', () => {
    // The built check above cannot see an import esbuild INLINED, and that is
    // the case that actually happens: `bundle: true` resolves a relative or
    // installed specifier straight into the IIFE, so the emitted file names no
    // module even though the tap now carries that code. Measured rather than
    // reasoned — adding `import './tap-protocol.ts';` to src/tap.ts left
    // dist/tap.js byte-identical and every check above green.
    //
    // So both halves are read, and they fail on different things: this one
    // when the tap grows a dependency at all, the built one when a specifier
    // esbuild could not resolve is left in the artifact as a real import. The
    // size ceiling is the third leg, catching a dependency large enough to
    // show even though neither regex names it.
    expect(SOURCE).not.toMatch(/^[ \t]*import\b/m);
    expect(SOURCE).not.toMatch(/\bimport\s*\(/);
    expect(SOURCE).not.toMatch(/\brequire\s*\(/);
  });

  it('names nothing a network tap has no business naming', () => {
    // What this can see is the emitted TEXT. So it catches an API named in the
    // source and survives minification, because esbuild renames bindings and
    // not property names or globals it does not own. What it cannot see is a
    // name assembled at runtime (`self['ch' + 'rome']`), a capability reached
    // through a reference the page handed over, or anything the tap does with
    // the two transports it legitimately holds. The size ceiling and the
    // no-imports checks are the other legs; none of the three is the whole
    // bound on its own.
    for (const banned of FORBIDDEN_NAMES) {
      expect(BUILT, `the tap bundle names ${banned}`).not.toContain(banned);
    }
  });

  it('still intercepts both transports — the control on the absences above', () => {
    // Naming `fetch` proves nothing: the word survives as a property KEY in the
    // `patched` report even with every line of interception deleted. What only
    // real interception produces is an ASSIGNMENT over the page's own
    // properties, so that is what is asserted.
    //
    // The trailing `[^=>]` is load-bearing and was measured, not guessed: a
    // bare `\.fetch\s*=` also matches the feature test `typeof x.fetch ==
    // 'function'`, so the control passed on a build with the whole assignment
    // stripped out.
    expect(BUILT, 'the tap no longer replaces the page fetch').toMatch(/\.fetch\s*=[^=>]/);
    expect(BUILT, 'the tap no longer replaces XMLHttpRequest.prototype.open').toMatch(
      /\.open\s*=[^=>]/,
    );
    expect(BUILT, 'the tap no longer replaces XMLHttpRequest.prototype.send').toMatch(
      /\.send\s*=[^=>]/,
    );
    expect(BUILT).toContain('XMLHttpRequest');
  });

  it('posts to a window exactly once, for the handshake', () => {
    // The one name above that cannot be banned outright, so it is bounded by
    // count instead. Two occurrences ship: the port write every message goes
    // through, and the single handshake. A third is a second destination for
    // captured bytes — which is what an exfiltration out of the page looks
    // like, and it needs no transport this file bans.
    const posts = BUILT.match(/postMessage/g) ?? [];
    expect(posts).toHaveLength(2);
  });

  it('pulls at least as many response bytes as the host will store', () => {
    // Two ceilings on the same text, in two packages, with nothing between
    // them: what the TAP will pull from one response, and what the HOST will
    // keep of it. The tap's is upstream, so if the host's ever rises past it
    // the wire becomes the binding cap and the host's number silently stops
    // describing anything. Read out of the source rather than imported,
    // because src/tap.ts carries no imports and so cannot share a constant.
    const declared = /const RESPONSE_MAX_BYTES = (\d+) \* 1024 \* 1024;/.exec(SOURCE);
    expect(declared, 'RESPONSE_MAX_BYTES is not declared in the form this reads').not.toBeNull();
    const tapCeiling = Number(declared?.[1]) * 1024 * 1024;
    // Non-vacuous: a failed parse would otherwise compare NaN, which is neither
    // greater nor less and so cannot fail an inequality.
    expect(tapCeiling).toBeGreaterThan(0);
    expect(tapCeiling).toBeGreaterThanOrEqual(RESPONSE_TEXT_MAX_BYTES);
  });

  it('stays small enough to have no dependency in it', () => {
    expect(BUILT.length).toBeLessThan(SIZE_CEILING_BYTES);
  });

  it('speaks the handshake tag the protocol module declares', () => {
    // src/tap.ts cannot import that module — the emitted bundle must carry no
    // import at all — so it duplicates the literal. This is what pins the two
    // copies together: rename one and the bridge, which reads the module, stops
    // hearing a tap that is still shipping.
    expect(BUILT).toContain(TAP_CHANNEL);
  });

  it('emits exactly the vocabulary the protocol module declares', () => {
    // The other half of the same duplication. The tap mirrors TapToPage by
    // hand, and a member added on one side only is a message the bridge either
    // never sends for or silently drops — a divergence nothing else here reads,
    // since the built artifact carries the tap's copy and no other.
    const mirrored = unionLiterals(SOURCE);
    expect(mirrored).toEqual(unionLiterals(PROTOCOL));
    // Non-vacuous: an extractor that found nothing would make the line above
    // pass on two empty arrays.
    expect(mirrored).toContain('request');
    expect(mirrored).toContain('chunk');
  });
});
