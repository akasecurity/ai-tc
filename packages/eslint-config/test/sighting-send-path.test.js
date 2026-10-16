import { readFileSync } from 'node:fs';
import { join, posix } from 'node:path';

import { describe, expect, it } from 'vitest';

import { lintableTrackedFiles, REPO_ROOT } from './helpers/lint-invocations.js';

// Credential sightings leave a machine through one transport, built by
// `createCredentialSightingsSender` in `@akasecurity/remote`, and only a
// forwarder that reads the sharing gate first may be handed it. This suite walks
// the whole workspace because a direct send can appear in any package; it lives
// here because this package's test inputs hash every tree it reads.

const TREE_WALK_TIMEOUT_MS = 30_000;

/** The transport's own package, where the route and the sender are defined. */
const TRANSPORT_HOME = 'packages/remote/src/';

/** The forwarders that read the sharing gate before they call the sender. */
const GATED_FORWARDERS = new Set([
  'forwardCredentialSightings',
  'forwardScanSightings',
  'sendScanSightings',
]);

const BUILDS_SENDER = /\bcreateCredentialSightingsSender\s*\(/g;
const CALLS_ROUTE = /\.recordCredentialSightings\s*\(/;

/** @param {string} file repo-relative posix path */
function isTestFile(file) {
  const segments = file.split('/');
  return (
    segments.slice(0, -1).some((s) => s === 'test' || s === 'tests') ||
    /\.(test|spec)\./.test(posix.basename(file))
  );
}

/**
 * The name of the call whose argument list holds `offset`: the identifier
 * before the nearest `(` left open at that point, or undefined.
 * @param {string} text
 * @param {number} offset
 */
function enclosingCallName(text, offset) {
  let depth = 0;
  for (let i = offset - 1; i >= 0; i -= 1) {
    const ch = text[i];
    if (ch === ')') depth += 1;
    else if (ch === '(') {
      if (depth === 0) return /([A-Za-z_$][\w$]*)\s*$/.exec(text.slice(0, i))?.[1];
      depth -= 1;
    }
  }
  return undefined;
}

/**
 * Each place in `sources` that builds the sender outside a gated forwarder's
 * arguments, or calls the route directly, as `path:offset`.
 * @param {{ path: string, text: string }[]} sources
 */
function ungatedSends(sources) {
  const found = [];
  for (const { path, text } of sources) {
    if (CALLS_ROUTE.test(text)) found.push(`${path}:route`);
    for (const match of text.matchAll(BUILDS_SENDER)) {
      if (!GATED_FORWARDERS.has(enclosingCallName(text, match.index) ?? '')) {
        found.push(`${path}:${String(match.index)}`);
      }
    }
  }
  return found;
}

function productSources() {
  return lintableTrackedFiles()
    .filter(
      (file) =>
        !isTestFile(file) &&
        !file.startsWith(TRANSPORT_HOME) &&
        !file.startsWith('test/') &&
        !file.startsWith('tools/'),
    )
    .map((file) => ({ path: file, text: readFileSync(join(REPO_ROOT, file), 'utf8') }));
}

describe('the credential-sightings send path', () => {
  it(
    'hands the sender only to a forwarder that reads the sharing gate',
    () => {
      expect(ungatedSends(productSources())).toEqual([]);
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'sees the surfaces that send, so it is not guarding an absence',
    () => {
      const builders = productSources()
        .filter((s) => /\bcreateCredentialSightingsSender\s*\(/.test(s.text))
        .map((s) => s.path);
      expect(builders).toEqual(
        expect.arrayContaining([
          'cli/src/commands/scan.ts',
          'packages/plugin-runtime/src/scan-sightings.ts',
          'web-ui/app/(app)/scan/actions.ts',
        ]),
      );
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it('flags a direct send, even beside a gated forwarder call in the same file', () => {
    const handedOn =
      'forwardScanSightings(base, target, result, { send: createCredentialSightingsSender() });';
    const fallback =
      'return forwardCredentialSightings(base, input, { send: deps.send ?? createCredentialSightingsSender() });';
    const direct = 'await createCredentialSightingsSender()(target, request);';
    const heldInAVariable =
      'const send = createCredentialSightingsSender();\nawait forwardScanSightings(a, b, c, { send });';
    const route = 'await client.recordCredentialSightings(request);';

    expect(
      ungatedSends([
        { path: 'handed-on.ts', text: handedOn },
        { path: 'fallback.ts', text: fallback },
        { path: 'mixed.ts', text: `${handedOn}\n${direct}` },
        { path: 'variable.ts', text: heldInAVariable },
        { path: 'route.ts', text: route },
      ]),
    ).toEqual([`mixed.ts:${String(handedOn.length + 7)}`, 'variable.ts:13', 'route.ts:route']);
  });
});
