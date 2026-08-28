import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT, trackedFiles } from './helpers/lint-invocations.js';

// The attached posture report's `plugin` block is produced only when the
// resolving caller passes its build identity (`meta.pluginBuild`), and the
// receiver replaces the plugin columns wholesale on every report — so ONE
// caller that reaches `ensureInventory` without the identity makes the fleet
// row flicker to null whenever that path wins the hourly throttle. That is the
// missing-producer bug this feature fixed, reintroduced intermittently.
//
// "Every caller that can reach ensureInventory carries pluginBuild" was a
// hand-maintained invariant in a resolve.ts comment. This suite converts it
// into a structural one, derived from the tracked tree rather than listed:
//
//  - every shipped-source file carrying the `handleSessionStart(` call form
//    (the adapters' door to the inventory pass, and its definition) must
//    spell the `pluginBuild:` key it threads;
//  - every shipped-source file that both resolves a gateway and calls
//    `.ensureInventory(` on one (the reconcilers, and the runtime's own
//    session pass) must spell it too.
//
// It lives HERE, beside the other tree-wide walks, because only this package's
// turbo `test` inputs hash the whole workspace: the same check inside
// plugin-runtime would replay a cached green while an unwired caller appeared
// in a plugin. A source-text rule cannot judge the VALUE passed — the
// per-package behavioural pins (usage.test.ts, handle-session-start.test.ts,
// host.test.ts, factory-posture.test.ts) hold that half; this holds the set.
const TREE_WALK_TIMEOUT_MS = 30_000;

/** Shipped source: package src trees, never tests, benches, or build output. */
function shippedSource() {
  return trackedFiles().filter(
    (file) =>
      /\/src\/.*\.ts$/.test(file) && !file.endsWith('.d.ts') && !file.includes('/test-fixtures/'),
  );
}

function read(file) {
  return readFileSync(join(REPO_ROOT, file), 'utf8');
}

// The adapters' door — the CALL form, never the bare name: several files
// mention handleSessionStart in prose, and counting those is the same
// comment-counts-as-caller trap the fixture-import audit documents.
const SESSION_PASS_RE = /\bhandleSessionStart\(/;
// A gateway resolved AND driven through the inventory pass in the same file.
const RESOLVES_RE = /\bresolveDataGateway\(/;
const ENSURES_RE = /\.ensureInventory\(/;

// Exact sets, not floors: a NEW file entering either set is a new surface that
// must decide about posture identity on purpose, and a file leaving one is a
// caller this guard silently stopped covering. Both deserve a deliberate edit
// here — and the sets double as the positive control that the regexes still
// match anything at all.
const EXPECTED_SESSION_PASS_FILES = [
  'packages/plugin-runtime/src/handle-session-start.ts',
  'plugins/antigravity/src/hooks/pre-invocation.ts',
  'plugins/browser-extension/src/native-host/host.ts',
  'plugins/claude-code/src/hooks/session-start.ts',
  'plugins/codex/src/hooks/session-start.ts',
];

const EXPECTED_INVENTORY_RESOLVER_FILES = [
  'packages/plugin-runtime/src/handle-session-start.ts',
  'plugins/antigravity/src/history/usage.ts',
  'plugins/claude-code/src/history/usage.ts',
  'plugins/codex/src/history/usage.ts',
];

describe('posture build identity reaches every inventory-pass caller', () => {
  it(
    'the session-pass file set is exactly the expected one',
    () => {
      const actual = shippedSource().filter((file) => SESSION_PASS_RE.test(read(file)));
      expect(actual.sort()).toEqual([...EXPECTED_SESSION_PASS_FILES].sort());
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'every session-pass caller spells the pluginBuild key it threads',
    () => {
      const missing = EXPECTED_SESSION_PASS_FILES.filter(
        (file) => !read(file).includes('pluginBuild:'),
      );
      expect(missing).toEqual([]);
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'the resolve-and-ensure file set is exactly the expected one',
    () => {
      const actual = shippedSource().filter((file) => {
        const text = read(file);
        return RESOLVES_RE.test(text) && ENSURES_RE.test(text);
      });
      expect(actual.sort()).toEqual([...EXPECTED_INVENTORY_RESOLVER_FILES].sort());
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'every resolve-and-ensure caller spells the pluginBuild key',
    () => {
      const missing = EXPECTED_INVENTORY_RESOLVER_FILES.filter(
        (file) => !read(file).includes('pluginBuild:'),
      );
      expect(missing).toEqual([]);
    },
    TREE_WALK_TIMEOUT_MS,
  );
});
