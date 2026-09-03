import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  readPackageManifest,
  REPO_ROOT,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';

// The vitest hook/test ceilings, pinned as an EXACT map.
//
// These are not a comfort setting. A store suite with per-test isolation used to
// migrate a whole SQLite schema in `beforeEach`, and on the Windows leg that ran
// 1–4 s per test against a 20 s ceiling — so the leg failed on a hook timeout in
// a different package almost every run, never in the package the PR touched. The
// fix applied to it the first time was raising this number from vitest's 10 s
// default to 20 s, which moved the threshold rather than removing the cost; the
// failure then spread from one package to four.
//
// So the number is the thing to hold still while the cost comes down. A raise
// here is the change that must not pass unnoticed — it buys a green run today
// and hides the next regression in setup cost, which is how this arrived. It is
// pinned in BOTH directions rather than as a ceiling: a lowering is a good
// change (the setup cost is now a file copy, so there is headroom to give back)
// but it is a deliberate one, and a ratchet that only forbids raises would let
// a package be lowered into flakiness with nothing to say so.
//
// This lives in @akasecurity/eslint-config for the reason coverage-config.test.js
// does: only this package's turbo `inputs` cover the whole workspace, so only a
// suite here re-runs when a DIFFERENT package edits its config. The same check
// inside each package would be the one guard that cannot see the edit it exists
// to catch.
//
// A package absent from this map must declare NEITHER timeout — it runs on
// vitest's own defaults, which is the cheapest thing to be true.
const TIMEOUTS = {
  '@akasecurity/cli': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/detections': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/local-ops': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/persistence': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/plugin-runtime': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/plugin-sdk': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/scanner': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/ai-tc-antigravity': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/ai-tc-copilot': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/plugin-browser-extension': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/ai-tc-claude-code': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/ai-tc-codex': { testTimeout: 20_000, hookTimeout: 20_000 },
  '@akasecurity/web-ui': { testTimeout: 20_000, hookTimeout: 20_000 },
  // The installer suite drives the real `install.sh`/`install.ps1` end to end
  // against a loopback fixture release — a genuinely long operation, and not a
  // per-test store setup at all.
  '@akasecurity/installer': { testTimeout: 120_000, hookTimeout: 120_000 },
};

/**
 * A timeout as the config declares it. Read from the TEXT rather than by
 * importing the config: importing executes it, plugins and all, and the value
 * this pins is a literal in the file either way. Both spellings the workspace
 * uses are accepted — `20_000` and `20000` are the same number, and a ratchet
 * that saw only one of them would report every package using the other as
 * undeclared.
 */
function declaredTimeout(configText, key) {
  const match = new RegExp(`^\\s*${key}:\\s*([0-9_]+)\\s*,`, 'm').exec(configText);
  return match ? Number(match[1].replaceAll('_', '')) : undefined;
}

/** A package's npm scripts, or an empty set when it declares none. */
function scriptsFor(dir) {
  return readPackageManifest(dir).scripts ?? {};
}

const PACKAGES = workspacePackageDirs()
  .map((dir) => ({ dir, name: readPackageManifest(dir).name }))
  .filter(({ dir }) => existsSync(join(REPO_ROOT, dir, 'vitest.config.ts')))
  .map((pkg) => {
    const text = readFileSync(join(REPO_ROOT, pkg.dir, 'vitest.config.ts'), 'utf8');
    return {
      ...pkg,
      testTimeout: declaredTimeout(text, 'testTimeout'),
      hookTimeout: declaredTimeout(text, 'hookTimeout'),
    };
  });

describe('vitest timeout ratchet', () => {
  it('raises no timeout through a test script instead of the config', () => {
    // The pin below reads config LITERALS, so a package that passed
    // `--hookTimeout=60000` on its `vitest` command line would clear every
    // assertion here while the ceiling this exists to hold had been raised.
    // No package does that today; the guard is what keeps it that way, since
    // the flag is the obvious next move for anyone hitting the timeout again.
    const viaFlag = workspacePackageDirs()
      .map((dir) => ({ name: readPackageManifest(dir).name, script: scriptsFor(dir).test ?? '' }))
      .filter(({ script }) => /--(test|hook)Timeout\b/.test(script))
      .map(({ name }) => name);
    expect(viaFlag).toEqual([]);
  });

  it('declares exactly the pinned timeouts, in both directions', () => {
    const declared = Object.fromEntries(
      PACKAGES.filter((p) => p.testTimeout !== undefined || p.hookTimeout !== undefined).map(
        (p) => [p.name, { testTimeout: p.testTimeout, hookTimeout: p.hookTimeout }],
      ),
    );
    // One comparison over the whole map, not a per-package assertion: a package
    // that ADDS a timeout is the same defect as one that raises an existing
    // one, and only an exact set catches both.
    expect(declared).toEqual(TIMEOUTS);
  });

  it('is not a table of vitest defaults', () => {
    // A positive control. Every assertion above would hold with the map emptied
    // and every config's timeouts deleted, which is a different repo from this
    // one — so the pin has to be shown to be pinning something.
    expect(Object.keys(TIMEOUTS).length).toBeGreaterThan(5);
    for (const [name, pinned] of Object.entries(TIMEOUTS)) {
      expect(pinned.hookTimeout, name).toBeGreaterThan(0);
    }
  });
});
