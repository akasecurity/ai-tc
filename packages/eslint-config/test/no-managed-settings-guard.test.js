import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  readPackageManifest,
  REPO_ROOT,
  toPosix,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';

// The administrative overlay is read from ABSOLUTE SYSTEM paths — outside
// `~/.aka` on purpose, so that a lock is not removable by the party being
// locked (packages/persistence/src/managed-settings.ts). A suite that builds a
// whole fake machine in a temp dir therefore still reads the REAL one: `base`
// redirects the home and reaches none of it.
//
// That made twenty-eight cases across three packages depend on who ran them. A
// developer laptop enrolled for dogfooding pins `runMode: attached`, so those
// cases assert `standalone` and receive `attached` on a clean checkout of main,
// while CI — which has no such file — stays green and reports nothing. An
// undeclared input that only fails off-CI is the worst shape a test dependency
// takes: the machines that can see it are the ones with no gate on them.
//
// `test/setup/no-managed-settings.ts` declares the answer once per test file,
// process-wide, exactly as the no-network guard does and for the same reason —
// the reads that fail sit several frames below the test, so no per-call
// override reaches them.
//
// What this file guards is the WIRING, and it derives which packages owe it
// rather than listing them. A package can only be affected if its dependency
// closure can load @akasecurity/persistence at all, so that closure IS the
// rule; a list would leave the next package to gain that edge silently
// unguarded, which is the drift this whole class of bug comes from.

const GUARD_REL = 'test/setup/no-managed-settings.ts';
const GUARD_ABS = join(REPO_ROOT, ...GUARD_REL.split('/'));
const SEAM = 'UNSAFE_TEST_ONLY_setManagedSettingsPaths';
const PERSISTENCE = '@akasecurity/persistence';

/**
 * Strip comments, so prose naming the guard is never mistaken for live wiring.
 * Every config edited here carries a comment that names it.
 * @param {string} source
 */
const stripComments = (source) =>
  source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

// Both halves matter: the entry proves the guard is wired into the run, and the
// URL is where a wrong `../..` depth would hide — a binding that resolves
// nowhere still reads as wiring.
const SETUP_ENTRY = /setupFiles\s*:\s*\[[^\]]*\bnoManagedSettingsGuard\b[^\]]*\]/;
const GUARD_URL = new RegExp(
  String.raw`new URL\(\s*'([^']*test/setup/no-managed-settings\.ts)'\s*,\s*import\.meta\.url\s*\)`,
);

/**
 * Every workspace package, by name, with its declared edges and test script.
 *
 * `workspacePackageDirs()` yields repo-RELATIVE dirs and `readPackageManifest`
 * joins the root itself, so each manifest is read once here and passed around
 * as data — re-deriving a path from it downstream is how this double-joined
 * the root on its first run.
 */
function workspaceByName() {
  /** @type {Map<string, {dir: string, deps: string[], testScript: string}>} */
  const byName = new Map();
  for (const dir of workspacePackageDirs()) {
    const pkg = readPackageManifest(dir);
    if (!pkg?.name) continue;
    byName.set(pkg.name, {
      dir: toPosix(dir),
      // devDependencies count. A test may import a package the product never
      // does — web-ui takes @akasecurity/plugin-sdk dev-only for fixture
      // seeding — and a test is exactly what this guard is about.
      deps: [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})],
      testScript: pkg.scripts?.test ?? '',
    });
  }
  return byName;
}

/**
 * Can this package's test process load @akasecurity/persistence at all?
 * @param {string} name
 * @param {Map<string, {dir: string, deps: string[]}>} byName
 */
function reachesPersistence(name, byName, seen = new Set()) {
  if (name === PERSISTENCE) return true;
  const entry = byName.get(name);
  if (!entry) return false; // outside the workspace: cannot re-enter it
  for (const dep of entry.deps) {
    if (dep === PERSISTENCE) return true;
    if (seen.has(dep)) continue;
    seen.add(dep);
    if (reachesPersistence(dep, byName, seen)) return true;
  }
  return false;
}

/** Every vitest package, tagged with whether it owes the guard and wires it. */
function auditPackages() {
  const byName = workspaceByName();
  return [...byName.entries()]
    .map(([name, { dir, testScript }]) => {
      const configAbs = join(REPO_ROOT, ...dir.split('/'), 'vitest.config.ts');
      const runsVitest = /(^|[\s/])vitest([\s/]|$)/.test(testScript);
      const owes = runsVitest && reachesPersistence(name, byName);
      if (!owes || !existsSync(configAbs)) {
        return { name, dir, owes, wired: false, resolved: null, hasConfig: false };
      }
      const source = stripComments(readFileSync(configAbs, 'utf8'));
      const url = GUARD_URL.exec(source);
      return {
        name,
        dir,
        owes,
        hasConfig: true,
        wired: SETUP_ENTRY.test(source),
        resolved: url ? resolve(REPO_ROOT, dir, url[1]) : null,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

const PACKAGES = auditPackages();
const OWING = PACKAGES.filter((p) => p.owes);

describe('the no-managed-settings guard', () => {
  it('exists, and installs the seam rather than merely importing it', () => {
    // A guard file that imports the seam and never calls it wires perfectly,
    // resolves perfectly, and neutralises nothing — every assertion below would
    // still pass while all twenty-eight cases went back to reading the
    // developer's own machine.
    expect(existsSync(GUARD_ABS)).toBe(true);
    const source = readFileSync(GUARD_ABS, 'utf8');
    expect(source).toMatch(new RegExp(String.raw`${SEAM}\(\s*\[\s*\]\s*\)`));
  });

  it('reaches the seam by module path, never through the package barrel', () => {
    // A setup file is loaded before EVERY test file in every package that wires
    // it, so whatever it imports sits in the module cache before any of them
    // registers a mock. Importing the BARREL pre-cached `paths.ts`,
    // `fingerprint.ts` and the vault bound to the real `node:fs`, so the three
    // suites that `vi.mock('node:fs')` and then `await import('../src/…')` got
    // the unmocked instance back and nineteen cases failed on a branch they
    // could no longer enter.
    //
    // Naming the one module keeps that graph to `managed-settings.ts`. Nothing
    // in the assertions elsewhere in this file would notice the barrel coming
    // back — the wiring, the depth and the install all stay correct — and the
    // damage lands in a different package's suite, on a mock, which reads as
    // anything but a setup-file import. Hence a case of its own.
    const source = readFileSync(GUARD_ABS, 'utf8');
    const specifiers = [...source.matchAll(/^\s*import\s[^;]*?from\s+'([^']+)'/gm)].map(
      (m) => m[1],
    );

    expect(specifiers).toEqual(['../../packages/persistence/src/managed-settings.ts']);
  });

  it('is owed by the packages that can actually load the overlay', () => {
    // The positive control on the derivation itself. An empty or near-empty
    // closure — a manifest reader returning nothing, a workspace glob that
    // matched no directory — makes every per-package assertion below hold
    // vacuously, and this suite would report green over an unwired workspace.
    const owed = OWING.map((p) => p.name);
    expect(owed).toContain(PERSISTENCE);
    expect(owed).toContain('@akasecurity/cli');
    expect(owed).toContain('@akasecurity/plugin-sdk');
    expect(owed).toContain('@akasecurity/web-ui');
    expect(owed.length).toBeGreaterThanOrEqual(10);
  });

  it('is not owed by a package that cannot reach the overlay', () => {
    // The other direction, and it is what keeps the rule a RULE rather than
    // "everything". A closure that answered true for every package would make
    // the case above pass just as well, while quietly demanding the guard in
    // tools/ and packages/schema — where the import would not even resolve.
    const exempt = PACKAGES.filter((p) => !p.owes).map((p) => p.name);
    expect(exempt).toContain('@akasecurity/schema');
    expect(exempt).toContain('@akasecurity/detections');
    expect(exempt).toContain('@akasecurity/portability-gate');
  });

  it('every owing package ships a vitest.config.ts', () => {
    expect(OWING.filter((p) => !p.hasConfig).map((p) => p.dir)).toEqual([]);
  });

  it('every owing package wires it into setupFiles', () => {
    expect(OWING.filter((p) => !p.wired).map((p) => p.dir)).toEqual([]);
  });

  it('every owing package points at a path that resolves to the guard', () => {
    // A relative depth is the half that fails silently: `../` from a package
    // two levels down resolves to a file that does not exist, and vitest is
    // what reports it — after the wiring has already read as correct here.
    const wrong = OWING.filter((p) => p.resolved !== GUARD_ABS).map((p) => ({
      dir: p.dir,
      resolved: p.resolved,
    }));
    expect(wrong).toEqual([]);
  });
});
