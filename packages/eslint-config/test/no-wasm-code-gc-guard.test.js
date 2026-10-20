import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  lintableTrackedFiles,
  readPackageManifest,
  REPO_ROOT,
  toPosix,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';

// On Node 24, V8 can abort a whole test process while freeing code after a
// worker thread is terminated. vitest then reports "Worker exited unexpectedly"
// and names no file. Two pieces answer it, and both are wired per package:
//
//   - `test/setup/no-wasm-code-gc.ts` turns wasm code GC off, the workaround the
//     upstream issue reports;
//   - `unfinishedModulesReporter()` from `test/vitest/unfinished-modules-reporter.ts`
//     names the file that was running when the process died.
//
// Neither fails loudly when it goes missing. Dropping the setup entry leaves the
// suite green until the abort recurs, and `setFlagsFromString` does not throw on
// a flag V8 does not know — it prints to stderr and carries on — so a renamed
// flag is a no-op that reads as wiring. This file holds both.
//
// Which packages owe them is derived, not listed: a package whose test process
// can terminate a worker. That is a package whose own tracked files call
// `.terminate()`, or whose dependency closure reaches a package whose `src/`
// does, since its tests then run that product code in-process.

const SETUP_REL = 'test/setup/no-wasm-code-gc.ts';
const SETUP_ABS = join(REPO_ROOT, ...SETUP_REL.split('/'));
const REPORTER_REL = 'test/vitest/unfinished-modules-reporter.ts';
const REPORTER_ABS = join(REPO_ROOT, ...REPORTER_REL.split('/'));

const TERMINATES = /\.terminate\(\)/;

/**
 * Strip comments, so prose naming the wiring is never mistaken for it.
 * @param {string} source
 */
const stripComments = (source) =>
  source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

const SETUP_ENTRY = /setupFiles\s*:\s*\[[^\]]*\bnoWasmCodeGc\b[^\]]*\]/;
const SETUP_URL = new RegExp(
  String.raw`new URL\(\s*'([^']*test/setup/no-wasm-code-gc\.ts)'\s*,\s*import\.meta\.url\s*\)`,
);
const PLUGIN_ENTRY = /plugins\s*:\s*\[[^\]]*\bunfinishedModulesReporter\(\)[^\]]*\]/;
const REPORTER_IMPORT =
  /import\s*\{[^}]*\bunfinishedModulesReporter\b[^}]*\}\s*from\s*'([^']*test\/vitest\/unfinished-modules-reporter\.ts)'/;

function auditPackages() {
  const tracked = lintableTrackedFiles().filter((f) => !f.includes('/dist/'));
  /** @type {Map<string, {dir: string, deps: string[], testScript: string}>} */
  const byName = new Map();
  for (const dir of workspacePackageDirs()) {
    const pkg = readPackageManifest(dir);
    if (!pkg?.name) continue;
    byName.set(pkg.name, {
      dir: toPosix(dir),
      deps: [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})],
      testScript: pkg.scripts?.test ?? '',
    });
  }

  /** @param {string} prefix */
  const anyTerminates = (prefix) =>
    tracked
      .filter((f) => f.startsWith(prefix))
      .some((f) => TERMINATES.test(readFileSync(join(REPO_ROOT, ...f.split('/')), 'utf8')));

  const productTerminates = new Set(
    [...byName].filter(([, { dir }]) => anyTerminates(`${dir}/src/`)).map(([name]) => name),
  );

  /** @param {string} name */
  const closureTerminates = (name, seen = new Set()) => {
    for (const dep of byName.get(name)?.deps ?? []) {
      if (productTerminates.has(dep)) return true;
      if (seen.has(dep)) continue;
      seen.add(dep);
      if (closureTerminates(dep, seen)) return true;
    }
    return false;
  };

  return [...byName.entries()]
    .map(([name, { dir, testScript }]) => {
      const runsVitest = /(^|[\s/])vitest([\s/]|$)/.test(testScript);
      const owes = runsVitest && (anyTerminates(`${dir}/`) || closureTerminates(name));
      const configAbs = join(REPO_ROOT, ...dir.split('/'), 'vitest.config.ts');
      if (!owes || !existsSync(configAbs)) {
        return { name, dir, owes, hasConfig: false, setup: null, reporter: null, reporters: false };
      }
      const source = stripComments(readFileSync(configAbs, 'utf8'));
      const setupUrl = SETUP_URL.exec(source);
      const reporterImport = REPORTER_IMPORT.exec(source);
      return {
        name,
        dir,
        owes,
        hasConfig: true,
        setup: SETUP_ENTRY.test(source) && setupUrl ? resolve(REPO_ROOT, dir, setupUrl[1]) : null,
        reporter:
          PLUGIN_ENTRY.test(source) && reporterImport
            ? resolve(REPO_ROOT, dir, reporterImport[1])
            : null,
        reporters: /\breporters\s*:/.test(source),
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

const PACKAGES = auditPackages();
const OWING = PACKAGES.filter((p) => p.owes);

describe('the no-wasm-code-gc workaround', () => {
  it('sets a flag this Node’s V8 recognises', () => {
    const source = stripComments(readFileSync(SETUP_ABS, 'utf8'));
    const call = /setFlagsFromString\(\s*'--(?:no-)?([a-z0-9-]+)'\s*\)/.exec(source);
    expect(call, `${SETUP_REL} no longer calls setFlagsFromString with a literal flag`).not.toBe(
      null,
    );

    const listed = spawnSync(process.execPath, ['--v8-options'], { encoding: 'utf8' });
    expect(listed.status).toBe(0);
    expect(listed.stdout).toMatch(new RegExp(String.raw`^\s*--${call[1]}\s`, 'm'));
  });

  it('stays gated to every Node line the repo pins', () => {
    // The flag is only set on the gated major, so moving `.nvmrc` or a
    // workflow's `node-version` past it would switch the workaround off with
    // every case here still green. Fail instead, until the gate is widened or
    // the file is deleted because the abort is fixed on the new line.
    const source = stripComments(readFileSync(SETUP_ABS, 'utf8'));
    const gate = /process\.versions\.node\.split\('\.'\)\[0\]\s*===\s*'(\d+)'/.exec(source);
    expect(gate, `${SETUP_REL} no longer gates on a literal Node major`).not.toBe(null);
    const gated = Number(gate[1]);

    const pins = [['.nvmrc', readFileSync(join(REPO_ROOT, '.nvmrc'), 'utf8')]];
    const workflows = join(REPO_ROOT, '.github', 'workflows');
    for (const name of readdirSync(workflows).filter((f) => /\.ya?ml$/.test(f))) {
      for (const m of readFileSync(join(workflows, name), 'utf8').matchAll(
        /node-version:\s*['"]?(\d+)/g,
      )) {
        pins.push([`.github/workflows/${name}`, m[1]]);
      }
    }
    expect(pins.length).toBeGreaterThan(1);
    for (const [where, value] of pins) {
      const major = Number(/\d+/.exec(value)?.[0]);
      expect(
        major,
        `${where} pins Node ${String(major)}, past the Node ${String(gated)} gate in ${SETUP_REL}`,
      ).toBeLessThanOrEqual(gated);
    }
  });

  it('is owed by the packages that terminate workers', () => {
    // The positive control on the derivation. An empty tracked-file list or a
    // regex that matches nothing makes every per-package case below vacuous.
    const owed = OWING.map((p) => p.name);
    expect(owed).toContain('@akasecurity/plugin-sdk');
    expect(owed).toContain('@akasecurity/local-ops');
    expect(owed).toContain('@akasecurity/ai-tc-claude-code');
    expect(owed).toContain('@akasecurity/ai-tc-codex');
    expect(owed).toContain('@akasecurity/plugin-browser-extension');
  });

  it('is not owed by a package that cannot terminate a worker', () => {
    const exempt = PACKAGES.filter((p) => !p.owes).map((p) => p.name);
    expect(exempt).toContain('@akasecurity/schema');
    expect(exempt).toContain('@akasecurity/ui-kit');
    expect(exempt).toContain('@akasecurity/remote');
  });

  it('every owing package ships a vitest.config.ts', () => {
    expect(OWING.filter((p) => !p.hasConfig).map((p) => p.dir)).toEqual([]);
  });

  it('every owing package wires the setup file at a path that resolves to it', () => {
    const wrong = OWING.filter((p) => p.setup !== SETUP_ABS).map((p) => ({
      dir: p.dir,
      resolved: p.setup,
    }));
    expect(wrong).toEqual([]);
  });

  it('every owing package adds the unfinished-modules reporter as a plugin', () => {
    // As a plugin, not a `reporters` entry: a `reporters` list replaces the
    // ones vitest adds by itself, `github-actions` among them.
    const wrong = OWING.filter((p) => p.reporter !== REPORTER_ABS || p.reporters).map((p) => ({
      dir: p.dir,
      resolved: p.reporter,
      replacesDefaults: p.reporters,
    }));
    expect(wrong).toEqual([]);
  });
});
