import { existsSync, globSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ESLint, Linter } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

// These tests exercise the ASSEMBLED per-package configs on disk — not the
// exported building blocks (base / noEnterpriseImports / the helpers) that
// no-network.test.js covers in isolation. Flat config resolves "last wins":
// the final block matching a file overrides earlier ones for a given rule, and
// no-restricted-imports never merges across blocks. So a package that layers a
// second config on top of base (web-ui: react + noEnterpriseImports; persistence
// / local-ops: base + noEnterpriseImports; cli: base + the dashboard opt-out)
// could silently drop a network ban with the unit suite still green. Here we
// resolve each real eslint.config.mjs through ESLint itself and assert the ban
// still fires on real code — the composition, not the components.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

const KEYS = /** @type {const} */ ([
  'no-restricted-globals',
  'no-restricted-properties',
  'no-restricted-imports',
  'no-restricted-syntax',
]);

// One snippet that must trip all four network rules at once: a banned import, a
// bare global, a dynamic import, and the container-global member bypass.
const NETWORK_SNIPPET = [
  "import x from 'axios';",
  "fetch('/x');",
  "await import('undici');",
  'globalThis.fetch();',
].join('\n');

const linter = new Linter();
const LANG = { ecmaVersion: 'latest', sourceType: 'module' };

// Every workspace glob from pnpm-workspace.yaml that can hold a package config.
// Discovering them (rather than hard-coding a list) means a NEW package that
// forgets to extend `base` fails this suite instead of slipping through
// unlinted for network calls.
const CONFIG_FILES = [
  ...globSync('packages/*/eslint.config.mjs', { cwd: REPO_ROOT }),
  ...globSync('plugins/*/eslint.config.mjs', { cwd: REPO_ROOT }),
  ...globSync('tools/*/eslint.config.mjs', { cwd: REPO_ROOT }),
  ...['cli/eslint.config.mjs', 'web-ui/eslint.config.mjs'].filter((p) =>
    existsSync(join(REPO_ROOT, p)),
  ),
].sort();

// Resolving a real config through ESLint (`new ESLint` + `calculateConfigForFile`)
// is slow on a cold runner: the first call loads the whole typescript-eslint +
// plugin stack and, for a large package like cli, can take several seconds —
// past a default per-test timeout. So every resolution happens in a `beforeAll`
// with a generous budget, and the tests themselves are fast assertions on the
// cached result.
const RESOLVE_TIMEOUT_MS = 120_000;

/**
 * Resolve the effective config a package's real eslint.config.mjs produces for
 * `relFile`, and return just the four network rules from it. calculateConfigForFile
 * runs the full flat-config cascade without parsing the file, so it needs no
 * type information and the probe path need not exist.
 * @param {string} pkgDir absolute package directory
 * @param {string} relFile path within the package to resolve config for
 */
async function resolveNetworkRules(pkgDir, relFile) {
  const eslint = new ESLint({ cwd: pkgDir, overrideConfigFile: join(pkgDir, 'eslint.config.mjs') });
  const config = await eslint.calculateConfigForFile(join(pkgDir, relFile));
  return Object.fromEntries(KEYS.map((k) => [k, config.rules?.[k]]));
}

/** Which network rule ids fire when `code` is linted with `rules`. */
function firedRuleIds(code, rules) {
  return new Set(linter.verify(code, { languageOptions: LANG, rules }).map((m) => m.ruleId));
}

describe('effective per-package config (composition / last-wins)', () => {
  /** @type {Map<string, Set<string>>} configRel -> rule ids the snippet trips */
  const firedByConfig = new Map();

  beforeAll(async () => {
    for (const configRel of CONFIG_FILES) {
      const pkgDir = join(REPO_ROOT, dirname(configRel));
      // A source path base applies to; it need not exist (config is computed,
      // not parsed). Avoids each package's real layout while still hitting base.
      const rules = await resolveNetworkRules(pkgDir, 'src/__network_ban_probe__.ts');
      firedByConfig.set(configRel, firedRuleIds(NETWORK_SNIPPET, rules));
    }
  }, RESOLVE_TIMEOUT_MS);

  it('discovered the workspace package configs (guard against a vacuous pass)', () => {
    // A broken glob would leave it.each empty and every enforcement test would
    // silently not run. Pin the floor: 11 packages ship an eslint.config.mjs
    // today (all of packages/* except eslint-config, plus cli, web-ui, plugin).
    expect(CONFIG_FILES.length).toBeGreaterThanOrEqual(11);
  });

  it.each(CONFIG_FILES)('bans every network form in %s', (configRel) => {
    const fired = firedByConfig.get(configRel);
    for (const key of KEYS) {
      expect(fired, `${configRel} :: ${key}`).toContain(key);
    }
  });
});

describe('cli dashboard.ts file-scoped opt-out (real config)', () => {
  const cliDir = join(REPO_ROOT, 'cli');
  // Resolved network rules for two cli files, populated in beforeAll (see the
  // RESOLVE_TIMEOUT_MS note): dashboard.ts carries the node:net opt-out, the
  // other file must not.
  const resolved = { dashboard: undefined, otherFile: undefined };

  beforeAll(async () => {
    resolved.dashboard = await resolveNetworkRules(cliDir, 'src/commands/dashboard.ts');
    resolved.otherFile = await resolveNetworkRules(cliDir, 'src/lib/open-url.ts');
  }, RESOLVE_TIMEOUT_MS);

  it('allows node:net in dashboard.ts (the 127.0.0.1 bind probe)', () => {
    expect(firedRuleIds("import { createServer } from 'node:net';", resolved.dashboard).size).toBe(
      0,
    );
    // Symmetric: the dynamic form is opted out too.
    expect(firedRuleIds("await import('node:net');", resolved.dashboard).size).toBe(0);
  });

  it('still bans every OTHER network module in dashboard.ts', () => {
    expect(firedRuleIds("import http from 'node:http';", resolved.dashboard)).toContain(
      'no-restricted-imports',
    );
    expect(firedRuleIds("fetch('/x');", resolved.dashboard)).toContain('no-restricted-globals');
  });

  it('does NOT leak the node:net opt-out to other cli files', () => {
    expect(firedRuleIds("import { createServer } from 'node:net';", resolved.otherFile)).toContain(
      'no-restricted-imports',
    );
  });
});
