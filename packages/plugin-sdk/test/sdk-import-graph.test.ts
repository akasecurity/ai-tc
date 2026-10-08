import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { isBuiltin } from 'node:module';
import { dirname, join, relative, resolve, sep } from 'node:path';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

// The value symbols an SDK built on this package imports from its ROOT entry.
// That SDK is bundled for customer processes, so whatever these reach ships
// with it: a module that imports `node:sqlite` makes the bundle unloadable on a
// Node without the builtin, and carries store code into a process that never
// opens the store. Types are erased and reach nothing, so they are not listed.
const SDK_SYMBOLS = [
  'createPluginRuntime',
  'buildModelRefusalEvent',
  'isModelProhibited',
  'normalizeModelId',
  'prohibitedModelMessage',
  'bundledDetections',
  'ruleProbeKey',
  'maskMatch',
] as const;

const REPO_ROOT = resolve(import.meta.dirname, '../../..');
const SQLITE_SPECIFIERS = new Set(['node:sqlite', 'sqlite']);

// A static walk rather than a bundle: no bundler is a dependency of this
// package. It models what one keeps, at MODULE granularity, from the
// manifests themselves — so it can only over-report:
//   - a package whose manifest does not declare `sideEffects: false` keeps
//     every module the walk touches, with every import that module makes,
//     because a bundler must assume loading it does something;
//   - a side-effect-free one keeps a module only when a name somebody uses is
//     defined in it or re-exported through it.
// A kept module keeps ALL of its value imports, with no statement-level
// dead-code removal, so an edge a bundler would prune still counts here.
// `import type` and type-only specifiers are erased. Under
// `verbatimModuleSyntax`, `import { type A } from 'x'` still loads `x`, so
// that form is an edge with no names.

interface Manifest {
  dir: string;
  exports: Record<string, string>;
  sideEffects: unknown;
}

const manifests = new Map<string, Manifest>();
for (const root of ['packages', 'plugins']) {
  for (const name of readdirSync(join(REPO_ROOT, root))) {
    const file = join(REPO_ROOT, root, name, 'package.json');
    if (!existsSync(file)) continue;
    const pkg = JSON.parse(readFileSync(file, 'utf8')) as {
      name: string;
      exports?: Record<string, string>;
      sideEffects?: unknown;
    };
    manifests.set(pkg.name, {
      dir: dirname(file),
      exports: pkg.exports ?? {},
      sideEffects: pkg.sideEffects,
    });
  }
}

function manifestOf(file: string): Manifest | undefined {
  for (const m of manifests.values()) if (file.startsWith(m.dir + sep)) return m;
  return undefined;
}

function isSideEffectFree(file: string): boolean {
  const m = manifestOf(file);
  if (m === undefined) return false;
  if (m.sideEffects === false) return true;
  if (Array.isArray(m.sideEffects)) {
    const own = `./${relative(m.dir, file).split(sep).join('/')}`;
    return !m.sideEffects.includes(own);
  }
  return false;
}

type Target =
  | { kind: 'module'; file: string }
  | { kind: 'leaf'; file: string }
  | { kind: 'external'; specifier: string };

function resolveSpecifier(from: string, specifier: string): Target {
  if (specifier.startsWith('.')) {
    const file = resolve(dirname(from), specifier);
    if (!existsSync(file)) throw new Error(`${from}: unresolved ${specifier}`);
    return file.endsWith('.ts') ? { kind: 'module', file } : { kind: 'leaf', file };
  }
  if (isBuiltin(specifier)) return { kind: 'external', specifier };
  const scoped = /^(@akasecurity\/[^/]+)(\/.*)?$/.exec(specifier);
  const m = scoped ? manifests.get(scoped[1] ?? '') : undefined;
  if (scoped === null || m === undefined) return { kind: 'external', specifier };
  const subpath = `.${scoped[2] ?? ''}`;
  const target = m.exports[subpath];
  if (target === undefined) throw new Error(`${from}: ${specifier} is not exported`);
  return { kind: 'module', file: resolve(m.dir, target) };
}

type Names = Set<string> | 'all';

interface ModuleFacts {
  imports: { specifier: string; names: Names }[];
  reexports: { specifier: string; pairs: { exported: string; local: string }[] }[];
  stars: { specifier: string; as?: string }[];
  localExports: Set<string>;
  // Files that hand 'node:sqlite' to a call — a builtin resolved at call time,
  // which no import graph shows and no bundler follows.
  lazySqlite: boolean;
}

const factsCache = new Map<string, ModuleFacts>();

function factsOf(file: string): ModuleFacts {
  const cached = factsCache.get(file);
  if (cached) return cached;
  const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest);
  const facts: ModuleFacts = {
    imports: [],
    reexports: [],
    stars: [],
    localExports: new Set(),
    lazySqlite: false,
  };
  for (const s of source.statements) {
    if (ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier)) {
      const clause = s.importClause;
      if (clause?.phaseModifier === ts.SyntaxKind.TypeKeyword) continue;
      const specifier = s.moduleSpecifier.text;
      if (clause === undefined) {
        facts.imports.push({ specifier, names: new Set() });
        continue;
      }
      const bindings = clause.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) {
        facts.imports.push({ specifier, names: 'all' });
        continue;
      }
      const names = new Set<string>();
      if (clause.name) names.add('default');
      if (bindings && ts.isNamedImports(bindings)) {
        for (const el of bindings.elements) {
          if (!el.isTypeOnly) names.add((el.propertyName ?? el.name).text);
        }
      }
      facts.imports.push({ specifier, names });
    } else if (ts.isExportDeclaration(s)) {
      if (s.isTypeOnly) continue;
      if (s.moduleSpecifier === undefined || !ts.isStringLiteral(s.moduleSpecifier)) {
        if (s.exportClause && ts.isNamedExports(s.exportClause)) {
          for (const el of s.exportClause.elements) facts.localExports.add(el.name.text);
        }
        continue;
      }
      const specifier = s.moduleSpecifier.text;
      if (s.exportClause === undefined) {
        facts.stars.push({ specifier });
      } else if (ts.isNamespaceExport(s.exportClause)) {
        facts.stars.push({ specifier, as: s.exportClause.name.text });
      } else {
        const pairs = s.exportClause.elements
          .filter((el) => !el.isTypeOnly)
          .map((el) => ({ exported: el.name.text, local: (el.propertyName ?? el.name).text }));
        facts.reexports.push({ specifier, pairs });
      }
    } else if (ts.isExportAssignment(s)) {
      facts.localExports.add('default');
    } else if (
      ts.canHaveModifiers(s) &&
      ts.getModifiers(s)?.some((mod) => mod.kind === ts.SyntaxKind.ExportKeyword)
    ) {
      if (ts.isVariableStatement(s)) {
        for (const d of s.declarationList.declarations) {
          if (ts.isIdentifier(d.name)) facts.localExports.add(d.name.text);
        }
      } else if (
        (ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s) || ts.isEnumDeclaration(s)) &&
        s.name
      ) {
        facts.localExports.add(s.name.text);
      }
    }
  }
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const [first] = node.arguments;
      if (first && ts.isStringLiteralLike(first)) {
        const isImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
        const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
        if (isImport || isRequire) facts.imports.push({ specifier: first.text, names: 'all' });
        else if (SQLITE_SPECIFIERS.has(first.text)) facts.lazySqlite = true;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  factsCache.set(file, facts);
  return facts;
}

const exportedCache = new Map<string, Set<string>>();

/** Every value name a module exports, through `export *` chains. */
function exportedNames(file: string): Set<string> {
  const cached = exportedCache.get(file);
  if (cached) return cached;
  const names = new Set<string>();
  exportedCache.set(file, names);
  const facts = factsOf(file);
  for (const n of facts.localExports) names.add(n);
  for (const r of facts.reexports) for (const p of r.pairs) names.add(p.exported);
  for (const star of facts.stars) {
    if (star.as !== undefined) {
      names.add(star.as);
      continue;
    }
    const target = resolveSpecifier(file, star.specifier);
    if (target.kind !== 'module') continue;
    for (const n of exportedNames(target.file)) if (n !== 'default') names.add(n);
  }
  return names;
}

interface Reach {
  modules: Set<string>;
  externals: Map<string, Set<string>>;
}

function reach(symbols: readonly string[]): Reach {
  const entry = resolveSpecifier(join(REPO_ROOT, 'entry.ts'), '@akasecurity/plugin-sdk');
  if (entry.kind !== 'module') throw new Error('plugin-sdk root did not resolve to a module');
  const kept = new Map<string, Names>();
  const externals = new Map<string, Set<string>>();
  const queue: [string, Names][] = [[entry.file, new Set(symbols)]];

  const follow = (from: string, specifier: string, names: Names): void => {
    const target = resolveSpecifier(from, specifier);
    if (target.kind === 'external') {
      const importers = externals.get(target.specifier) ?? new Set<string>();
      importers.add(rel(from));
      externals.set(target.specifier, importers);
      return;
    }
    if (target.kind === 'leaf') return;
    const named = names === 'all' || names.size > 0;
    if (!named && isSideEffectFree(target.file)) return;
    queue.push([target.file, names]);
  };

  for (let next = queue.shift(); next; next = queue.shift()) {
    const [file, incoming] = next;
    const requested: Names = isSideEffectFree(file) ? incoming : 'all';
    const prior = kept.get(file);
    let merged: Names;
    if (prior === 'all' || requested === 'all') merged = 'all';
    else merged = new Set([...(prior ?? []), ...requested]);
    const grew =
      prior === undefined || (prior !== 'all' && (merged === 'all' || merged.size > prior.size));
    if (!grew) continue;
    kept.set(file, merged);

    const wants = (name: string): boolean => merged === 'all' || merged.has(name);
    const facts = factsOf(file);
    for (const imp of facts.imports) follow(file, imp.specifier, imp.names);
    for (const r of facts.reexports) {
      const used = r.pairs.filter((p) => wants(p.exported)).map((p) => p.local);
      follow(file, r.specifier, new Set(used));
    }
    for (const star of facts.stars) {
      if (star.as !== undefined) {
        follow(file, star.specifier, wants(star.as) ? 'all' : new Set());
        continue;
      }
      const target = resolveSpecifier(file, star.specifier);
      if (target.kind !== 'module') {
        follow(file, star.specifier, new Set());
        continue;
      }
      const offered = exportedNames(target.file);
      const used = merged === 'all' ? 'all' : new Set([...merged].filter((n) => offered.has(n)));
      follow(file, star.specifier, used);
    }
  }
  return { modules: new Set([...kept.keys()].map(rel)), externals };
}

function rel(file: string): string {
  return relative(REPO_ROOT, file).split(sep).join('/');
}

function sqliteImporters(r: Reach): string[] {
  return [...SQLITE_SPECIFIERS].flatMap((s) => [...(r.externals.get(s) ?? [])]).sort();
}

describe("the SDK's value imports from the root entry", () => {
  const sdk = reach(SDK_SYMBOLS);

  it('are all still exported there, so none drops out of the walk unnoticed', () => {
    const root = resolveSpecifier(join(REPO_ROOT, 'entry.ts'), '@akasecurity/plugin-sdk');
    if (root.kind !== 'module') throw new Error('plugin-sdk root did not resolve to a module');
    const offered = exportedNames(root.file);
    expect(SDK_SYMBOLS.filter((s) => !offered.has(s))).toEqual([]);
  });

  it('reach no module that imports node:sqlite', () => {
    expect(sqliteImporters(sdk)).toEqual([]);
  });

  it("never load persistence's root entry or its database module", () => {
    // The root entry re-exports the whole store layer, and a package that is
    // not side-effect-free keeps everything it re-exports. One import of it
    // brings `database.ts` back, whichever symbol was asked for.
    const persistenceRoot = [
      'packages/persistence/src/index.ts',
      'packages/persistence/src/database.ts',
    ].filter((f) => sdk.modules.has(f));
    expect(persistenceRoot).toEqual([]);
  });

  it('resolve node:sqlite at call time in exactly one place: the fingerprint floor read', () => {
    // `storedKeyVersionFloor` opens an EXISTING store read-only when a key is
    // minted. It asks for the builtin when it runs, so loading the runtime does
    // not, and a second site doing the same would be invisible to the checks
    // above — so the set is pinned rather than allowed to grow.
    const lazy = [...sdk.modules].filter((f) => factsOf(resolve(REPO_ROOT, f)).lazySqlite);
    expect(lazy).toEqual(['packages/persistence/src/fingerprint.ts']);
  });

  it('still reach persistence, so the checks above are not describing an empty graph', () => {
    expect(sdk.modules).toContain('packages/plugin-sdk/src/runtime.ts');
    expect(sdk.modules).toContain('packages/persistence/src/fingerprint.ts');
    expect(sdk.externals.has('node:crypto')).toBe(true);
  });
});

describe('the walk itself', () => {
  it('sees node:sqlite when a symbol really needs the store', () => {
    // The vault glue opens the local database, so its graph MUST import the
    // builtin. If this goes quiet, the walk has stopped seeing the thing the
    // cases above assert is absent.
    const vault = reach(['createVaultGlue']);
    expect(sqliteImporters(vault)).toContain('packages/persistence/src/database.ts');
  });
});
