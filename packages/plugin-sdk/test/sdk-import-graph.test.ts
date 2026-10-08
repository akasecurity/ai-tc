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
// What it cannot read it refuses rather than guesses: a `sideEffects` entry
// that is not one literal path, and an `@akasecurity/*` package with no
// manifest, both throw; a load whose name it cannot read is pinned below.
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
  return m !== undefined && sideEffectFreeUnder(m, file);
}

// Bundlers read each `sideEffects` entry as a GLOB, and one with no `/` as
// `**/<entry>`. This walk compares paths, so it accepts only an entry that is
// one literal `./` path and refuses anything else: a glob compared as a
// literal matches nothing, which turns "these keep their effects" into
// "nothing does" — the one direction this walk must never err in.
const LITERAL_ENTRY = /^\.\/[^*?[\]{}()!\\]+$/;

function sideEffectFreeUnder(m: Manifest, file: string): boolean {
  if (m.sideEffects === false) return true;
  if (!Array.isArray(m.sideEffects)) return false;
  for (const entry of m.sideEffects as unknown[]) {
    if (typeof entry !== 'string' || !LITERAL_ENTRY.test(entry)) {
      throw new Error(
        `${m.dir}: sideEffects entry ${JSON.stringify(entry)} is not one literal ./ path`,
      );
    }
  }
  const own = `./${relative(m.dir, file).split(sep).join('/')}`;
  return !m.sideEffects.includes(own);
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
  if (scoped === null) return { kind: 'external', specifier };
  // Read as external, a package of ours would be a leaf whose imports nobody
  // walks — the under-report this walk exists to rule out.
  const m = manifests.get(scoped[1] ?? '');
  if (m === undefined) throw new Error(`${from}: ${specifier} has no workspace manifest`);
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
  // Calls that load a module whose name the walk cannot read: a loader given a
  // non-literal argument, or a `require` minted by `createRequire`, whose later
  // calls no binding-blind reader can follow.
  opaqueLoads: string[];
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  return name.elements.flatMap((el) => (ts.isOmittedExpression(el) ? [] : bindingNames(el.name)));
}

function calleeName(call: ts.CallExpression): string | undefined {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) return callee.text;
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text;
  return undefined;
}

const LOADERS = new Set(['require', 'getBuiltinModule']);

const factsCache = new Map<string, ModuleFacts>();

function factsOf(file: string): ModuleFacts {
  const cached = factsCache.get(file);
  if (cached) return cached;
  const facts = readFacts(file, readFileSync(file, 'utf8'));
  factsCache.set(file, facts);
  return facts;
}

function readFacts(file: string, text: string): ModuleFacts {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest);
  const facts: ModuleFacts = {
    imports: [],
    reexports: [],
    stars: [],
    localExports: new Set(),
    lazySqlite: false,
    opaqueLoads: [],
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
          for (const n of bindingNames(d.name)) facts.localExports.add(n);
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
      const isImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
      const name = calleeName(node);
      if (first && ts.isStringLiteralLike(first)) {
        if (isImport || isRequire) facts.imports.push({ specifier: first.text, names: 'all' });
        else if (SQLITE_SPECIFIERS.has(first.text)) facts.lazySqlite = true;
      } else if (isImport || (name !== undefined && LOADERS.has(name))) {
        facts.opaqueLoads.push(node.getText(source));
      }
      if (name === 'createRequire') facts.opaqueLoads.push(node.getText(source));
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return facts;
}

const exportedCache = new Map<string, Set<string>>();

/**
 * Every value name a module exports, through `export *` chains.
 *
 * Each call walks the star graph from its own module and caches only the
 * finished set. A memo filled while recursing would hand a module met inside
 * a star cycle the partial set its caller had so far, and cache that.
 */
function exportedNames(file: string): Set<string> {
  const cached = exportedCache.get(file);
  if (cached) return cached;
  const names = new Set<string>();
  const seen = new Set<string>();
  const collect = (current: string): void => {
    if (seen.has(current)) return;
    seen.add(current);
    // `export *` never forwards a default, so only the module asked about
    // contributes one.
    const add = (n: string): void => {
      if (current === file || n !== 'default') names.add(n);
    };
    const facts = factsOf(current);
    for (const n of facts.localExports) add(n);
    for (const r of facts.reexports) for (const p of r.pairs) add(p.exported);
    for (const star of facts.stars) {
      if (star.as !== undefined) {
        add(star.as);
        continue;
      }
      const target = resolveSpecifier(current, star.specifier);
      if (target.kind === 'module') collect(target.file);
    }
  };
  collect(file);
  exportedCache.set(file, names);
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

  it('load no module at call time through a name the walk cannot read', () => {
    // The pin above sees only a literal 'node:sqlite'. A loader handed a
    // computed name, or a `require` minted by `createRequire`, can load the
    // builtin with neither an import edge nor that literal, so the checks
    // above would stay green. None is reachable today, and one that arrives
    // has to be read and justified here rather than slip past them.
    const opaque = [...sdk.modules].flatMap((f) =>
      factsOf(resolve(REPO_ROOT, f)).opaqueLoads.map((call) => `${f}: ${call}`),
    );
    expect(opaque).toEqual([]);
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

  it('refuses a sideEffects entry it cannot read as one literal path', () => {
    // Bundlers read each entry as a glob, and one with no `/` as `**/<entry>`.
    // Compared as a literal, `./src/*.ts` matches no file, so every module
    // would read as side-effect-free while a bundler keeps them all.
    const dir = join(REPO_ROOT, 'pkg');
    const file = join(dir, 'src', 'a.ts');
    for (const entry of ['./src/*.ts', 'a.ts', 'src/a.ts', './src/{a,b}.ts', './src/[ab].ts']) {
      const m: Manifest = { dir, exports: {}, sideEffects: [entry] };
      expect(() => sideEffectFreeUnder(m, file), entry).toThrow(/not one literal/);
    }
    const literal: Manifest = { dir, exports: {}, sideEffects: ['./src/a.ts'] };
    expect(sideEffectFreeUnder(literal, file)).toBe(false);
    expect(sideEffectFreeUnder(literal, join(dir, 'src', 'b.ts'))).toBe(true);
  });

  it('refuses an @akasecurity package it has no manifest for', () => {
    // Read as external, the walk would never see what that package imports.
    expect(() =>
      resolveSpecifier(join(REPO_ROOT, 'entry.ts'), '@akasecurity/no-such-package'),
    ).toThrow(/no workspace manifest/);
  });

  it('reads every name a destructured export binds', () => {
    const facts = readFacts('m.ts', 'export const { a, b: [c, , ...d], e = 1, ...f } = source;');
    expect([...facts.localExports].sort()).toEqual(['a', 'c', 'd', 'e', 'f']);
  });

  it('gives every module in a star-export cycle its whole export set', () => {
    const at = (name: string): string =>
      resolve(import.meta.dirname, 'helpers/import-graph', `star-cycle-${name}.ts`);
    // Asking for a first is what used to leave b cached mid-cycle, before a
    // had reached c.
    expect([...exportedNames(at('a'))].sort()).toEqual(['fromB', 'fromC']);
    expect([...exportedNames(at('b'))].sort()).toEqual(['fromB', 'fromC']);
  });

  it('records a loader whose specifier it cannot read', () => {
    const opaque = (text: string): string[] => readFacts('m.ts', text).opaqueLoads;
    expect(opaque("const ID = 'node:sqlite'; process.getBuiltinModule(ID);")).toHaveLength(1);
    expect(opaque('await import(url);')).toHaveLength(1);
    expect(opaque('require(name);')).toHaveLength(1);
    expect(opaque('module.require(name);')).toHaveLength(1);
    expect(opaque('createRequire(import.meta.url);')).toHaveLength(1);
    // A literal specifier is an edge the walk follows, not an opaque load.
    expect(opaque("await import('./x.ts'); process.getBuiltinModule('node:fs');")).toEqual([]);
  });
});
