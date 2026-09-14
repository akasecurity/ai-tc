import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import ts from 'typescript';

/**
 * What a suite's teardown removes, read from its source with the TypeScript
 * parser rather than with a regular expression.
 *
 * WHY A PARSER. The first version of the temp-home guard matched
 * `rmSync(… recursive: true …)` as text inside an `afterEach` body, and that
 * text match had three blind spots, each of which the tree was already using:
 *
 * - A removal through a HELPER. `removeTree(home)` from the shared
 *   `test/helpers/remove-tree.ts` is not the text `rmSync`, and it was the
 *   dominant teardown shape — sixteen suites removed their home that way, and
 *   the guard saw none of them.
 * - A removal in `afterAll`. The handle `app/lib/db.ts` holds is just as open
 *   there, and the guard only read `afterEach`.
 * - A removal whose path is built by a call. `[^)]*` stops at the first `)`, so
 *   `rmSync(join(home, 'x'), { recursive: true })` ends the match inside
 *   `join(…)` and never reaches the options.
 *
 * WHAT IT SEES. A tree removal is a call to `removeTree` or `removeTrees`, or a
 * call to `rm`/`rmSync`/`rmdir`/`rmdirSync` — on any receiver, so `fs.rmSync`
 * too — whose options say `recursive`, or cannot be proven not to (an options
 * object built elsewhere, or spread into). From each `afterEach`/`afterAll` it
 * follows calls to functions declared in the same file, and to functions
 * imported by name from a relative path, transitively and without looping.
 * Callbacks passed as arguments count, since they are how a loop over several
 * directories is usually written; a function merely declared inside a hook and
 * never called does not.
 *
 * WHAT IT DOES NOT SEE, stated so nobody reads more into a green result: a call
 * through an object (`helpers.cleanup()`), a re-export (`export { a as b }`), a
 * default import, a dynamic import, and anything computed at run time. A suite
 * that hides a removal behind one of those passes. The sanctioned teardown —
 * `tempHomes()` — needs none of them, which is the practical answer.
 */

export type TeardownHook = 'afterEach' | 'afterAll';

export interface TreeRemoval {
  hook: TeardownHook;
  /** 1-based line of the hook call in the suite. */
  line: number;
  /** The call chain from the hook to the removal, e.g. `afterEach → cleanup → removeTree`. */
  path: string;
}

export interface TeardownScan {
  /** The suite points `homedir()` somewhere else — the precondition for the bug. */
  redirectsHome: boolean;
  /** How many teardown hooks the parse found, so an empty result can be told from a blind one. */
  hooks: number;
  removals: TreeRemoval[];
}

/** Where source text comes from. The disk by default; a map in the detector's own suite. */
export interface SourceHost {
  read(path: string): string | undefined;
}

const diskHost: SourceHost = {
  read(path) {
    try {
      return readFileSync(path, 'utf8');
    } catch {
      return undefined;
    }
  },
};

const HOOKS: ReadonlySet<string> = new Set<TeardownHook>(['afterEach', 'afterAll']);
/** Shared helpers that remove a tree by definition, whatever their arguments. */
const TREE_REMOVERS: ReadonlySet<string> = new Set(['removeTree', 'removeTrees']);
/** node:fs removals, which remove a tree only when told to. */
const FS_REMOVERS: ReadonlySet<string> = new Set(['rm', 'rmSync', 'rmdir', 'rmdirSync']);

type FunctionNode = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction;

interface Module {
  path: string;
  source: ts.SourceFile;
  /** Every function declared in the file, at any depth, by the name it is called with. */
  functions: Map<string, FunctionNode[]>;
  /** Named imports from relative specifiers: local name → where it comes from. */
  imports: Map<string, { specifier: string; exported: string }>;
}

function parse(path: string, text: string): ts.SourceFile {
  const kind = path.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  return ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind);
}

function isFunctionNode(node: ts.Node): node is FunctionNode {
  return (
    ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
  );
}

function indexModule(path: string, source: ts.SourceFile): Module {
  const functions = new Map<string, FunctionNode[]>();
  const imports = new Map<string, { specifier: string; exported: string }>();
  const declare = (name: string, fn: FunctionNode): void => {
    functions.set(name, [...(functions.get(name) ?? []), fn]);
  };
  const visit = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.name !== undefined) declare(node.name.text, node);
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer !== undefined &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      declare(node.name.text, node.initializer);
    }
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      node.moduleSpecifier.text.startsWith('.')
    ) {
      const bindings = node.importClause?.namedBindings;
      if (bindings !== undefined && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          imports.set(element.name.text, {
            specifier: node.moduleSpecifier.text,
            exported: element.propertyName?.text ?? element.name.text,
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { path, source, functions, imports };
}

function calleeName(expression: ts.Expression): string | undefined {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return undefined;
}

function propertyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

/**
 * Whether an fs removal call removes a tree.
 *
 * One argument is a file: `rmSync(keyFile)` deletes what it names and nothing
 * under it, which several suites do mid-test on purpose. An options object that
 * cannot be read here counts as recursive — a guard that guessed the other way
 * would be the kind of green this rewrite exists to remove.
 */
function removesTree(call: ts.CallExpression): boolean {
  const options = call.arguments[1];
  if (options === undefined) return false;
  if (!ts.isObjectLiteralExpression(options)) return true;
  for (const property of options.properties) {
    if (ts.isSpreadAssignment(property)) return true;
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === 'recursive') {
      return true;
    }
    if (ts.isPropertyAssignment(property) && propertyName(property.name) === 'recursive') {
      return property.initializer.kind !== ts.SyntaxKind.FalseKeyword;
    }
  }
  return false;
}

/** Whether a function node is handed to a call — a callback, or an immediately invoked function. */
function isInvokedFunction(node: FunctionNode): boolean {
  const parent = node.parent;
  if (ts.isCallExpression(parent) && parent.arguments.some((arg) => arg === node)) return true;
  return (
    ts.isParenthesizedExpression(parent) &&
    ts.isCallExpression(parent.parent) &&
    parent.parent.expression === parent
  );
}

class Scanner {
  private readonly modules = new Map<string, Module | null>();
  private readonly host: SourceHost;

  // A plain field rather than a parameter property, which is TypeScript-only
  // syntax: this way the module also runs under Node's type stripping, so the
  // scan can be pointed at the tree from a script without a build.
  constructor(host: SourceHost) {
    this.host = host;
  }

  module(path: string, text?: string): Module | null {
    const cached = this.modules.get(path);
    if (cached !== undefined) return cached;
    const source = text ?? this.host.read(path);
    const module = source === undefined ? null : indexModule(path, parse(path, source));
    this.modules.set(path, module);
    return module;
  }

  private resolveImport(from: string, specifier: string): Module | null {
    const base = resolve(dirname(from), specifier);
    for (const candidate of [base, `${base}.ts`, `${base}.tsx`, join(base, 'index.ts')]) {
      const module = this.module(candidate);
      if (module !== null) return module;
    }
    return null;
  }

  /** The declarations a bare identifier call could reach, in this file or through a named import. */
  private targets(name: string, within: Module): [FunctionNode, Module][] {
    const local = within.functions.get(name);
    if (local !== undefined) return local.map((fn) => [fn, within]);
    const imported = within.imports.get(name);
    if (imported === undefined) return [];
    const module = this.resolveImport(within.path, imported.specifier);
    if (module === null) return [];
    return (module.functions.get(imported.exported) ?? []).map((fn) => [fn, module]);
  }

  /**
   * The removals reachable by calling `name` from `within` — a function this file
   * declares, or one it imports by name. `seen` stops a cycle of wrappers from
   * recursing for ever.
   */
  callRemovals(name: string, within: Module, trail: string[], seen: Set<string>): string[] {
    const found: string[] = [];
    for (const [fn, module] of this.targets(name, within)) {
      const key = `${module.path}:${String(fn.pos)}`;
      if (seen.has(key) || fn.body === undefined) continue;
      seen.add(key);
      found.push(...this.removals(fn.body, module, [...trail, name], seen));
    }
    return found;
  }

  /** Every tree removal reachable from `root`, each as the call chain that reaches it. */
  removals(root: ts.Node, within: Module, trail: string[], seen: Set<string>): string[] {
    const found: string[] = [];
    const visit = (node: ts.Node): void => {
      // A function defined here and never called is not a removal that runs.
      if (node !== root && isFunctionNode(node) && !isInvokedFunction(node)) return;
      if (ts.isCallExpression(node)) {
        const name = calleeName(node.expression);
        if (name !== undefined) {
          if (TREE_REMOVERS.has(name) || (FS_REMOVERS.has(name) && removesTree(node))) {
            found.push([...trail, name].join(' → '));
          } else if (ts.isIdentifier(node.expression)) {
            found.push(...this.callRemovals(name, within, trail, seen));
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(root);
    return found;
  }
}

/**
 * Whether a suite redirects `homedir()`.
 *
 * By the shapes the tree uses and the ones it plausibly will: a `vi.mock` or
 * `vi.doMock` of `node:os` or `os` whose factory names `homedir` anywhere — an
 * arrow, a method, a shorthand, a quoted key — or a `vi.spyOn(…, 'homedir')`.
 * Read from the syntax tree, so a comment mentioning `homedir` does not count.
 */
function redirectsHome(source: ts.SourceFile): boolean {
  let found = false;
  const namesHomedir = (node: ts.Node): boolean => {
    if ((ts.isIdentifier(node) || ts.isStringLiteral(node)) && node.text === 'homedir') return true;
    return ts.forEachChild(node, namesHomedir) ?? false;
  };
  const visit = (node: ts.Node): void => {
    if (found) return;
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'vi'
    ) {
      const method = node.expression.name.text;
      const [first, second] = node.arguments;
      if (
        (method === 'mock' || method === 'doMock') &&
        first !== undefined &&
        ts.isStringLiteralLike(first) &&
        (first.text === 'node:os' || first.text === 'os') &&
        second !== undefined &&
        namesHomedir(second)
      ) {
        found = true;
        return;
      }
      if (
        method === 'spyOn' &&
        second !== undefined &&
        ts.isStringLiteralLike(second) &&
        second.text === 'homedir'
      ) {
        found = true;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

/** Scan one suite: whether it redirects the home, and what its teardown hooks remove. */
export function scanTeardowns(
  path: string,
  text: string,
  host: SourceHost = diskHost,
): TeardownScan {
  const scanner = new Scanner(host);
  const suite = scanner.module(path, text);
  if (suite === null) return { redirectsHome: false, hooks: 0, removals: [] };

  let hooks = 0;
  const removals: TreeRemoval[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const hook = calleeName(node.expression);
      const [callback] = node.arguments;
      if (hook !== undefined && HOOKS.has(hook) && callback !== undefined) {
        hooks += 1;
        const line = suite.source.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        const seen = new Set<string>();
        // `afterEach(cleanup)` hands the hook a reference; follow it like a call.
        const chains = isFunctionNode(callback)
          ? scanner.removals(callback, suite, [hook], seen)
          : ts.isIdentifier(callback)
            ? scanner.callRemovals(callback.text, suite, [hook], seen)
            : [];
        for (const path of chains) removals.push({ hook: hook as TeardownHook, line, path });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(suite.source);

  return { redirectsHome: redirectsHome(suite.source), hooks, removals };
}
