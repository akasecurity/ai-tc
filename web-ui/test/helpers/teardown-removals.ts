import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import ts from 'typescript';

/**
 * What a suite's teardown removes, read from its source with the TypeScript
 * parser rather than with a regular expression.
 *
 * WHY A PARSER. The first version of the temp-home guard matched
 * `rmSync(… recursive: true …)` as text inside an `afterEach` body, and that
 * text match had three blind spots, each of which the tree was already using: a
 * removal through the shared `removeTree` helper (sixteen suites, none of them
 * seen), a removal in `afterAll`, and a path built by a call — `[^)]*` stops at
 * the `)` that closes `join(…)`.
 *
 * WHAT COUNTS AS A TEARDOWN. `afterEach`, `afterAll`, `onTestFinished` and
 * `onTestFailed`, including under an alias imported from vitest; a function
 * RETURNED from `beforeEach` or `beforeAll`, which vitest runs as that hook's
 * teardown; a `test.extend` fixture; and any of those registered by a helper
 * imported from a test directory — except `tempHomes()` itself, whose `afterAll`
 * releases the store before it removes anything and is the sanctioned path.
 *
 * WHAT COUNTS AS A TREE REMOVAL. `removeTree` or `removeTrees`, called or handed
 * over by reference. Or `rm`/`rmSync`/`rmdir`/`rmdirSync` from node:fs — named,
 * aliased, through a namespace or `promises` — whose options say `recursive`, or
 * cannot be proven not to. Options named by a `const` object literal, or spread
 * from one, are read rather than guessed at.
 *
 * WHAT IT FOLLOWS. Calls and references to functions in lexical scope: function
 * declarations, `const`/`let` arrows, `vi.fn(fn)`, and functions later assigned
 * to a `let`. Named and namespace imports from relative paths, and re-exports.
 * Callbacks handed to a call, since that call usually runs them — except the
 * mock installers (`vi.fn`, `mockImplementation`, `vi.mock`), which store one for
 * later. Scope is respected, so two functions sharing a name in different
 * `describe` blocks are not confused.
 *
 * WHAT IT DOES NOT SEE, stated so nobody reads more into a green result: a
 * removal stored as data and called later (a list of disposers), a function
 * handed over through `.bind` or `.call`, a call through a plain object, a
 * default import, a dynamic import, anything computed at run time, and a helper
 * outside a test directory that registers hooks. A suite that hides a removal
 * behind one of those passes. The sanctioned teardown needs none of them.
 */

export interface TreeRemoval {
  /** The teardown the removal runs from: a hook name, `beforeEach teardown`, `fixture home`. */
  hook: string;
  /** 1-based line in the suite of the call that registered the teardown. */
  line: number;
  /** The call chain from the teardown to the removal, e.g. `afterEach → cleanup → removeTree`. */
  path: string;
}

export interface TeardownScan {
  /** The suite points `homedir()` somewhere else — the precondition for the bug. */
  redirectsHome: boolean;
  /** How many teardowns the parse found, so an empty result can be told from a blind one. */
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

const TEARDOWN_HOOKS: ReadonlySet<string> = new Set([
  'afterEach',
  'afterAll',
  'onTestFinished',
  'onTestFailed',
]);
/** Setup hooks whose callback may RETURN a teardown. */
const SETUP_HOOKS: ReadonlySet<string> = new Set(['beforeEach', 'beforeAll']);
/** Shared helpers that remove a tree by definition, whatever their arguments. */
const TREE_REMOVERS: ReadonlySet<string> = new Set(['removeTree', 'removeTrees']);
/** node:fs removals, which remove a tree only when told to. */
const FS_REMOVERS: ReadonlySet<string> = new Set(['rm', 'rmSync', 'rmdir', 'rmdirSync']);
const FS_MODULES: ReadonlySet<string> = new Set([
  'node:fs',
  'fs',
  'node:fs/promises',
  'fs/promises',
]);
/** Receivers that are node:fs by convention, for source whose import this scan cannot see. */
const FS_NAMESPACE_NAMES: ReadonlySet<string> = new Set(['fs', 'fsp', 'fsPromises']);
/** Calls that store a callback to run later, rather than running it. */
const DEFERRING_CALLEES: ReadonlySet<string> = new Set([
  'fn',
  'mock',
  'doMock',
  'mockImplementation',
  'mockImplementationOnce',
]);
/** The sanctioned teardown, identified by the file that defines it and its name. */
const SANCTIONED_FILE = '/test/helpers/temp-home.ts';
const SANCTIONED_NAME = 'tempHomes';

type FunctionNode =
  ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;

/** An import binding: the exported name, `*` for a namespace, `default` for a default import. */
interface ImportBinding {
  specifier: string;
  name: string;
}

type ExportEntry = { local: string } | { specifier: string; name: string };

interface Module {
  path: string;
  source: ts.SourceFile;
  imports: Map<string, ImportBinding>;
  exports: Map<string, ExportEntry>;
}

/** What an identifier refers to at the point it is used. */
type Resolution =
  | { kind: 'functions'; fns: FunctionNode[] }
  | { kind: 'object'; literal: ts.ObjectLiteralExpression }
  | { kind: 'import'; binding: ImportBinding }
  /** A parameter, a destructured binding, a class, a non-function value: known, and nothing to follow. */
  | { kind: 'bound' }
  | { kind: 'unresolved' };

function parse(path: string, text: string): ts.SourceFile {
  const kind = path.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  return ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind);
}

function isFunctionNode(node: ts.Node): node is FunctionNode {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

/** Strip the wrappers that do not change what an expression is. */
function unwrap(expression: ts.Expression): ts.Expression {
  let e = expression;
  while (
    ts.isParenthesizedExpression(e) ||
    ts.isAsExpression(e) ||
    ts.isSatisfiesExpression(e) ||
    ts.isNonNullExpression(e) ||
    ts.isTypeAssertionExpression(e)
  ) {
    e = e.expression;
  }
  return e;
}

function propertyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

function calleeLabel(expression: ts.Expression): string {
  const e = unwrap(expression);
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) return e.name.text;
  return '(call)';
}

function lineOf(module: Module, node: ts.Node): number {
  return module.source.getLineAndCharacterOfPosition(node.getStart(module.source)).line + 1;
}

function indexModule(path: string, source: ts.SourceFile): Module {
  const imports = new Map<string, ImportBinding>();
  const exports = new Map<string, ExportEntry>();
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      const specifier = statement.moduleSpecifier.text;
      const clause = statement.importClause;
      if (clause === undefined) continue;
      if (clause.name !== undefined) imports.set(clause.name.text, { specifier, name: 'default' });
      const bindings = clause.namedBindings;
      if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
        imports.set(bindings.name.text, { specifier, name: '*' });
      } else if (bindings !== undefined) {
        for (const element of bindings.elements) {
          imports.set(element.name.text, {
            specifier,
            name: element.propertyName?.text ?? element.name.text,
          });
        }
      }
    }
    if (
      ts.isExportDeclaration(statement) &&
      statement.exportClause !== undefined &&
      ts.isNamedExports(statement.exportClause)
    ) {
      const from =
        statement.moduleSpecifier !== undefined && ts.isStringLiteral(statement.moduleSpecifier)
          ? statement.moduleSpecifier.text
          : undefined;
      for (const element of statement.exportClause.elements) {
        const local = element.propertyName?.text ?? element.name.text;
        exports.set(
          element.name.text,
          from === undefined ? { local } : { specifier: from, name: local },
        );
      }
    }
  }
  return { path, source, imports, exports };
}

function bindsName(binding: ts.BindingName, name: string): boolean {
  if (ts.isIdentifier(binding)) return binding.text === name;
  return binding.elements.some(
    (element) => !ts.isOmittedExpression(element) && bindsName(element.name, name),
  );
}

/** The function an initializer or assignment produces: an arrow, a function, or `vi.fn(fn)`. */
function functionOf(expression: ts.Expression): FunctionNode | undefined {
  const e = unwrap(expression);
  if (ts.isArrowFunction(e) || ts.isFunctionExpression(e)) return e;
  if (ts.isCallExpression(e) && calleeLabel(e.expression) === 'fn') {
    const [implementation] = e.arguments;
    if (implementation !== undefined) {
      const inner = unwrap(implementation);
      if (ts.isArrowFunction(inner) || ts.isFunctionExpression(inner)) return inner;
    }
  }
  return undefined;
}

/** Functions assigned to `name` anywhere under `scope`: `cleanup = () => …`. */
function assignedFunctions(scope: ts.Node, name: string): FunctionNode[] {
  const out: FunctionNode[] = [];
  const visit = (node: ts.Node): void => {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left) &&
      node.left.text === name
    ) {
      const fn = functionOf(node.right);
      if (fn !== undefined) out.push(fn);
    }
    ts.forEachChild(node, visit);
  };
  visit(scope);
  return out;
}

/** What `name` is, if `scope` itself declares it. */
function declarationsIn(scope: ts.Node, name: string): Resolution | undefined {
  if (isFunctionNode(scope)) {
    if (scope.parameters.some((parameter) => bindsName(parameter.name, name))) {
      return { kind: 'bound' };
    }
    if (
      (ts.isFunctionDeclaration(scope) || ts.isFunctionExpression(scope)) &&
      scope.name?.text === name
    ) {
      return { kind: 'functions', fns: [scope] };
    }
    return undefined;
  }
  if (ts.isCatchClause(scope)) {
    return scope.variableDeclaration !== undefined &&
      bindsName(scope.variableDeclaration.name, name)
      ? { kind: 'bound' }
      : undefined;
  }

  const lists: ts.VariableDeclarationList[] = [];
  if (
    ts.isSourceFile(scope) ||
    ts.isBlock(scope) ||
    ts.isModuleBlock(scope) ||
    ts.isCaseClause(scope) ||
    ts.isDefaultClause(scope)
  ) {
    for (const statement of scope.statements) {
      if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
        return { kind: 'functions', fns: [statement] };
      }
      if (ts.isClassDeclaration(statement) && statement.name?.text === name) {
        return { kind: 'bound' };
      }
      if (ts.isVariableStatement(statement)) lists.push(statement.declarationList);
    }
  } else if (
    (ts.isForStatement(scope) || ts.isForOfStatement(scope) || ts.isForInStatement(scope)) &&
    scope.initializer !== undefined &&
    ts.isVariableDeclarationList(scope.initializer)
  ) {
    lists.push(scope.initializer);
  } else {
    return undefined;
  }

  for (const list of lists) {
    for (const declaration of list.declarations) {
      if (!bindsName(declaration.name, name)) continue;
      if (!ts.isIdentifier(declaration.name)) return { kind: 'bound' };
      const reassignable = (list.flags & ts.NodeFlags.Const) === 0;
      const initial =
        declaration.initializer === undefined ? undefined : functionOf(declaration.initializer);
      const fns = [
        ...(initial === undefined ? [] : [initial]),
        ...(reassignable ? assignedFunctions(scope, name) : []),
      ];
      if (fns.length > 0) return { kind: 'functions', fns };
      const value =
        declaration.initializer === undefined ? undefined : unwrap(declaration.initializer);
      if (!reassignable && value !== undefined && ts.isObjectLiteralExpression(value)) {
        return { kind: 'object', literal: value };
      }
      return { kind: 'bound' };
    }
  }
  return undefined;
}

/** What the identifier `name` refers to at `at`, walking outward through enclosing scopes. */
function resolveName(name: string, at: ts.Node, module: Module): Resolution {
  // `parent` is typed as always present, and is not on a SourceFile, so the walk
  // ends there explicitly rather than by testing for a value the type denies.
  for (let node: ts.Node | undefined = at; node !== undefined;) {
    const found = declarationsIn(node, name);
    if (found !== undefined) return found;
    node = ts.isSourceFile(node) ? undefined : node.parent;
  }
  const binding = module.imports.get(name);
  return binding === undefined ? { kind: 'unresolved' } : { kind: 'import', binding };
}

type Recursion = 'yes' | 'no' | 'unknown';

/**
 * What an fs options argument says about `recursive`.
 *
 * A literal is read property by property, later ones overriding earlier ones.
 * A name bound to a `const` object literal, and a spread of one, are read the
 * same way. Anything else is `unknown`, which counts as recursive: a guard that
 * guessed the other way would be the kind of green this detector exists to
 * remove.
 */
function optionsRecursion(expression: ts.Expression, module: Module, depth = 0): Recursion {
  if (depth > 8) return 'unknown';
  const e = unwrap(expression);
  let literal: ts.ObjectLiteralExpression | undefined;
  if (ts.isObjectLiteralExpression(e)) {
    literal = e;
  } else if (ts.isIdentifier(e)) {
    const resolved = resolveName(e.text, e, module);
    if (resolved.kind === 'object') literal = resolved.literal;
  }
  if (literal === undefined) return 'unknown';

  let state: Recursion = 'no';
  for (const property of literal.properties) {
    if (ts.isSpreadAssignment(property)) {
      const spread = optionsRecursion(property.expression, module, depth + 1);
      if (spread !== 'no') state = spread;
    } else if (ts.isShorthandPropertyAssignment(property) && property.name.text === 'recursive') {
      state = 'unknown';
    } else if (ts.isPropertyAssignment(property) && propertyName(property.name) === 'recursive') {
      const kind = property.initializer.kind;
      state =
        kind === ts.SyntaxKind.FalseKeyword
          ? 'no'
          : kind === ts.SyntaxKind.TrueKeyword
            ? 'yes'
            : 'unknown';
    }
  }
  return state;
}

/** One argument is a file; otherwise the options decide. */
function removesTree(call: ts.CallExpression, module: Module): boolean {
  const options = call.arguments[1];
  if (options === undefined) return false;
  return optionsRecursion(options, module) !== 'no';
}

/** Whether a receiver is node:fs: a namespace or default import of it, its `promises`, or `fs` by convention. */
function isFsReceiver(receiver: ts.Expression, module: Module): boolean {
  const e = unwrap(receiver);
  if (ts.isPropertyAccessExpression(e) && e.name.text === 'promises') {
    return isFsReceiver(e.expression, module);
  }
  if (!ts.isIdentifier(e)) return false;
  const resolved = resolveName(e.text, e, module);
  if (resolved.kind === 'import') {
    return (
      FS_MODULES.has(resolved.binding.specifier) &&
      ['*', 'default', 'promises'].includes(resolved.binding.name)
    );
  }
  return resolved.kind === 'unresolved' && FS_NAMESPACE_NAMES.has(e.text);
}

/** The name to report if this call is itself a tree removal. */
function removalName(call: ts.CallExpression, module: Module): string | undefined {
  const callee = unwrap(call.expression);
  if (ts.isIdentifier(callee)) {
    const resolved = resolveName(callee.text, callee, module);
    if (resolved.kind === 'import') {
      const { specifier, name } = resolved.binding;
      if (FS_MODULES.has(specifier) && FS_REMOVERS.has(name)) {
        return removesTree(call, module) ? callee.text : undefined;
      }
      return TREE_REMOVERS.has(name) ? callee.text : undefined;
    }
    if (resolved.kind === 'unresolved') {
      if (TREE_REMOVERS.has(callee.text)) return callee.text;
      if (FS_REMOVERS.has(callee.text)) return removesTree(call, module) ? callee.text : undefined;
    }
    return undefined;
  }
  if (ts.isPropertyAccessExpression(callee)) {
    const name = callee.name.text;
    if (TREE_REMOVERS.has(name)) return name;
    if (FS_REMOVERS.has(name) && isFsReceiver(callee.expression, module)) {
      return removesTree(call, module) ? name : undefined;
    }
  }
  return undefined;
}

function isDeferring(call: ts.CallExpression | ts.NewExpression): boolean {
  return DEFERRING_CALLEES.has(calleeLabel(call.expression));
}

/** Whether a function node runs where it is written: a callback handed to a call, or invoked in place. */
function isInvokedFunction(node: FunctionNode): boolean {
  const parent = node.parent;
  if (
    (ts.isCallExpression(parent) || ts.isNewExpression(parent)) &&
    parent.arguments?.some((argument) => argument === node) === true
  ) {
    return !isDeferring(parent);
  }
  return (
    ts.isParenthesizedExpression(parent) &&
    ts.isCallExpression(parent.parent) &&
    parent.parent.expression === parent
  );
}

/** The name a teardown or setup hook call is, resolving an alias imported from vitest. */
function hookName(call: ts.CallExpression, module: Module): string | undefined {
  const callee = unwrap(call.expression);
  if (ts.isIdentifier(callee)) {
    const resolved = resolveName(callee.text, callee, module);
    if (resolved.kind === 'import') {
      return resolved.binding.specifier === 'vitest' ? resolved.binding.name : undefined;
    }
    // A destructured test-context `onTestFinished` is bound, and still the hook.
    return resolved.kind === 'unresolved' || resolved.kind === 'bound' ? callee.text : undefined;
  }
  if (
    ts.isPropertyAccessExpression(callee) &&
    (callee.name.text === 'onTestFinished' || callee.name.text === 'onTestFailed')
  ) {
    return callee.name.text;
  }
  return undefined;
}

/** What a setup hook's callback returns, which vitest runs as that hook's teardown. */
function returnedTeardowns(callback: ts.Expression): ts.Expression[] {
  const fn = unwrap(callback);
  if (!isFunctionNode(fn)) return [];
  if (!ts.isBlock(fn.body)) return [fn.body];
  const out: ts.Expression[] = [];
  const visit = (node: ts.Node): void => {
    if (isFunctionNode(node)) return;
    if (ts.isReturnStatement(node) && node.expression !== undefined) out.push(node.expression);
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(fn.body, visit);
  return out;
}

/** The fixture functions of a `test.extend({ … })` call, by fixture name. */
function fixtures(call: ts.CallExpression): [string, FunctionNode][] {
  if (calleeLabel(call.expression) !== 'extend') return [];
  const [argument] = call.arguments;
  if (argument === undefined) return [];
  const object = unwrap(argument);
  if (!ts.isObjectLiteralExpression(object)) return [];
  const out: [string, FunctionNode][] = [];
  for (const property of object.properties) {
    if (ts.isMethodDeclaration(property)) {
      const name = propertyName(property.name);
      if (name !== undefined) out.push([name, property]);
    } else if (ts.isPropertyAssignment(property)) {
      const name = propertyName(property.name);
      let value = unwrap(property.initializer);
      // `[fn, { auto: true }]` is the tuple form.
      const first = ts.isArrayLiteralExpression(value) ? value.elements[0] : undefined;
      if (first !== undefined) value = unwrap(first);
      if (name !== undefined && isFunctionNode(value)) out.push([name, value]);
    }
  }
  return out;
}

function functionName(fn: FunctionNode): string | undefined {
  if ((ts.isFunctionDeclaration(fn) || ts.isFunctionExpression(fn)) && fn.name !== undefined) {
    return fn.name.text;
  }
  const parent = fn.parent;
  return ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)
    ? parent.name.text
    : undefined;
}

function normalized(path: string): string {
  return path.replaceAll('\\', '/');
}

interface Sink {
  hook(): void;
  add(hook: string, line: number, paths: string[]): void;
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
    if (!specifier.startsWith('.')) return null;
    const base = resolve(dirname(from), specifier);
    for (const candidate of [base, `${base}.ts`, `${base}.tsx`, join(base, 'index.ts')]) {
      const module = this.module(candidate);
      if (module !== null) return module;
    }
    return null;
  }

  /** The functions a module exports under `name`, following re-exports. */
  private exported(module: Module, name: string, depth = 0): [FunctionNode, Module][] {
    if (depth > 8) return [];
    const entry = module.exports.get(name);
    if (entry !== undefined && 'specifier' in entry) {
      const target = this.resolveImport(module.path, entry.specifier);
      return target === null ? [] : this.exported(target, entry.name, depth + 1);
    }
    return this.targetsOf(entry?.local ?? name, module.source, module, depth + 1);
  }

  /** The functions the identifier `name` can reach at `at`, in scope or through an import. */
  private targetsOf(
    name: string,
    at: ts.Node,
    module: Module,
    depth = 0,
  ): [FunctionNode, Module][] {
    const resolved = resolveName(name, at, module);
    if (resolved.kind === 'functions') return resolved.fns.map((fn) => [fn, module]);
    if (
      resolved.kind === 'import' &&
      resolved.binding.name !== '*' &&
      resolved.binding.name !== 'default'
    ) {
      const target = this.resolveImport(module.path, resolved.binding.specifier);
      return target === null ? [] : this.exported(target, resolved.binding.name, depth);
    }
    return [];
  }

  /** The functions a callee reaches: a name in scope, or a member of a namespace import. */
  calleeTargets(callee: ts.Expression, module: Module): [FunctionNode, Module][] {
    const e = unwrap(callee);
    if (ts.isIdentifier(e)) return this.targetsOf(e.text, e, module);
    if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression)) {
      const resolved = resolveName(e.expression.text, e.expression, module);
      if (resolved.kind === 'import' && resolved.binding.name === '*') {
        const target = this.resolveImport(module.path, resolved.binding.specifier);
        return target === null ? [] : this.exported(target, e.name.text);
      }
    }
    return [];
  }

  /** The removals inside each target's body. `seen` stops a cycle of wrappers recursing for ever. */
  private follow(
    targets: [FunctionNode, Module][],
    label: string,
    trail: string[],
    seen: Set<string>,
  ): string[] {
    const found: string[] = [];
    for (const [fn, module] of targets) {
      const key = `${module.path}:${String(fn.pos)}`;
      if (seen.has(key) || fn.body === undefined) continue;
      seen.add(key);
      found.push(...this.removals(fn.body, module, [...trail, label], seen));
    }
    return found;
  }

  /** A function handed over by reference — `forEach(removeTree)`, `afterEach(cleanup)`. */
  private reference(
    expression: ts.Expression,
    module: Module,
    trail: string[],
    seen: Set<string>,
  ): string[] {
    const e = unwrap(expression);
    if (ts.isIdentifier(e)) {
      const resolved = resolveName(e.text, e, module);
      if (
        (resolved.kind === 'import' && TREE_REMOVERS.has(resolved.binding.name)) ||
        (resolved.kind === 'unresolved' && TREE_REMOVERS.has(e.text))
      ) {
        return [[...trail, e.text].join(' → ')];
      }
      return this.follow(this.targetsOf(e.text, e, module), e.text, trail, seen);
    }
    if (ts.isPropertyAccessExpression(e)) {
      if (TREE_REMOVERS.has(e.name.text)) return [[...trail, e.name.text].join(' → ')];
      return this.follow(this.calleeTargets(e, module), e.name.text, trail, seen);
    }
    return [];
  }

  /** Every tree removal reachable from `root`, each as the call chain that reaches it. */
  removals(root: ts.Node, module: Module, trail: string[], seen: Set<string>): string[] {
    const found: string[] = [];
    const visit = (node: ts.Node): void => {
      // A function defined here and never run is not a removal that runs.
      if (node !== root && isFunctionNode(node) && !isInvokedFunction(node)) return;
      if (ts.isCallExpression(node)) {
        const removal = removalName(node, module);
        if (removal !== undefined) {
          found.push([...trail, removal].join(' → '));
        } else {
          const label = calleeLabel(node.expression);
          found.push(
            ...this.follow(this.calleeTargets(node.expression, module), label, trail, seen),
          );
          if (!isDeferring(node)) {
            for (const argument of node.arguments) {
              if (!isFunctionNode(unwrap(argument))) {
                found.push(...this.reference(argument, module, trail, seen));
              }
            }
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(root);
    return found;
  }

  /** The removals a teardown callback reaches: written in place, or handed over by name. */
  private teardown(callback: ts.Expression, module: Module, trail: string[]): string[] {
    const e = unwrap(callback);
    const seen = new Set<string>();
    return isFunctionNode(e)
      ? this.removals(e, module, trail, seen)
      : this.reference(e, module, trail, seen);
  }

  /** Find every teardown under `root`, including ones registered by test helpers it calls. */
  hooks(
    root: ts.Node,
    module: Module,
    prefix: string[],
    suiteLine: number | undefined,
    sink: Sink,
    helpersSeen: Set<string>,
  ): void {
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const line = suiteLine ?? lineOf(module, node);
        const hook = hookName(node, module);
        const [callback] = node.arguments;
        if (hook !== undefined && TEARDOWN_HOOKS.has(hook) && callback !== undefined) {
          sink.hook();
          sink.add(hook, line, this.teardown(callback, module, [...prefix, hook]));
        } else if (hook !== undefined && SETUP_HOOKS.has(hook) && callback !== undefined) {
          for (const returned of returnedTeardowns(callback)) {
            const e = unwrap(returned);
            if (!isFunctionNode(e) && !ts.isIdentifier(e)) continue;
            const label = `${hook} teardown`;
            sink.hook();
            sink.add(label, line, this.teardown(e, module, [...prefix, label]));
          }
        } else {
          for (const [name, fn] of fixtures(node)) {
            const label = `fixture ${name}`;
            sink.hook();
            sink.add(label, line, this.removals(fn, module, [...prefix, label], new Set()));
          }
          // A helper from a test directory may register teardowns of its own.
          // Local functions are already under this walk, so only other files.
          for (const [fn, target] of this.calleeTargets(node.expression, module)) {
            if (target === module || !normalized(target.path).includes('/test/')) continue;
            if (
              normalized(target.path).endsWith(SANCTIONED_FILE) &&
              functionName(fn) === SANCTIONED_NAME
            ) {
              continue;
            }
            const key = `${target.path}:${String(fn.pos)}`;
            if (helpersSeen.has(key) || fn.body === undefined) continue;
            helpersSeen.add(key);
            this.hooks(
              fn.body,
              target,
              [...prefix, calleeLabel(node.expression)],
              line,
              sink,
              helpersSeen,
            );
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(root);
  }

  /**
   * Whether a suite redirects `homedir()`.
   *
   * A `vi.mock` or `vi.doMock` of `node:os` or `os` — as a string or as
   * `import('node:os')` — whose factory names `homedir`, itself or through a
   * function it calls; a `vi.spyOn(…, 'homedir')`; or a `vi.mocked(…)` of
   * something naming `homedir`, which is how an automocked module is pointed
   * somewhere. Read from the syntax tree, so a comment does not count.
   */
  redirectsHome(module: Module): boolean {
    const seen = new Set<string>();
    const namesHomedir = (node: ts.Node, within: Module): boolean => {
      if ((ts.isIdentifier(node) || ts.isStringLiteral(node)) && node.text === 'homedir') {
        return true;
      }
      if (ts.isCallExpression(node)) {
        for (const [fn, target] of this.calleeTargets(node.expression, within)) {
          const key = `${target.path}:${String(fn.pos)}`;
          if (seen.has(key) || fn.body === undefined) continue;
          seen.add(key);
          if (namesHomedir(fn.body, target)) return true;
        }
      }
      return ts.forEachChild(node, (child) => namesHomedir(child, within) || undefined) ?? false;
    };
    const isOsSpecifier = (expression: ts.Expression): boolean => {
      const e = unwrap(expression);
      if (ts.isStringLiteralLike(e)) return e.text === 'node:os' || e.text === 'os';
      if (ts.isCallExpression(e) && e.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const [specifier] = e.arguments;
        return specifier !== undefined && isOsSpecifier(specifier);
      }
      return false;
    };

    let found = false;
    const visit = (node: ts.Node): void => {
      if (found) return;
      if (ts.isCallExpression(node)) {
        const callee = unwrap(node.expression);
        if (
          ts.isPropertyAccessExpression(callee) &&
          ts.isIdentifier(callee.expression) &&
          callee.expression.text === 'vi'
        ) {
          const method = callee.name.text;
          const [first, second] = node.arguments;
          if (
            (method === 'mock' || method === 'doMock') &&
            first !== undefined &&
            isOsSpecifier(first) &&
            second !== undefined &&
            namesHomedir(second, module)
          ) {
            found = true;
          } else if (
            method === 'spyOn' &&
            second !== undefined &&
            ts.isStringLiteralLike(second) &&
            second.text === 'homedir'
          ) {
            found = true;
          } else if (method === 'mocked' && first !== undefined && namesHomedir(first, module)) {
            found = true;
          }
          if (found) return;
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(module.source);
    return found;
  }
}

/** Scan one suite: whether it redirects the home, and what its teardowns remove. */
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
  const sink: Sink = {
    hook() {
      hooks += 1;
    },
    add(hook, line, paths) {
      for (const removalPath of paths) removals.push({ hook, line, path: removalPath });
    },
  };
  scanner.hooks(suite.source, suite, [], undefined, sink, new Set());

  return { redirectsHome: scanner.redirectsHome(suite), hooks, removals };
}
