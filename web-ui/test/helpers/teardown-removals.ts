import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

/**
 * What a suite's teardowns remove, read from its source with the TypeScript
 * parser rather than with a regular expression.
 *
 * WHY A PARSER. The first version of the temp-home guard matched
 * `rmSync(… recursive: true …)` as text inside an `afterEach` body, and that
 * text match had three blind spots, each of which the tree was already using: a
 * removal through the shared `removeTree` helper (sixteen suites, none of them
 * seen), a removal in `afterAll`, and a path built by a call — `[^)]*` stops at
 * the `)` that closes `join(…)`.
 *
 * NO PRECONDITION. An earlier version only looked at suites it could tell were
 * redirecting `homedir()`, and recognising a redirect turned out to be as
 * open-ended as recognising a removal: every spelling it missed took a whole
 * suite out of the guard, silently. So this reports every teardown removal in
 * every suite, and the guard decides which ones are allowed.
 *
 * WHAT COUNTS AS A TEARDOWN.
 * - `afterEach`, `afterAll`, `aroundEach`, `aroundAll`, `onTestFinished`,
 *   `onTestFailed` — imported, aliased, or through `test.`/a namespace.
 * - A function RETURNED from `beforeEach` or `beforeAll`, which vitest runs as
 *   that hook's teardown — written in place, handed over by name, or returned
 *   by a helper the setup calls.
 * - A `test.extend` fixture — inline, by name, shorthand, in a tuple, or in an
 *   object held in a `const`.
 * - A callback handed to a function that registers a teardown hook, since that
 *   is how a "release, then run my cleanup" wrapper gets written.
 * - Any of the above anywhere in a helper module the suite imports from a test
 *   directory, transitively and through `export *` barrels — except inside
 *   `tempHomes()` itself, which is the sanctioned path and is exempted by its
 *   exact file and name.
 *
 * WHAT COUNTS AS A TREE REMOVAL. `removeTree` or `removeTrees`, called or handed
 * over by reference. Or `rm`/`rmSync`/`rmdir`/`rmdirSync` from node:fs — named,
 * aliased, destructured, through a namespace or `promises` — whose options say
 * `recursive`, or cannot be proven not to. Options held in a `const`, imported,
 * or spread from one are read rather than guessed at.
 *
 * WHAT IT FOLLOWS. Calls and references to functions in lexical scope: function
 * declarations, arrows, `vi.fn(fn)`, functions assigned later (including with
 * `??=`), and functions RETURNED by a factory a binding was set from. Named and
 * namespace imports from relative paths, named and star re-exports. Callbacks
 * handed to a call, except to a mock installer (`vi.fn`, `mockImplementation`,
 * `vi.mock`) or an inspector (`expect`, `vi.mocked`, `vi.spyOn`).
 *
 * IT FAILS CLOSED. A call chain too deep to follow, or a file it cannot parse,
 * is reported as a finding rather than passed.
 *
 * WHAT IT DOES NOT SEE, stated so nobody reads more into a green result: a
 * removal stored as data and called later (a list of disposers), a function
 * handed over through `.bind` or `.call`, a method called on a plain object or a
 * class instance, a default import, a dynamic import or `vi.importActual`,
 * anything computed at run time, and hooks registered by a module outside a
 * test directory. It also reports a hook registered inside a function nobody
 * calls, which fails loud rather than open.
 */

export interface TreeRemoval {
  /** The teardown the removal runs from: a hook name, `beforeEach teardown`, `fixture home`. */
  hook: string;
  /** 1-based line in the suite: the registration, or the import that brings in the helper. */
  line: number;
  /** The call chain from the teardown to the removal, e.g. `afterEach → cleanup → removeTree`. */
  path: string;
}

export interface TeardownScan {
  /** How many teardowns the parse found, so an empty result can be told from a blind one. */
  hooks: number;
  removals: TreeRemoval[];
}

/** Where source text comes from. The disk by default; a map in the detector's own suite. */
export interface SourceHost {
  read(path: string): string | undefined;
}

export interface ScanOptions {
  host?: SourceHost;
  /** The one teardown allowed to remove a tree. Defaults to the real `tempHomes` beside this file. */
  sanctioned?: { file: string; name: string };
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

const DEFAULT_SANCTIONED = {
  file: fileURLToPath(new URL('./temp-home.ts', import.meta.url)),
  name: 'tempHomes',
};

const TEARDOWN_HOOKS: ReadonlySet<string> = new Set([
  'afterEach',
  'afterAll',
  'aroundEach',
  'aroundAll',
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
/** Calls that look at their arguments rather than run them. */
const INSPECTING_CALLEES: ReadonlySet<string> = new Set(['expect', 'mocked', 'spyOn']);
const ASSIGNMENTS: ReadonlySet<ts.SyntaxKind> = new Set([
  ts.SyntaxKind.EqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
]);
/** Longest call chain followed before the scan reports it instead of passing it. */
const MAX_CHAIN = 64;
/** How far name, export and factory resolution go before giving up on one lookup. */
const MAX_RESOLVE = 16;

type FunctionNode =
  ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;

type Target = [FunctionNode, Module];

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
  /** `export * from '…'` specifiers. */
  starExports: string[];
  /** Every module specifier this file imports or re-exports from, with the line it is on. */
  dependencies: { specifier: string; line: number }[];
}

/** What an identifier refers to at the point it is used. */
type Resolution =
  /** Functions it can hold, and factory calls whose returned functions it can hold. */
  | { kind: 'functions'; fns: FunctionNode[]; calls: ts.CallExpression[] }
  | { kind: 'object'; literal: ts.ObjectLiteralExpression }
  /** `const { rmSync } = fs` — the property taken, and what it was taken from. */
  | { kind: 'destructured'; from: ts.Expression; property: string }
  | { kind: 'import'; binding: ImportBinding }
  /** A parameter, a class, a non-function value: known, and nothing to follow. */
  | { kind: 'bound' }
  | { kind: 'unresolved' };

type Recursion = 'yes' | 'no' | 'unknown';

interface Sink {
  hook(): void;
  add(hook: string, line: number, paths: string[]): void;
}

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

function isWrapper(
  node: ts.Node,
): node is
  | ts.ParenthesizedExpression
  | ts.AsExpression
  | ts.SatisfiesExpression
  | ts.NonNullExpression
  | ts.TypeAssertion {
  return (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isTypeAssertionExpression(node)
  );
}

/** Strip the wrappers that do not change what an expression is. */
function unwrap(expression: ts.Expression): ts.Expression {
  let e = expression;
  while (isWrapper(e)) e = e.expression;
  return e;
}

/** Case- and separator-insensitive, because the filesystems this runs on are. */
function keyOf(path: string): string {
  return path.replaceAll('\\', '/').toLowerCase();
}

function isTestPath(path: string): boolean {
  return keyOf(path).includes('/test/');
}

function shortLabel(path: string): string {
  return path.replaceAll('\\', '/').split('/').slice(-2).join('/');
}

function propertyKey(name: ts.PropertyName): string | undefined {
  if (
    ts.isIdentifier(name) ||
    ts.isPrivateIdentifier(name) ||
    ts.isStringLiteralLike(name) ||
    ts.isNumericLiteral(name)
  ) {
    return name.text;
  }
  if (ts.isComputedPropertyName(name)) {
    const e = unwrap(name.expression);
    if (ts.isStringLiteralLike(e) || ts.isNumericLiteral(e)) return e.text;
  }
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
  const module: Module = {
    path,
    source,
    imports: new Map(),
    exports: new Map(),
    starExports: [],
    dependencies: [],
  };
  const line = (node: ts.Node): number =>
    source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      const specifier = statement.moduleSpecifier.text;
      module.dependencies.push({ specifier, line: line(statement) });
      const clause = statement.importClause;
      if (clause === undefined) continue;
      if (clause.name !== undefined) {
        module.imports.set(clause.name.text, { specifier, name: 'default' });
      }
      const bindings = clause.namedBindings;
      if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
        module.imports.set(bindings.name.text, { specifier, name: '*' });
      } else if (bindings !== undefined) {
        for (const element of bindings.elements) {
          module.imports.set(element.name.text, {
            specifier,
            name: element.propertyName?.text ?? element.name.text,
          });
        }
      }
    } else if (ts.isExportDeclaration(statement)) {
      const from =
        statement.moduleSpecifier !== undefined && ts.isStringLiteral(statement.moduleSpecifier)
          ? statement.moduleSpecifier.text
          : undefined;
      if (from !== undefined) module.dependencies.push({ specifier: from, line: line(statement) });
      const clause = statement.exportClause;
      if (clause === undefined) {
        if (from !== undefined) module.starExports.push(from);
      } else if (ts.isNamedExports(clause)) {
        for (const element of clause.elements) {
          const local = element.propertyName?.text ?? element.name.text;
          module.exports.set(
            element.name.text,
            from === undefined ? { local } : { specifier: from, name: local },
          );
        }
      } else if (from !== undefined) {
        module.exports.set(clause.name.text, { specifier: from, name: '*' });
      }
    }
  }
  return module;
}

function bindsName(binding: ts.BindingName, name: string): boolean {
  if (ts.isIdentifier(binding)) return binding.text === name;
  return binding.elements.some(
    (element) => !ts.isOmittedExpression(element) && bindsName(element.name, name),
  );
}

/** The property a destructuring pattern takes into `name`, when it is a plain one. */
function destructuredProperty(pattern: ts.BindingName, name: string): string | undefined {
  if (!ts.isObjectBindingPattern(pattern)) return undefined;
  for (const element of pattern.elements) {
    if (ts.isIdentifier(element.name) && element.name.text === name) {
      return element.propertyName === undefined ? name : propertyKey(element.propertyName);
    }
  }
  return undefined;
}

/** The function a value produces: an arrow, a function, or `vi.fn(fn)`. */
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

function isScope(node: ts.Node): boolean {
  return (
    isFunctionNode(node) ||
    ts.isCatchClause(node) ||
    ts.isSourceFile(node) ||
    ts.isBlock(node) ||
    ts.isModuleBlock(node) ||
    ts.isCaseClause(node) ||
    ts.isDefaultClause(node) ||
    ts.isForStatement(node) ||
    ts.isForOfStatement(node) ||
    ts.isForInStatement(node)
  );
}

function statementsOf(scope: ts.Node): readonly ts.Statement[] | undefined {
  if (
    ts.isSourceFile(scope) ||
    ts.isBlock(scope) ||
    ts.isModuleBlock(scope) ||
    ts.isCaseClause(scope) ||
    ts.isDefaultClause(scope)
  ) {
    return scope.statements;
  }
  return undefined;
}

function declarationListsOf(scope: ts.Node): ts.VariableDeclarationList[] {
  const statements = statementsOf(scope);
  if (statements !== undefined) {
    return statements.filter(ts.isVariableStatement).map((s) => s.declarationList);
  }
  if (
    (ts.isForStatement(scope) || ts.isForOfStatement(scope) || ts.isForInStatement(scope)) &&
    scope.initializer !== undefined &&
    ts.isVariableDeclarationList(scope.initializer)
  ) {
    return [scope.initializer];
  }
  return [];
}

/** Whether `scope` itself declares `name` — without resolving what it holds. */
function declaresDirectly(scope: ts.Node, name: string): boolean {
  if (isFunctionNode(scope)) {
    if (scope.parameters.some((parameter) => bindsName(parameter.name, name))) return true;
    return (
      (ts.isFunctionDeclaration(scope) || ts.isFunctionExpression(scope)) &&
      scope.name?.text === name
    );
  }
  if (ts.isCatchClause(scope)) {
    return (
      scope.variableDeclaration !== undefined && bindsName(scope.variableDeclaration.name, name)
    );
  }
  const statements = statementsOf(scope) ?? [];
  if (
    statements.some(
      (s) => (ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s)) && s.name?.text === name,
    )
  ) {
    return true;
  }
  return declarationListsOf(scope).some((list) =>
    list.declarations.some((declaration) => bindsName(declaration.name, name)),
  );
}

/** Functions and factory calls assigned to `name` under `scope`, stopping where a nested scope shadows it. */
function assignmentsTo(
  scope: ts.Node,
  name: string,
): { fns: FunctionNode[]; calls: ts.CallExpression[] } {
  const fns: FunctionNode[] = [];
  const calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node): void => {
    if (node !== scope && isScope(node) && declaresDirectly(node, name)) return;
    if (
      ts.isBinaryExpression(node) &&
      ASSIGNMENTS.has(node.operatorToken.kind) &&
      ts.isIdentifier(node.left) &&
      node.left.text === name
    ) {
      const value = unwrap(node.right);
      const fn = functionOf(value);
      if (fn !== undefined) fns.push(fn);
      else if (ts.isCallExpression(value)) calls.push(value);
    }
    ts.forEachChild(node, visit);
  };
  visit(scope);
  return { fns, calls };
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
      return { kind: 'functions', fns: [scope], calls: [] };
    }
    return undefined;
  }
  if (ts.isCatchClause(scope)) {
    return scope.variableDeclaration !== undefined &&
      bindsName(scope.variableDeclaration.name, name)
      ? { kind: 'bound' }
      : undefined;
  }
  for (const statement of statementsOf(scope) ?? []) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
      return { kind: 'functions', fns: [statement], calls: [] };
    }
    if (ts.isClassDeclaration(statement) && statement.name?.text === name) {
      return { kind: 'bound' };
    }
  }
  for (const list of declarationListsOf(scope)) {
    for (const declaration of list.declarations) {
      if (!bindsName(declaration.name, name)) continue;
      if (!ts.isIdentifier(declaration.name)) {
        const property = destructuredProperty(declaration.name, name);
        return property !== undefined && declaration.initializer !== undefined
          ? { kind: 'destructured', from: declaration.initializer, property }
          : { kind: 'bound' };
      }
      const reassignable = (list.flags & ts.NodeFlags.Const) === 0;
      const value =
        declaration.initializer === undefined ? undefined : unwrap(declaration.initializer);
      const fns: FunctionNode[] = [];
      const calls: ts.CallExpression[] = [];
      if (value !== undefined) {
        const fn = functionOf(value);
        if (fn !== undefined) fns.push(fn);
        else if (ts.isCallExpression(value)) calls.push(value);
      }
      if (reassignable) {
        const assigned = assignmentsTo(scope, name);
        fns.push(...assigned.fns);
        calls.push(...assigned.calls);
      }
      if (fns.length > 0 || calls.length > 0) return { kind: 'functions', fns, calls };
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

function isDeferring(call: ts.CallExpression | ts.NewExpression): boolean {
  return DEFERRING_CALLEES.has(calleeLabel(call.expression));
}

/** Whether a function node runs where it is written: a callback handed to a call, or invoked in place. */
function isInvokedFunction(node: FunctionNode): boolean {
  let child: ts.Node = node;
  let parent = node.parent;
  while (isWrapper(parent)) {
    child = parent;
    parent = parent.parent;
  }
  if (ts.isCallExpression(parent) && parent.expression === child) return true;
  if (
    (ts.isCallExpression(parent) || ts.isNewExpression(parent)) &&
    parent.arguments?.some((argument) => argument === child) === true
  ) {
    return !isDeferring(parent);
  }
  return false;
}

/** The name a hook call is, resolving an alias imported from vitest and `test.`/namespace forms. */
function hookName(call: ts.CallExpression, module: Module): string | undefined {
  const callee = unwrap(call.expression);
  if (ts.isIdentifier(callee)) {
    const resolved = resolveName(callee.text, callee, module);
    if (resolved.kind === 'import') {
      return resolved.binding.specifier === 'vitest' ? resolved.binding.name : undefined;
    }
    // A destructured test-context `onTestFinished` is bound, and still the hook.
    return resolved.kind === 'unresolved' ||
      resolved.kind === 'bound' ||
      resolved.kind === 'destructured'
      ? callee.text
      : undefined;
  }
  if (ts.isPropertyAccessExpression(callee)) {
    const name = callee.name.text;
    const receiver = unwrap(callee.expression);
    const isExpect = ts.isIdentifier(receiver) && receiver.text === 'expect';
    if (!isExpect && (TEARDOWN_HOOKS.has(name) || SETUP_HOOKS.has(name))) return name;
  }
  return undefined;
}

/** What a function returns: the expression body of an arrow, or its own return statements. */
function returnExpressions(fn: FunctionNode): ts.Expression[] {
  if (fn.body === undefined) return [];
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

function functionName(fn: FunctionNode): string | undefined {
  if ((ts.isFunctionDeclaration(fn) || ts.isFunctionExpression(fn)) && fn.name !== undefined) {
    return fn.name.text;
  }
  const parent = fn.parent;
  return ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)
    ? parent.name.text
    : undefined;
}

class Scanner {
  private readonly modules = new Map<string, Module | null>();
  private readonly registers = new Map<ts.Node, boolean>();
  private readonly host: SourceHost;
  private readonly sanctioned: { file: string; name: string };

  // Plain fields rather than parameter properties, which are TypeScript-only
  // syntax: this way the module also runs under Node's type stripping, so the
  // scan can be pointed at the tree from a script without a build.
  constructor(host: SourceHost, sanctioned: { file: string; name: string }) {
    this.host = host;
    // Through the same `resolve()` every module path goes through, so the two
    // sides of the comparison agree on every platform — on Windows `resolve()`
    // adds a drive letter, and a path that skipped it would never match.
    this.sanctioned = { file: resolve(sanctioned.file), name: sanctioned.name };
  }

  module(path: string, text?: string): Module | null {
    const cached = this.modules.get(path);
    if (cached !== undefined) return cached;
    const source = text ?? this.host.read(path);
    const module = source === undefined ? null : indexModule(path, parse(path, source));
    this.modules.set(path, module);
    return module;
  }

  private candidates(from: string, specifier: string): string[] {
    const base = resolve(dirname(from), specifier);
    return [base, `${base}.ts`, `${base}.tsx`, join(base, 'index.ts')];
  }

  private resolveImport(from: string, specifier: string): Module | null {
    if (!specifier.startsWith('.')) return null;
    for (const candidate of this.candidates(from, specifier)) {
      const module = this.module(candidate);
      if (module !== null) return module;
    }
    return null;
  }

  /** The functions a module exports under `name`, following named and star re-exports. */
  private exported(module: Module, name: string, depth: number): Target[] {
    if (depth > MAX_RESOLVE) return [];
    const entry = module.exports.get(name);
    if (entry !== undefined && 'specifier' in entry) {
      if (entry.name === '*') return [];
      const target = this.resolveImport(module.path, entry.specifier);
      return target === null ? [] : this.exported(target, entry.name, depth + 1);
    }
    const local = this.targetsOf(entry?.local ?? name, module.source, module, depth + 1);
    if (local.length > 0 || entry !== undefined) return local;
    for (const specifier of module.starExports) {
      const target = this.resolveImport(module.path, specifier);
      const found = target === null ? [] : this.exported(target, name, depth + 1);
      if (found.length > 0) return found;
    }
    return [];
  }

  /** The `const` object literal a module exports under `name`, with the module it lives in. */
  private exportedObject(
    module: Module,
    name: string,
    depth: number,
  ): { literal: ts.ObjectLiteralExpression; module: Module } | undefined {
    if (depth > MAX_RESOLVE) return undefined;
    const entry = module.exports.get(name);
    if (entry !== undefined && 'specifier' in entry) {
      const target = this.resolveImport(module.path, entry.specifier);
      return target === null ? undefined : this.exportedObject(target, entry.name, depth + 1);
    }
    const resolved = resolveName(entry?.local ?? name, module.source, module);
    if (resolved.kind === 'object') return { literal: resolved.literal, module };
    if (resolved.kind === 'import') return this.importedObject(resolved.binding, module, depth);
    if (entry !== undefined) return undefined;
    for (const specifier of module.starExports) {
      const target = this.resolveImport(module.path, specifier);
      const found = target === null ? undefined : this.exportedObject(target, name, depth + 1);
      if (found !== undefined) return found;
    }
    return undefined;
  }

  private importedObject(
    binding: ImportBinding,
    within: Module,
    depth: number,
  ): { literal: ts.ObjectLiteralExpression; module: Module } | undefined {
    if (binding.name === '*' || binding.name === 'default') return undefined;
    const target = this.resolveImport(within.path, binding.specifier);
    return target === null ? undefined : this.exportedObject(target, binding.name, depth + 1);
  }

  /** The object literal an expression names, and the module it lives in. */
  private objectOf(
    expression: ts.Expression,
    module: Module,
    depth: number,
  ): { literal: ts.ObjectLiteralExpression; module: Module } | undefined {
    const e = unwrap(expression);
    if (ts.isObjectLiteralExpression(e)) return { literal: e, module };
    if (!ts.isIdentifier(e)) return undefined;
    const resolved = resolveName(e.text, e, module);
    if (resolved.kind === 'object') return { literal: resolved.literal, module };
    if (resolved.kind === 'import') return this.importedObject(resolved.binding, module, depth);
    return undefined;
  }

  /** The functions the identifier `name` can hold at `at`: in scope, imported, or made by a factory. */
  private targetsOf(name: string, at: ts.Node, module: Module, depth = 0): Target[] {
    if (depth > MAX_RESOLVE) return [];
    const resolved = resolveName(name, at, module);
    if (resolved.kind === 'functions') {
      return [
        ...resolved.fns.map((fn): Target => [fn, module]),
        ...resolved.calls.flatMap((call) => this.returnedFunctions(call, module, depth + 1)),
      ];
    }
    if (
      resolved.kind === 'import' &&
      resolved.binding.name !== '*' &&
      resolved.binding.name !== 'default'
    ) {
      const target = this.resolveImport(module.path, resolved.binding.specifier);
      return target === null ? [] : this.exported(target, resolved.binding.name, depth + 1);
    }
    return [];
  }

  /** The functions a callee reaches: a name, a member of a namespace import, or a call's result. */
  private calleeTargets(callee: ts.Expression, module: Module, depth = 0): Target[] {
    if (depth > MAX_RESOLVE) return [];
    const e = unwrap(callee);
    if (ts.isIdentifier(e)) return this.targetsOf(e.text, e, module, depth);
    if (ts.isCallExpression(e)) return this.returnedFunctions(e, module, depth + 1);
    if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression)) {
      const resolved = resolveName(e.expression.text, e.expression, module);
      if (resolved.kind === 'import' && resolved.binding.name === '*') {
        const target = this.resolveImport(module.path, resolved.binding.specifier);
        return target === null ? [] : this.exported(target, e.name.text, depth + 1);
      }
    }
    return [];
  }

  /** The functions a call returns, following the callee into its return statements. */
  private returnedFunctions(call: ts.CallExpression, module: Module, depth: number): Target[] {
    if (depth > MAX_RESOLVE) return [];
    const out: Target[] = [];
    for (const [fn, within] of this.calleeTargets(call.expression, module, depth + 1)) {
      for (const expression of returnExpressions(fn)) {
        out.push(...this.functionsOf(expression, within, depth + 1));
      }
    }
    return out;
  }

  /** The functions an expression evaluates to: a literal, a name, or a call's result. */
  private functionsOf(expression: ts.Expression, module: Module, depth = 0): Target[] {
    const e = unwrap(expression);
    if (isFunctionNode(e)) return [[e, module]];
    if (ts.isIdentifier(e)) return this.targetsOf(e.text, e, module, depth);
    if (ts.isCallExpression(e)) return this.returnedFunctions(e, module, depth + 1);
    return [];
  }

  /** What an fs options argument says about `recursive`. Unreadable counts as recursive. */
  private optionsRecursion(expression: ts.Expression, module: Module, depth = 0): Recursion {
    if (depth > MAX_RESOLVE) return 'unknown';
    const found = this.objectOf(expression, module, depth);
    if (found === undefined) return 'unknown';
    let state: Recursion = 'no';
    for (const property of found.literal.properties) {
      if (ts.isSpreadAssignment(property)) {
        const spread = this.optionsRecursion(property.expression, found.module, depth + 1);
        if (spread !== 'no') state = spread;
        continue;
      }
      const key = propertyKey(property.name);
      if (key === undefined) {
        // A computed key that is not a literal could be `recursive`.
        state = 'unknown';
        continue;
      }
      if (key !== 'recursive') continue;
      if (ts.isPropertyAssignment(property)) {
        const kind = unwrap(property.initializer).kind;
        state =
          kind === ts.SyntaxKind.FalseKeyword
            ? 'no'
            : kind === ts.SyntaxKind.TrueKeyword
              ? 'yes'
              : 'unknown';
      } else {
        // A shorthand, a getter, a method: a value this cannot read.
        state = 'unknown';
      }
    }
    return state;
  }

  /** One argument is a file; otherwise the options decide. */
  private removesTree(call: ts.CallExpression, module: Module): boolean {
    const options = call.arguments[1];
    return options !== undefined && this.optionsRecursion(options, module) !== 'no';
  }

  /** The name to report if this call is itself a tree removal. */
  private removalName(call: ts.CallExpression, module: Module): string | undefined {
    const callee = unwrap(call.expression);
    if (ts.isIdentifier(callee)) {
      const resolved = resolveName(callee.text, callee, module);
      let taken: string | undefined;
      let fromFs = false;
      if (resolved.kind === 'import') {
        taken = resolved.binding.name;
        fromFs = FS_MODULES.has(resolved.binding.specifier);
      } else if (resolved.kind === 'destructured') {
        taken = resolved.property;
        fromFs = isFsReceiver(resolved.from, module);
      } else if (resolved.kind === 'unresolved') {
        taken = callee.text;
        fromFs = true;
      }
      if (taken === undefined) return undefined;
      if (TREE_REMOVERS.has(taken)) return callee.text;
      if (fromFs && FS_REMOVERS.has(taken)) {
        return this.removesTree(call, module) ? callee.text : undefined;
      }
      return undefined;
    }
    if (ts.isPropertyAccessExpression(callee)) {
      const name = callee.name.text;
      if (TREE_REMOVERS.has(name)) return name;
      if (FS_REMOVERS.has(name) && isFsReceiver(callee.expression, module)) {
        return this.removesTree(call, module) ? name : undefined;
      }
    }
    return undefined;
  }

  /** The removals inside each target's body. `seen` stops a cycle of wrappers recursing for ever. */
  private follow(targets: Target[], label: string, trail: string[], seen: Set<string>): string[] {
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
      const taken =
        resolved.kind === 'import'
          ? resolved.binding.name
          : resolved.kind === 'destructured'
            ? resolved.property
            : resolved.kind === 'unresolved'
              ? e.text
              : undefined;
      if (taken !== undefined && TREE_REMOVERS.has(taken)) return [[...trail, e.text].join(' → ')];
      return this.follow(this.targetsOf(e.text, e, module), e.text, trail, seen);
    }
    if (ts.isPropertyAccessExpression(e)) {
      if (TREE_REMOVERS.has(e.name.text)) return [[...trail, e.name.text].join(' → ')];
      return this.follow(this.calleeTargets(e, module), e.name.text, trail, seen);
    }
    if (ts.isCallExpression(e)) {
      return this.follow(
        this.returnedFunctions(e, module, 0),
        calleeLabel(e.expression),
        trail,
        seen,
      );
    }
    return [];
  }

  /** Every tree removal reachable from `root`, each as the call chain that reaches it. */
  removals(root: ts.Node, module: Module, trail: string[], seen: Set<string>): string[] {
    if (trail.length > MAX_CHAIN) return [`${trail.join(' → ')} → (too deep to follow)`];
    const found: string[] = [];
    const visit = (node: ts.Node): void => {
      // A function defined here and never run is not a removal that runs.
      if (node !== root && isFunctionNode(node) && !isInvokedFunction(node)) return;
      if (ts.isCallExpression(node)) {
        const removal = this.removalName(node, module);
        if (removal !== undefined) {
          found.push([...trail, removal].join(' → '));
        } else {
          const label = calleeLabel(node.expression);
          found.push(
            ...this.follow(this.calleeTargets(node.expression, module), label, trail, seen),
          );
          if (!isDeferring(node) && !INSPECTING_CALLEES.has(label)) {
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

  /** The removals a teardown reaches: a callback written in place, a name, or a call's result. */
  private teardown(callback: ts.Expression, module: Module, trail: string[]): string[] {
    const e = unwrap(callback);
    const seen = new Set<string>();
    return isFunctionNode(e)
      ? this.removals(e, module, trail, seen)
      : this.reference(e, module, trail, seen);
  }

  /** The teardowns a setup hook's callback returns, however the callback is written. */
  private setupReturns(
    callback: ts.Expression,
    module: Module,
  ): { fn: FunctionNode; module: Module; name: string | undefined }[] {
    const out: { fn: FunctionNode; module: Module; name: string | undefined }[] = [];
    for (const [fn, within] of this.functionsOf(callback, module)) {
      for (const expression of returnExpressions(fn)) {
        // A teardown returned BY NAME keeps that name in the reported chain: it is
        // the thing a reader has to go and find.
        const e = unwrap(expression);
        const name = ts.isIdentifier(e) ? e.text : undefined;
        for (const [returned, at] of this.functionsOf(e, within)) {
          out.push({ fn: returned, module: at, name });
        }
      }
    }
    return out;
  }

  /** The fixture functions of a `test.extend({ … })`, however each fixture is written. */
  private fixtures(call: ts.CallExpression, module: Module): [string, FunctionNode, Module][] {
    const callee = unwrap(call.expression);
    if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== 'extend') return [];
    const receiver = unwrap(callee.expression);
    if (ts.isIdentifier(receiver) && receiver.text === 'expect') return [];
    const [argument] = call.arguments;
    const found = argument === undefined ? undefined : this.objectOf(argument, module, 0);
    if (found === undefined) return [];
    const out: [string, FunctionNode, Module][] = [];
    for (const property of found.literal.properties) {
      if (ts.isSpreadAssignment(property)) continue;
      const name = propertyKey(property.name);
      if (name === undefined) continue;
      let targets: Target[] = [];
      if (ts.isMethodDeclaration(property)) {
        targets = [[property, found.module]];
      } else if (ts.isShorthandPropertyAssignment(property)) {
        targets = this.targetsOf(name, property, found.module);
      } else if (ts.isPropertyAssignment(property)) {
        let value = unwrap(property.initializer);
        // `[fn, { scope: 'file' }]` is the tuple form.
        const first = ts.isArrayLiteralExpression(value) ? value.elements[0] : undefined;
        if (first !== undefined) value = unwrap(first);
        targets = this.functionsOf(value, found.module);
      }
      for (const [fn, within] of targets) out.push([name, fn, within]);
    }
    return out;
  }

  private isSanctioned(fn: FunctionNode, module: Module): boolean {
    return (
      keyOf(module.path) === keyOf(this.sanctioned.file) &&
      functionName(fn) === this.sanctioned.name
    );
  }

  /** The body of the sanctioned function, when `module` is its file — skipped by the hook walk. */
  sanctionedBody(module: Module): ts.Node | undefined {
    if (keyOf(module.path) !== keyOf(this.sanctioned.file)) return undefined;
    let body: ts.Node | undefined;
    const visit = (node: ts.Node): void => {
      if (body !== undefined) return;
      if (isFunctionNode(node) && this.isSanctioned(node, module)) {
        body = node;
        return;
      }
      ts.forEachChild(node, visit);
    };
    visit(module.source);
    return body;
  }

  /** Whether a function registers a teardown hook anywhere in its body. */
  private registersTeardown(fn: FunctionNode, module: Module): boolean {
    const cached = this.registers.get(fn);
    if (cached !== undefined) return cached;
    let found = false;
    const visit = (node: ts.Node): void => {
      if (found) return;
      if (ts.isCallExpression(node)) {
        const hook = hookName(node, module);
        if (hook !== undefined && TEARDOWN_HOOKS.has(hook)) {
          found = true;
          return;
        }
      }
      ts.forEachChild(node, visit);
    };
    if (fn.body !== undefined) visit(fn.body);
    this.registers.set(fn, found);
    return found;
  }

  /**
   * A call to a function that registers a teardown hook: the callbacks handed to
   * it are that teardown's body, which is how `afterEachReleased(() => …)` is written.
   */
  private wrapperCallbacks(
    call: ts.CallExpression,
    module: Module,
    prefix: string[],
    line: number,
    sink: Sink,
  ): void {
    const label = calleeLabel(call.expression);
    const registers = this.calleeTargets(call.expression, module).some(
      ([fn, within]) => !this.isSanctioned(fn, within) && this.registersTeardown(fn, within),
    );
    if (!registers) return;
    const trail = [...prefix, `${label} teardown`];
    const seen = new Set<string>();
    const paths: string[] = [];
    for (const argument of call.arguments) {
      const e = unwrap(argument);
      if (isFunctionNode(e)) paths.push(...this.removals(e, module, trail, seen));
      else if (ts.isIdentifier(e)) paths.push(...this.reference(e, module, trail, seen));
    }
    sink.add(`${label} teardown`, line, paths);
  }

  /** Find every teardown under `root` and what it removes. */
  discover(
    root: ts.Node,
    module: Module,
    prefix: string[],
    fixedLine: number | undefined,
    sink: Sink,
    skip: ts.Node | undefined,
  ): void {
    const visit = (node: ts.Node): void => {
      if (node === skip) return;
      if (ts.isCallExpression(node)) {
        const line = fixedLine ?? lineOf(module, node);
        const hook = hookName(node, module);
        const [callback] = node.arguments;
        if (hook !== undefined && TEARDOWN_HOOKS.has(hook) && callback !== undefined) {
          sink.hook();
          sink.add(hook, line, this.teardown(callback, module, [...prefix, hook]));
        } else if (hook !== undefined && SETUP_HOOKS.has(hook) && callback !== undefined) {
          const label = `${hook} teardown`;
          for (const returned of this.setupReturns(callback, module)) {
            const trail = [
              ...prefix,
              label,
              ...(returned.name === undefined ? [] : [returned.name]),
            ];
            sink.hook();
            sink.add(label, line, this.removals(returned.fn, returned.module, trail, new Set()));
          }
        } else {
          for (const [name, fn, within] of this.fixtures(node, module)) {
            const label = `fixture ${name}`;
            sink.hook();
            sink.add(label, line, this.removals(fn, within, [...prefix, label], new Set()));
          }
          this.wrapperCallbacks(node, module, prefix, line, sink);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(root);
  }

  /** Helper modules the suite imports from test directories, transitively, with the suite line that brings each in. */
  helperModules(suite: Module): { module: Module; line: number; label: string }[] {
    const out: { module: Module; line: number; label: string }[] = [];
    const seen = new Set<string>([keyOf(suite.path)]);
    const queue: { module: Module; line: number }[] = [{ module: suite, line: 0 }];
    // A for-of over an array that grows while it runs visits what is appended.
    for (const { module, line } of queue) {
      for (const dependency of module.dependencies) {
        if (!dependency.specifier.startsWith('.')) continue;
        const candidates = this.candidates(module.path, dependency.specifier);
        if (!candidates.some(isTestPath)) continue;
        const target = this.resolveImport(module.path, dependency.specifier);
        if (target === null || seen.has(keyOf(target.path))) continue;
        seen.add(keyOf(target.path));
        const suiteLine = module === suite ? dependency.line : line;
        out.push({ module: target, line: suiteLine, label: shortLabel(target.path) });
        queue.push({ module: target, line: suiteLine });
      }
    }
    return out;
  }
}

/** Scan one suite: every teardown it registers, directly or through test helpers, and what each removes. */
export function scanTeardowns(path: string, text: string, options: ScanOptions = {}): TeardownScan {
  const scanner = new Scanner(options.host ?? diskHost, options.sanctioned ?? DEFAULT_SANCTIONED);
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
  try {
    const suite = scanner.module(path, text);
    if (suite !== null) {
      scanner.discover(suite.source, suite, [], undefined, sink, undefined);
      for (const helper of scanner.helperModules(suite)) {
        scanner.discover(
          helper.module.source,
          helper.module,
          [helper.label],
          helper.line,
          sink,
          scanner.sanctionedBody(helper.module),
        );
      }
    }
  } catch (error) {
    // FAIL CLOSED. A suite this cannot read is reported, not passed.
    const reason = error instanceof Error ? error.message : String(error);
    removals.push({ hook: '(scan)', line: 1, path: `could not be analysed: ${reason}` });
  }
  return { hooks, removals };
}
