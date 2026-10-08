import { readFileSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

import * as root from '../src/index.ts';
import * as entry from '../src/sqlite-free.ts';

const SRC = resolve(import.meta.dirname, '../src');
const ENTRY = resolve(SRC, 'sqlite-free.ts');

// Every specifier a module loads, read from the TypeScript AST: static
// imports and re-exports, a bare `import 'x'`, and an `import()` with a
// literal argument anywhere in the file. `import type` and `export type` are
// erased and load nothing, so they are skipped; anything else loads its
// module, including `import { type A } from 'x'` under `verbatimModuleSyntax`.
// A non-literal `import()` names no module and stays invisible here, as it is
// to the plugin-sdk walk.
function valueSpecifiers(source: string): string[] {
  const file = ts.createSourceFile('module.ts', source, ts.ScriptTarget.Latest);
  const specifiers: string[] = [];
  for (const s of file.statements) {
    if (ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier)) {
      if (s.importClause?.phaseModifier !== ts.SyntaxKind.TypeKeyword) {
        specifiers.push(s.moduleSpecifier.text);
      }
    } else if (
      ts.isExportDeclaration(s) &&
      !s.isTypeOnly &&
      s.moduleSpecifier !== undefined &&
      ts.isStringLiteral(s.moduleSpecifier)
    ) {
      specifiers.push(s.moduleSpecifier.text);
    }
  }
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const [first] = node.arguments;
      if (first && ts.isStringLiteralLike(first)) specifiers.push(first.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return specifiers;
}

/** Every module of this package the entry loads, and the builtins they import. */
function closure(): { modules: string[]; builtins: Set<string> } {
  const seen = new Set<string>();
  const builtins = new Set<string>();
  const queue = [ENTRY];
  for (let file = queue.shift(); file; file = queue.shift()) {
    if (seen.has(file)) continue;
    seen.add(file);
    for (const specifier of valueSpecifiers(readFileSync(file, 'utf8'))) {
      if (specifier.startsWith('.')) queue.push(resolve(dirname(file), specifier));
      else if (specifier.startsWith('node:')) builtins.add(specifier);
    }
  }
  const modules = [...seen].map((f) => relative(SRC, f).split(sep).join('/')).sort();
  return { modules, builtins };
}

describe('the ./sqlite-free entry', () => {
  it('reads every form that loads a module, so the walk below misses none', () => {
    const source = [
      "import type { A } from './type-only.ts';",
      "export type { B } from './type-only-export.ts';",
      "import { x, type C } from './static.ts';",
      "export * from './star.ts';",
      "import './bare.ts';",
      'export function lazy(): Promise<unknown> {',
      '  return import("./dynamic.ts");',
      '}',
    ].join('\n');
    expect(valueSpecifiers(source).sort()).toEqual([
      './bare.ts',
      './dynamic.ts',
      './star.ts',
      './static.ts',
    ]);
  });

  it('serves the bindings the root entry exports, not copies', () => {
    const names = Object.keys(entry);
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      expect(name in root, `${name} is not exported from the root entry`).toBe(true);
      expect((entry as Record<string, unknown>)[name]).toBe(
        (root as Record<string, unknown>)[name],
      );
    }
  });

  it('loads no module that imports node:sqlite', () => {
    const { modules, builtins } = closure();
    // The positive control: the walk really followed the entry's re-exports,
    // so an empty result below is not an empty graph.
    expect(modules).toContain('fingerprint.ts');
    expect(builtins.has('node:crypto')).toBe(true);

    expect(builtins.has('node:sqlite')).toBe(false);
    expect(modules).not.toContain('index.ts');
    expect(modules).not.toContain('database.ts');
  });
});
