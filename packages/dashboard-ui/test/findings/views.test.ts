import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

// src/findings/views.ts exists for one reason: a consumer's router needs the
// view vocabulary, and a route's `validateSearch` runs at route-tree
// construction, so every module it reaches is eager by nature. Reaching those
// three constants through the package barrel instead pulled in the d3-shape
// charts — measured at 347 kB raw / 93 kB gzip on the critical path of a page
// that renders no chart at all.
//
// That saving is not held by anything the compiler or the bundler checks. It is
// held by the file reaching nothing, and until this suite existed it was held
// only by a sentence in that file's doc comment. One `import` line added there
// gives the bytes back in full: nothing fails, no type errors, and the reviewer
// of THAT diff has no reason to read a one-line import as a bundle regression.
//
// So the property is asserted rather than described, and it is asserted on the
// module the export map actually points at — repointing `./findings/views` at a
// heavy module costs exactly the same bytes as importing one, and a check
// hardcoding the path would not see it.

const PKG_ROOT = new URL('../../', import.meta.url);
const SUBPATH = './findings/views';

/**
 * Every module specifier a source file names, in any form that puts another
 * module in its graph.
 *
 * Parsed rather than pattern-matched: the string `'./heavy.ts'` inside a
 * comment is not an edge, and `export { x } from './heavy.ts'` is one — a regex
 * over the text gets both backwards. The `moduleSpecifiers` cases below are the
 * control that keeps this honest: an empty result is the PASSING answer for the
 * file under test, so a collector that quietly stopped seeing anything would
 * report success for every input.
 */
function moduleSpecifiers(source: string, fileName: string): string[] {
  const sourceFile = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const found: string[] = [];

  const record = (node: ts.Node | undefined): void => {
    if (node && ts.isStringLiteralLike(node)) found.push(node.text);
  };

  const visit = (node: ts.Node): void => {
    // `import x from 'y'`, `import type { X } from 'y'`, `import 'y'`.
    if (ts.isImportDeclaration(node)) record(node.moduleSpecifier);
    // `export { x } from 'y'`, `export * from 'y'` — an edge exactly like an
    // import, and the form a regex looking for the word `import` misses. The
    // sibling meta.ts re-exports this very module that way.
    else if (ts.isExportDeclaration(node)) record(node.moduleSpecifier);
    // `import x = require('y')`.
    else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference)
    )
      record(node.moduleReference.expression);
    // `import('y')` — no static specifier, but a router that awaits one has
    // still put the module in the graph.
    else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword)
      record(node.arguments[0]);
    // `require('y')`.
    else if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'require'
    )
      record(node.arguments[0]);
    // `import('y').Thing` in type position.
    else if (
      ts.isImportTypeNode(node) &&
      ts.isLiteralTypeNode(node.argument) &&
      ts.isStringLiteralLike(node.argument.literal)
    )
      record(node.argument.literal);

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return found;
}

/**
 * The module `./findings/views` resolves to, read through the export map.
 *
 * Derived rather than hardcoded, because repointing the subpath at a heavy
 * module costs the consumer exactly what importing one costs, and a check aimed
 * straight at src/findings/views.ts would go on passing through it.
 */
function exportedModule(subpath: string): { path: string; source: string } {
  const manifest: unknown = JSON.parse(
    readFileSync(fileURLToPath(new URL('package.json', PKG_ROOT)), 'utf8'),
  );
  const exportsMap = (manifest as { exports?: Record<string, string> }).exports ?? {};
  const target = exportsMap[subpath];

  // Thrown rather than asserted so the string narrows for the URL below. It
  // fails the case either way; what a missing entry must not do is resolve to
  // "undefined" and report some unrelated file as import-free.
  if (typeof target !== 'string') {
    throw new Error(
      `@akasecurity/dashboard-ui's package.json exports no "${subpath}". That subpath is ` +
        `the whole point of the split: without it a consumer reaches the view vocabulary ` +
        `through the barrel again, and the barrel re-exports the d3-shape charts.`,
    );
  }

  const path = fileURLToPath(new URL(target, PKG_ROOT));
  return { path, source: readFileSync(path, 'utf8') };
}

describe(`the ${SUBPATH} subpath`, () => {
  it('reaches nothing — a router reaches whatever it reaches', () => {
    const { path, source } = exportedModule(SUBPATH);
    const reached = moduleSpecifiers(source, path);

    expect(
      reached,
      `${path} names ${reached.join(', ')}. This module is imported by a route's ` +
        `validateSearch, which runs at route-tree construction, so everything it ` +
        `reaches is on the consumer's critical path — that is the 347 kB raw / 93 kB ` +
        `gzip the subpath exists to keep off a page that renders no chart. Move ` +
        `whatever needs the dependency into meta.ts, which is already eager.`,
    ).toEqual([]);
  });

  // A type-only import is erased and costs no bytes, and this refuses it anyway.
  // The invariant is worth more strict than exact: permitted, it makes every
  // future line in this file a question about elision rules — whether the
  // bundler drops it, whether `verbatimModuleSyntax` is on, whether the imported
  // name stayed type-only after an edit. This module needs nothing, so the
  // strict form costs nothing and can be checked by reading one line.
  it('refuses a type-only import too, though that one is erased', () => {
    const { path } = exportedModule(SUBPATH);
    const withTypeImport = `import type { FindingStatus } from '@akasecurity/schema';\n`;

    expect(moduleSpecifiers(withTypeImport, path)).toEqual(['@akasecurity/schema']);
  });
});

describe('moduleSpecifiers', () => {
  // The assertion above passes on an empty array, so it also passes on a
  // collector that returns an empty array for everything. These two cases are
  // what separate those readings.
  it('sees every form an edge can take', () => {
    const source = [
      `import a from './static.ts';`,
      `import type { B } from './type-only.ts';`,
      `import './side-effect.ts';`,
      `export { c } from './re-export.ts';`,
      `export * from './star-re-export.ts';`,
      `import d = require('./import-equals.ts');`,
      `const e = await import('./dynamic.ts');`,
      `const f = require('./require.ts');`,
      `type G = import('./import-type.ts').Thing;`,
      `// import { h } from './comment.ts';`,
      `const i = "import { j } from './string.ts'";`,
    ].join('\n');

    expect(moduleSpecifiers(source, 'fixture.ts')).toEqual([
      './static.ts',
      './type-only.ts',
      './side-effect.ts',
      './re-export.ts',
      './star-re-export.ts',
      './import-equals.ts',
      './dynamic.ts',
      './require.ts',
      './import-type.ts',
    ]);
  });

  it('reports the eager sibling as reaching ui-kit', () => {
    const meta = fileURLToPath(new URL('src/findings/meta.ts', PKG_ROOT));
    const reached = moduleSpecifiers(readFileSync(meta, 'utf8'), meta);

    // Live control: the fixture above proves the collector reads the forms, and
    // this proves it reads THIS package's real source. meta.ts is the module the
    // vocabulary was lifted out of, and the ui-kit edge is half of why.
    expect(reached).toContain('@akasecurity/ui-kit');
    expect(reached).toContain('./views.ts');
  });
});
