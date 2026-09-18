// The suite for `test/helpers/turbo-inputs.ts`, which sits at the repo root
// because several packages' cross-package guards share it. It lives HERE for
// the reason `remove-tree.test.ts` does: the repo root is not a workspace
// package, so a root-level suite would be run by nothing.
//
// Both functions fail SILENTLY when weakened — a parser that matches text
// reports a disabled input as present, and a scanner that finds nothing
// demands nothing — and every caller stays green either way. Each case below
// therefore drives the real file forms against a real temp tree.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  crossPackageSpecifiers,
  declaredTestInputs,
  turboRootInput,
} from '../../../../test/helpers/turbo-inputs.ts';

let repoRoot: string;
let packageDir: string;

beforeEach(() => {
  repoRoot = mkdtempSync(join(tmpdir(), 'aka-turbo-inputs-'));
  packageDir = join(repoRoot, 'plugins', 'sample');
  mkdirSync(join(packageDir, 'test'), { recursive: true });
});

afterEach(() => {
  removeTree(repoRoot);
});

function writeTurboJson(text: string): void {
  writeFileSync(join(packageDir, 'turbo.json'), text);
}

const CLI_MANIFEST = turboRootInput('cli/package.json');

describe('turboRootInput', () => {
  it('spells a repo-relative path the way turbo.json does', () => {
    expect(CLI_MANIFEST).toBe('$TURBO_ROOT$/cli/package.json');
  });
});

describe('declaredTestInputs', () => {
  it('returns the test task inputs in declaration order', () => {
    writeTurboJson(
      JSON.stringify({
        extends: ['//'],
        tasks: { test: { inputs: ['$TURBO_DEFAULT$', CLI_MANIFEST] } },
      }),
    );
    expect(declaredTestInputs(packageDir)).toEqual(['$TURBO_DEFAULT$', CLI_MANIFEST]);
  });

  it('does not count a commented-out entry', () => {
    writeTurboJson(
      [
        '{',
        '  "tasks": {',
        '    "test": {',
        '      "inputs": [',
        `        // "${CLI_MANIFEST}",`,
        '        "$TURBO_DEFAULT$"',
        '      ]',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    );
    const inputs = declaredTestInputs(packageDir);
    expect(inputs).toEqual(['$TURBO_DEFAULT$']);
    expect(inputs).not.toContain(CLI_MANIFEST);
  });

  it('does not read a longer path as the one it contains', () => {
    const renamed = `${CLI_MANIFEST}.disabled`;
    writeTurboJson(JSON.stringify({ tasks: { test: { inputs: [renamed] } } }));
    // The text form this replaces is satisfied by the rename.
    expect(renamed).toContain(CLI_MANIFEST);
    expect(declaredTestInputs(packageDir)).not.toContain(CLI_MANIFEST);
  });

  it('does not read another task as the test task', () => {
    writeTurboJson(JSON.stringify({ tasks: { build: { inputs: [CLI_MANIFEST] } } }));
    expect(() => declaredTestInputs(packageDir)).toThrow(/no tasks\.test\.inputs/);
  });

  it('refuses a missing turbo.json, naming what the package then hashes', () => {
    expect(() => declaredTestInputs(packageDir)).toThrow(/does not exist/);
  });

  it('refuses inputs that are not an array of strings', () => {
    writeTurboJson(JSON.stringify({ tasks: { test: { inputs: CLI_MANIFEST } } }));
    expect(() => declaredTestInputs(packageDir)).toThrow(/no tasks\.test\.inputs/);
    writeTurboJson(JSON.stringify({ tasks: { test: { inputs: [CLI_MANIFEST, 1] } } }));
    expect(() => declaredTestInputs(packageDir)).toThrow(/no tasks\.test\.inputs/);
  });

  it('throws on a file that is not JSON rather than returning nothing', () => {
    writeTurboJson('{ "tasks": { "test": { "inputs": [ /* none */ ] } } }');
    expect(() => declaredTestInputs(packageDir)).toThrow(SyntaxError);
  });
});

describe('crossPackageSpecifiers', () => {
  function scan(source: string): string[] {
    const testFile = join(packageDir, 'test', 'sample.test.ts');
    writeFileSync(testFile, source);
    return crossPackageSpecifiers({ testFile, packageDir, repoRoot });
  }

  it('finds a literal that leaves the package, in each quote form', () => {
    expect(
      scan(
        [
          "read('../../../cli/package.json');",
          'read("../../../README.md");',
          'read(`../../../plugins/other/package.json`);',
        ].join('\n'),
      ),
    ).toEqual(['README.md', 'cli/package.json', 'plugins/other/package.json']);
  });

  it('leaves out a literal that stays inside the package', () => {
    expect(scan("read('../package.json');\nread('./fixtures/a.json');")).toEqual([]);
  });

  it('leaves out an anchor: a directory the package sits inside', () => {
    expect(
      scan(
        [
          "const repoRoot = new URL('../../..', import.meta.url);",
          "const plugins = new URL('../../', import.meta.url);",
          "read('../../../cli/package.json');",
        ].join('\n'),
      ),
    ).toEqual(['cli/package.json']);
  });

  it('still counts a sibling directory, which the package does not sit inside', () => {
    expect(scan("walk('../../other/');")).toEqual(['plugins/other']);
  });

  it('reports each file once however often it is read', () => {
    expect(scan("read('../../../cli/package.json');\nread('../../../cli/package.json');")).toEqual([
      'cli/package.json',
    ]);
  });

  it('leaves out the specifier of a static import, single- or multi-line', () => {
    expect(
      scan(
        [
          "import { removeTree } from '../../../test/helpers/remove-tree.ts';",
          'import {',
          '  declaredTestInputs,',
          '  turboRootInput,',
          "} from '../../../test/helpers/turbo-inputs.ts';",
          "export { x } from '../../../test/helpers/perf.ts';",
          "read('../../../cli/package.json');",
        ].join('\n'),
      ),
    ).toEqual(['cli/package.json']);
  });

  it('still counts a read that follows an import on the same line', () => {
    expect(scan("import { a } from '../src/a.ts'; read('../../../cli/package.json');")).toEqual([
      'cli/package.json',
    ]);
  });

  it('counts a side-effect import and a dynamic one, which name no binding', () => {
    expect(
      scan("import '../../../test/setup/x.ts';\nawait import('../../../cli/src/main.ts');"),
    ).toEqual(['cli/src/main.ts', 'test/setup/x.ts']);
  });

  it('returns an interpolated literal as a path no input can match', () => {
    const found = scan('read(`../../../${name}/package.json`);');
    expect(found).toHaveLength(1);
    expect(found[0]).toContain('${name}');
  });
});
