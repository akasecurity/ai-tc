import { describe, expect, it } from 'vitest';

import { scanTeardowns, type SourceHost } from './teardown-removals.ts';

// The detector behind the temp-home guard, driven with source it has never seen.
//
// The guard over the real tree can only prove what the tree happens to contain
// today. These cases pin each SHAPE, so a change that stops recognising one goes
// red here even while the tree is clean — which is the state the guard spends
// almost all of its life in, and the state in which a blind spot is invisible.
//
// Sources are template strings, not files: a call inside a string is not a call
// in the syntax tree, so this file is never mistaken for a suite doing any of it.

const SUITE = '/virtual/web-ui/test/pages/suite.test.ts';

function host(files: Record<string, string> = {}): SourceHost {
  return { read: (path) => files[path] };
}

function removals(text: string, files: Record<string, string> = {}): string[] {
  return scanTeardowns(SUITE, text, host(files)).removals.map((r) => r.path);
}

describe('scanTeardowns — what counts as removing a tree', () => {
  it('sees a literal recursive rmSync', () => {
    expect(
      removals(`afterEach(() => { rmSync(home, { recursive: true, force: true }); });`),
    ).toEqual(['afterEach → rmSync']);
  });

  // The shape a `[^)]*` regex cannot read: its first `)` closes `join(…)`, so
  // the match ends before it reaches the options at all.
  it('sees a removal whose path is itself a call', () => {
    expect(
      removals(`afterEach(() => { rmSync(join(home, 'data'), { recursive: true }); });`),
    ).toEqual(['afterEach → rmSync']);
  });

  it('sees options written across several lines', () => {
    expect(
      removals(`afterEach(() => {
        rmSync(home, {
          force: true,
          recursive: true,
        });
      });`),
    ).toEqual(['afterEach → rmSync']);
  });

  it('sees a removal through a namespace', () => {
    expect(removals(`afterEach(() => { fs.rmSync(home, { recursive: true }); });`)).toEqual([
      'afterEach → rmSync',
    ]);
  });

  it('sees the promise form, awaited in an async hook', () => {
    expect(removals(`afterEach(async () => { await rm(home, { recursive: true }); });`)).toEqual([
      'afterEach → rm',
    ]);
  });

  // THE BLIND SPOT this detector replaced a regex to close. Sixteen suites
  // removed their home this way and the text match saw none of them.
  it('sees the shared removeTree helper', () => {
    expect(removals(`afterEach(() => { resetSingleton(); removeTree(home); });`)).toEqual([
      'afterEach → removeTree',
    ]);
  });

  it('sees removeTrees', () => {
    expect(removals(`afterEach(() => { removeTrees([home, target]); });`)).toEqual([
      'afterEach → removeTrees',
    ]);
  });

  // The handle is as open at the end of a file as after a test.
  it('sees a removal in afterAll', () => {
    expect(removals(`afterAll(() => { removeTree(home); });`)).toEqual(['afterAll → removeTree']);
  });

  it('sees a removal inside try/finally', () => {
    expect(
      removals(
        `afterAll(() => { try { check(); } finally { dropMemoisedDb(); removeTree(home); } });`,
      ),
    ).toEqual(['afterAll → removeTree']);
  });

  it('counts an options object it cannot read as recursive', () => {
    expect(removals(`afterEach(() => { rmSync(home, options); });`)).toEqual([
      'afterEach → rmSync',
    ]);
  });

  it('counts spread options as recursive', () => {
    expect(removals(`afterEach(() => { rmSync(home, { ...options }); });`)).toEqual([
      'afterEach → rmSync',
    ]);
  });
});

describe('scanTeardowns — following the call to where the removal is', () => {
  it('follows a function declared in the same file', () => {
    expect(
      removals(`
        function cleanup(): void { removeTree(home); }
        afterEach(() => { cleanup(); });
      `),
    ).toEqual(['afterEach → cleanup → removeTree']);
  });

  it('follows arrow wrappers, through more than one level', () => {
    expect(
      removals(`
        const wipe = () => rmSync(home, { recursive: true });
        const cleanup = () => { wipe(); };
        afterEach(() => cleanup());
      `),
    ).toEqual(['afterEach → cleanup → wipe → rmSync']);
  });

  it('follows a hook handed a reference instead of a callback', () => {
    expect(
      removals(`
        function cleanup(): void { removeTree(home); }
        afterEach(cleanup);
      `),
    ).toEqual(['afterEach → cleanup → removeTree']);
  });

  it('follows a callback handed to another call', () => {
    expect(removals(`afterEach(() => { dirs.forEach((dir) => removeTree(dir)); });`)).toEqual([
      'afterEach → removeTree',
    ]);
  });

  it('follows a named import from a relative path, under an alias', () => {
    expect(
      removals(
        `import { wipe as clean } from '../helpers/wipe.ts';\nafterEach(() => { clean(); });`,
        {
          '/virtual/web-ui/test/helpers/wipe.ts': `export function wipe(): void { rmSync(dir, { recursive: true }); }`,
        },
      ),
    ).toEqual(['afterEach → clean → rmSync']);
  });

  it('resolves an import written without its extension', () => {
    expect(
      removals(`import { wipe } from '../helpers/wipe';\nafterAll(() => wipe());`, {
        '/virtual/web-ui/test/helpers/wipe.ts': `export const wipe = () => removeTree(dir);`,
      }),
    ).toEqual(['afterAll → wipe → removeTree']);
  });

  it('terminates on wrappers that call each other', () => {
    expect(
      removals(`
        function a(): void { b(); }
        function b(): void { a(); }
        afterEach(() => { a(); });
      `),
    ).toEqual([]);
  });

  it('reports a cycle that does reach a removal exactly once', () => {
    expect(
      removals(`
        function a(): void { b(); removeTree(home); }
        function b(): void { a(); }
        afterEach(() => { a(); });
      `),
    ).toEqual(['afterEach → a → removeTree']);
  });

  it('shrugs at an import it cannot resolve', () => {
    expect(removals(`import { gone } from './gone.ts';\nafterEach(() => { gone(); });`)).toEqual(
      [],
    );
  });
});

describe('scanTeardowns — what it must leave alone', () => {
  // Several suites delete a key or credential FILE mid-test on purpose; that
  // is the behaviour under test, and nothing under a store lives in it.
  it('ignores a single-file removal', () => {
    expect(removals(`afterEach(() => { rmSync(keyFile); });`)).toEqual([]);
  });

  it('ignores an explicitly non-recursive removal', () => {
    expect(removals(`afterEach(() => { rmSync(dir, { recursive: false }); });`)).toEqual([]);
  });

  it('ignores a removal outside the teardown hooks', () => {
    expect(
      removals(`
        beforeEach(() => { removeTree(stale); });
        it('deletes', () => { removeTree(home); });
        removeTree(atImport);
      `),
    ).toEqual([]);
  });

  it('ignores a function declared in a hook and never called', () => {
    expect(
      removals(`afterEach(() => { const later = () => removeTree(home); void later; });`),
    ).toEqual([]);
  });

  // The sanctioned teardown. Its removal lives inside `tempHomes`, registered
  // when the factory is created — not in anything the suite's hooks call.
  it('accepts a suite on tempHomes', () => {
    expect(
      removals(`
        import { tempHomes } from '../helpers/temp-home.ts';
        const newHome = tempHomes('aka-x-');
        beforeEach(() => { osHome.dir = newHome(); });
        afterEach(() => { resetSingleton(); });
      `),
    ).toEqual([]);
  });

  it('ignores removal named only in a comment or a string', () => {
    expect(
      removals(`afterEach(() => {
        // removeTree(home) used to live here
        log('rmSync(home, { recursive: true })');
      });`),
    ).toEqual([]);
  });
});

describe('scanTeardowns — whether the suite redirects the home', () => {
  const redirects = (text: string): boolean => scanTeardowns(SUITE, text, host()).redirectsHome;

  it('sees the arrow form the tree uses', () => {
    expect(
      redirects(`vi.mock('node:os', async (importActual) => {
        const actual = await importActual();
        return { ...actual, homedir: () => osHome.dir };
      });`),
    ).toBe(true);
  });

  it('sees a method, and the bare specifier', () => {
    expect(redirects(`vi.mock('os', () => ({ homedir() { return dir; } }));`)).toBe(true);
  });

  it('sees doMock', () => {
    expect(redirects(`vi.doMock('node:os', () => ({ homedir: fake }));`)).toBe(true);
  });

  it('sees a spy', () => {
    expect(redirects(`vi.spyOn(os, 'homedir').mockReturnValue(dir);`)).toBe(true);
  });

  it('does not count an os mock that leaves the home alone', () => {
    expect(redirects(`vi.mock('node:os', () => ({ tmpdir: () => dir }));`)).toBe(false);
  });

  it('does not count homedir named only in a comment', () => {
    expect(
      redirects(
        `// this suite deliberately does not redirect homedir\nvi.mock('node:os', () => ({}));`,
      ),
    ).toBe(false);
  });
});

describe('scanTeardowns — hook count', () => {
  // What lets the guard tell "these suites remove nothing" from "the parse saw
  // no hooks": a blind scan reports zero hooks, not merely zero removals.
  it('counts teardown hooks at any depth, and only teardown hooks', () => {
    const scan = scanTeardowns(
      SUITE,
      `
        beforeEach(() => {});
        afterEach(() => {});
        describe('x', () => {
          afterAll(() => {});
          describe('y', () => { afterEach(() => {}); });
        });
      `,
      host(),
    );
    expect(scan.hooks).toBe(3);
  });

  it('reports the hook line', () => {
    const [removal] = scanTeardowns(
      SUITE,
      `\n\nafterAll(() => removeTree(home));`,
      host(),
    ).removals;
    expect(removal).toEqual({ hook: 'afterAll', line: 3, path: 'afterAll → removeTree' });
  });
});
