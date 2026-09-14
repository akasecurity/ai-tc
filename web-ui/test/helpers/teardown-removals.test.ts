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

// ─── Shapes found by trying to evade the first parser-based version ─────────
//
// Each case below was written to slip past the detector, ran against it, and
// did. They are pinned here so that closing them is not a one-off.

describe('scanTeardowns — teardowns that are not written as afterEach', () => {
  // Vitest runs a function RETURNED from a setup hook as that hook's teardown.
  it('sees a teardown returned from beforeEach', () => {
    expect(
      removals(`beforeEach(() => {
        osHome.dir = home;
        return () => { resetSingleton(); removeTree(home); };
      });`),
    ).toEqual(['beforeEach teardown → removeTree']);
  });

  it('sees a teardown returned from beforeAll as an arrow body', () => {
    expect(removals(`beforeAll(() => () => removeTree(home));`)).toEqual([
      'beforeAll teardown → removeTree',
    ]);
  });

  it('sees a returned teardown handed back by name', () => {
    expect(
      removals(`
        function cleanup(): void { removeTree(home); }
        beforeEach(() => { return cleanup; });
      `),
    ).toEqual(['beforeEach teardown → cleanup → removeTree']);
  });

  it('ignores a setup hook that returns something that is not a function', () => {
    const scan = scanTeardowns(SUITE, `beforeEach(() => (osHome.dir = newHome()));`, host());
    expect(scan).toMatchObject({ hooks: 0, removals: [] });
  });

  it('sees onTestFinished, including from a destructured test context', () => {
    expect(
      removals(`
        beforeEach(() => { onTestFinished(() => { removeTree(home); }); });
        it('x', ({ onTestFailed }) => { onTestFailed(() => removeTree(home)); });
      `),
    ).toEqual(['onTestFinished → removeTree', 'onTestFailed → removeTree']);
  });

  it('sees a test.extend fixture that removes after use', () => {
    expect(
      removals(`const test = base.extend({
        home: async ({}, use) => {
          const dir = newDir();
          await use(dir);
          removeTree(dir);
        },
      });`),
    ).toEqual(['fixture home → removeTree']);
  });

  it('sees an aliased hook imported from vitest', () => {
    expect(
      removals(
        `import { afterEach as teardown } from 'vitest';\nteardown(() => { removeTree(home); });`,
      ),
    ).toEqual(['afterEach → removeTree']);
  });

  // Built like tempHomes(), but removing per test and without releasing first.
  it('sees a teardown registered by a helper imported from a test directory', () => {
    expect(
      removals(
        `import { tempHomeEach } from '../helpers/home.ts';\nconst newHome = tempHomeEach('aka-x-');`,
        {
          '/virtual/web-ui/test/helpers/home.ts': `export function tempHomeEach(prefix: string) {
            let dir = '';
            afterEach(() => { removeTree(dir); });
            return () => (dir = make(prefix));
          }`,
        },
      ),
    ).toEqual(['tempHomeEach → afterEach → removeTree']);
  });

  // The exemption is by file AND name, so a lookalike elsewhere is still read.
  it('exempts the real tempHomes, and only the real one', () => {
    const helper = `export function tempHomes(prefix: string) {
      afterAll(async () => { await releaseLocalStore(); removeTrees(made); });
      return () => make(prefix);
    }`;
    expect(
      removals(`import { tempHomes } from '../helpers/temp-home.ts';\nconst h = tempHomes('a-');`, {
        '/virtual/web-ui/test/helpers/temp-home.ts': helper,
      }),
    ).toEqual([]);
    expect(
      removals(
        `import { tempHomes } from '../helpers/other-home.ts';\nconst h = tempHomes('a-');`,
        {
          '/virtual/web-ui/test/helpers/other-home.ts': helper,
        },
      ),
    ).toEqual(['tempHomes → afterAll → removeTrees']);
  });
});

describe('scanTeardowns — removals the first parser-based version could not follow', () => {
  it('follows a function assigned to a let later', () => {
    expect(
      removals(`
        let cleanup: () => void = () => {};
        beforeEach(() => { cleanup = () => { resetSingleton(); removeTree(home); }; });
        afterEach(() => { cleanup(); });
      `),
    ).toEqual(['afterEach → cleanup → removeTree']);
  });

  it('sees removeTree handed over by reference', () => {
    expect(removals(`afterEach(() => { [home, target].forEach(removeTree); });`)).toEqual([
      'afterEach → removeTree',
    ]);
  });

  it('follows a wrapper made with vi.fn', () => {
    expect(
      removals(`
        const cleanup = vi.fn(() => { removeTree(home); });
        afterEach(() => { cleanup(); });
      `),
    ).toEqual(['afterEach → cleanup → removeTree']);
  });

  it('sees an fs removal imported under an alias', () => {
    expect(
      removals(`import { rmSync as removeSync } from 'node:fs';
        afterEach(() => { removeSync(home, { recursive: true, force: true }); });`),
    ).toEqual(['afterEach → removeSync']);
  });

  it('sees an fs removal through a namespace import and through promises', () => {
    expect(
      removals(`import * as fsp from 'node:fs/promises';
        import nodeFs from 'node:fs';
        afterEach(async () => {
          await fsp.rm(home, { recursive: true });
          await nodeFs.promises.rm(other, { recursive: true });
        });`),
    ).toEqual(['afterEach → rm', 'afterEach → rm']);
  });

  it('follows a member of a namespace import from a relative path', () => {
    expect(
      removals(
        `import * as helpers from '../helpers/cleanup.ts';\nafterEach(() => helpers.wipe());`,
        {
          '/virtual/web-ui/test/helpers/cleanup.ts': `export const wipe = () => removeTree(dir);`,
        },
      ),
    ).toEqual(['afterEach → wipe → removeTree']);
  });

  it('follows a re-export', () => {
    expect(
      removals(`import { clean } from '../helpers/index.ts';\nafterAll(() => clean());`, {
        '/virtual/web-ui/test/helpers/index.ts': `export { wipe as clean } from './wipe.ts';`,
        '/virtual/web-ui/test/helpers/wipe.ts': `export function wipe(): void { removeTree(dir); }`,
      }),
    ).toEqual(['afterAll → clean → removeTree']);
  });

  it('reads a const options object that does say recursive', () => {
    expect(
      removals(
        `const WIPE = { recursive: true, force: true };\nafterEach(() => { rmSync(home, WIPE); });`,
      ),
    ).toEqual(['afterEach → rmSync']);
  });
});

describe('scanTeardowns — false alarms the first parser-based version raised', () => {
  // Sidecar and credential FILES are removed with retry options held in a
  // constant; reading the constant is what tells them from a tree.
  it('reads a const options object that does not say recursive', () => {
    expect(
      removals(`const RM_FILE = { force: true, maxRetries: 10, retryDelay: 50 };
        afterEach(() => { for (const f of sidecars) rmSync(f, RM_FILE); });`),
    ).toEqual([]);
  });

  it('reads a spread of a const that does not say recursive', () => {
    expect(
      removals(`const retry = { maxRetries: 10, retryDelay: 50 };
        afterEach(() => { rmSync(credentialFile(), { force: true, ...retry }); });`),
    ).toEqual([]);
  });

  it('still counts a let options object, which could be anything by then', () => {
    expect(
      removals(`let opts = { force: true };\nafterEach(() => { rmSync(home, opts); });`),
    ).toEqual(['afterEach → rmSync']);
  });

  // The index used to be file-wide, so any function sharing the name was followed.
  it('respects scope when two describes declare the same name', () => {
    expect(
      removals(`
        describe('scan', () => {
          let target = '';
          const reset = () => { removeTree(target); };
          it('scans', () => { reset(); });
        });
        describe('settings', () => {
          const reset = () => { resetSingleton(); };
          afterEach(() => { reset(); });
        });
      `),
    ).toEqual([]);
  });

  it('does not treat a method named rm on some other object as fs', () => {
    expect(removals(`afterEach(async () => { await client.rm(pointer, reason); });`)).toEqual([]);
  });

  // A local `rm` is a function like any other: followed into, and not taken for
  // node:fs just because of its name. This one removes nothing.
  it('follows a local function named rm instead of assuming it is fs', () => {
    expect(
      removals(`
        function rm(a: string, b: string): void { log(a, b); }
        afterEach(() => { rm(home, reason); });
      `),
    ).toEqual([]);
  });

  it('does not run a callback handed to a mock installer', () => {
    expect(
      removals(`afterEach(() => {
        resetSingleton();
        vi.mocked(fsHelpers.purge).mockImplementation((d) => removeTree(d));
      });`),
    ).toEqual([]);
  });

  it('does not count a parameter that shadows a wrapper', () => {
    expect(
      removals(`
        const cleanup = () => removeTree(home);
        afterEach(() => { run((cleanup: () => void) => cleanup); });
      `),
    ).toEqual([]);
  });
});

describe('scanTeardowns — redirect shapes the first parser-based version missed', () => {
  const redirects = (text: string, files: Record<string, string> = {}): boolean =>
    scanTeardowns(SUITE, text, host(files)).redirectsHome;

  it('sees a mock factory that hands off to a helper naming homedir', () => {
    expect(
      redirects(
        `import { osWithHome } from '../helpers/os.ts';
        vi.mock('node:os', async (importActual) => osWithHome(await importActual(), osHome));`,
        {
          '/virtual/web-ui/test/helpers/os.ts': `export function osWithHome(actual, box) { return { ...actual, homedir: () => box.dir }; }`,
        },
      ),
    ).toBe(true);
  });

  it('sees the typed import() form of the module argument', () => {
    expect(
      redirects(`vi.mock(import('node:os'), async (importOriginal) => {
        const actual = await importOriginal();
        return { ...actual, homedir: () => osHome.dir };
      });`),
    ).toBe(true);
  });

  it('sees an automock pointed somewhere through vi.mocked', () => {
    expect(
      redirects(`import * as os from 'node:os';
        vi.mock('node:os', { spy: true });
        beforeEach(() => { vi.mocked(os.homedir).mockReturnValue(home); });`),
    ).toBe(true);
  });

  it('does not count a helper call in a factory that never names homedir', () => {
    expect(
      redirects(
        `import { osWithTmp } from '../helpers/os.ts';
        vi.mock('node:os', async (importActual) => osWithTmp(await importActual()));`,
        {
          '/virtual/web-ui/test/helpers/os.ts': `export function osWithTmp(actual) { return { ...actual, tmpdir: () => '/t' }; }`,
        },
      ),
    ).toBe(false);
  });
});
