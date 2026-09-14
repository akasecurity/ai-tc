import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { type ScanOptions, scanTeardowns, type SourceHost } from './teardown-removals.ts';

// The detector behind the temp-home guard, driven with source it has never seen.
//
// The guard over the real tree can only prove what the tree happens to contain
// today. These cases pin each SHAPE, so a change that stops recognising one goes
// red here even while the tree is clean — which is the state the guard spends
// almost all of its life in, and the state in which a blind spot is invisible.
//
// Most of the shapes below were found by adversarial passes that wrote teardowns
// designed to slip past an earlier version, ran them against it, and got through.
//
// Sources are template strings, not files: a call inside a string is not a call
// in the syntax tree, so this file is never mistaken for a suite doing any of it.

const SUITE = '/virtual/web-ui/test/pages/suite.test.ts';
const SANCTIONED = { file: '/virtual/web-ui/test/helpers/temp-home.ts', name: 'tempHomes' };

// Keyed through `resolve()`, the same way the scan resolves an import. On
// Windows `resolve()` turns '/virtual/…' into 'C:\\virtual\\…', and a map keyed by
// the raw POSIX spelling would miss every lookup — which is how seven of these
// cases once passed everywhere except the Windows leg.
function host(files: Record<string, string> = {}): SourceHost {
  const table = new Map(Object.entries(files).map(([path, text]) => [resolve(path), text]));
  return { read: (path) => table.get(resolve(path)) };
}

function options(files: Record<string, string> = {}): ScanOptions {
  return { host: host(files), sanctioned: SANCTIONED };
}

function removals(text: string, files: Record<string, string> = {}): string[] {
  return scanTeardowns(SUITE, text, options(files)).removals.map((r) => r.path);
}

function hooks(text: string, files: Record<string, string> = {}): number {
  return scanTeardowns(SUITE, text, options(files)).hooks;
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

  it('counts spread options it cannot read as recursive', () => {
    expect(removals(`afterEach(() => { rmSync(home, { ...options }); });`)).toEqual([
      'afterEach → rmSync',
    ]);
  });

  it('reads a const options object that does say recursive', () => {
    expect(
      removals(
        `const WIPE = { recursive: true, force: true };\nafterEach(() => { rmSync(home, WIPE); });`,
      ),
    ).toEqual(['afterEach → rmSync']);
  });

  it('reads recursive written as a quoted computed key', () => {
    expect(removals(`afterEach(() => { rmSync(home, { ['recursive']: true }); });`)).toEqual([
      'afterEach → rmSync',
    ]);
  });

  it('counts a getter named recursive, and a computed key it cannot read, as recursive', () => {
    expect(
      removals(`afterEach(() => {
        rmSync(a, { get recursive() { return true; } });
        rmSync(b, { [flag]: true });
      });`),
    ).toEqual(['afterEach → rmSync', 'afterEach → rmSync']);
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

  it('sees an fs remover destructured from the fs namespace', () => {
    expect(
      removals(`import * as nodeFs from 'node:fs';
        const { rmSync } = nodeFs;
        afterEach(() => { rmSync(home, { recursive: true, force: true }); });`),
    ).toEqual(['afterEach → rmSync']);
  });
});

describe('scanTeardowns — what counts as a teardown', () => {
  it('sees onTestFinished, including from a destructured test context', () => {
    expect(
      removals(`
        beforeEach(() => { onTestFinished(() => { removeTree(home); }); });
        it('x', ({ onTestFailed }) => { onTestFailed(() => removeTree(home)); });
      `),
    ).toEqual(['onTestFinished → removeTree', 'onTestFailed → removeTree']);
  });

  it('sees aroundEach and aroundAll', () => {
    expect(
      removals(`
        aroundEach(async (runTest) => { await runTest(); removeTree(home); });
        aroundAll(async (runSuite) => { await runSuite(); removeTree(root); });
      `),
    ).toEqual(['aroundEach → removeTree', 'aroundAll → removeTree']);
  });

  it('sees hooks called on an extended test, and through a vitest namespace', () => {
    expect(
      removals(`import * as vt from 'vitest';
        const test = base.extend({});
        test.afterEach(() => { removeTree(a); });
        vt.afterAll(() => { removeTree(b); });`),
    ).toEqual(['afterEach → removeTree', 'afterAll → removeTree']);
  });

  it('sees an aliased hook imported from vitest', () => {
    expect(
      removals(
        `import { afterEach as teardown } from 'vitest';\nteardown(() => { removeTree(home); });`,
      ),
    ).toEqual(['afterEach → removeTree']);
  });

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

  it('sees the teardown a named setup function returns', () => {
    expect(
      removals(`
        function setupHome() { osHome.dir = make(); return () => removeTree(osHome.dir); }
        beforeEach(setupHome);
      `),
    ).toEqual(['beforeEach teardown → removeTree']);
  });

  it('sees the disposer a helper returns to a setup hook, locally and imported', () => {
    expect(
      removals(
        `import { useHome } from '../helpers/home.ts';
        const useScratch = () => { const d = make(); return () => removeTree(d); };
        beforeEach(() => useHome(osHome));
        beforeAll(async () => { await seed(); return useScratch(); });`,
        {
          '/virtual/web-ui/test/helpers/home.ts': `export function useHome(box) { box.dir = make(); return () => removeTree(box.dir); }`,
        },
      ),
    ).toEqual(['beforeEach teardown → removeTree', 'beforeAll teardown → removeTree']);
  });

  it('ignores a setup hook that returns something that is not a function', () => {
    const scan = scanTeardowns(SUITE, `beforeEach(() => (osHome.dir = newHome()));`, options());
    expect(scan).toMatchObject({ hooks: 0, removals: [] });
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

  it('sees fixtures by name, in shorthand, in a tuple, and in a const object', () => {
    expect(
      removals(`
        async function home({}, use) { const d = make(); await use(d); removeTree(d); }
        const t1 = base.extend({ home });
        const t2 = base.extend({ h2: [home, { scope: 'file' }] });
        const t3 = base.extend({ h3: home });
        const fixtures = { h4: async ({}, use) => { await use(1); removeTree(x); } };
        const t4 = base.extend(fixtures);
      `),
    ).toEqual([
      'fixture home → removeTree',
      'fixture h2 → removeTree',
      'fixture h3 → removeTree',
      'fixture h4 → removeTree',
    ]);
  });

  // A "release, then run my cleanup" wrapper is the obvious thing to factor out
  // of the suites this guard moved. What its callback removes is decided at each
  // call site, which the scan does not connect to the hook inside the wrapper, so
  // the hook is reported as running a callback it cannot see — at the wrapper,
  // whether local or in a helper, and however deep the registration sits.
  it('reports a teardown that runs a callback handed in from outside', () => {
    const found = removals(
      `import { afterEachReleased } from '../helpers/hooks.ts';
      function afterAllReleased(fn: () => void) { afterAll(async () => { await release(); fn(); }); }
      afterEachReleased(() => removeTree(home));
      afterAllReleased(() => removeTree(root));`,
      {
        '/virtual/web-ui/test/helpers/hooks.ts': `function register(fn: () => void) { afterEach(async () => { await release(); fn(); }); }
          export function afterEachReleased(fn: () => void) { register(fn); }`,
      },
    );
    expect(found).toHaveLength(2);
    expect(found[0]).toMatch(/^afterAll → fn\(\) — a callback handed in from outside/);
    expect(found[1]).toMatch(
      /^helpers\/hooks\.ts → afterEach → fn\(\) — a callback handed in from outside/,
    );
  });

  // The shape the old wrapper rule got wrong the other way: a describe-level
  // wrapper that adds its own release and then runs the body it was given. The
  // body's removal is inside a test, not a teardown, and the release runs no
  // callback it was handed.
  it('does not read a wrapped describe body as a teardown', () => {
    const scan = scanTeardowns(
      SUITE,
      `function describeWithStore(name: string, body: () => void) {
        afterEach(() => { dropMemoisedDb(); });
        describe(name, body);
      }
      describeWithStore('x', () => { it('removes in a test', () => { removeTree(scratch); }); });`,
      options(),
    );
    expect(scan).toMatchObject({ hooks: 1, removals: [] });
  });

  // A teardown's own parameters, and a helper's own callback, are not handed in
  // from outside: the callback a helper runs is read where it is written.
  it('does not report a teardown calling its own parameter, or a helper its own callback', () => {
    expect(
      removals(`
        function run(cb: () => void): void { cb(); }
        aroundEach(async (runTest) => { await runTest(); });
        afterEach(() => { run(() => resetSingleton()); });
        afterAll(() => { run(() => removeTree(root)); });
      `),
    ).toEqual(['afterAll → removeTree']);
  });
});

describe('scanTeardowns — teardowns that live in a helper module', () => {
  // Built like tempHomes(), but removing per test and without releasing first.
  it('sees a teardown a helper imported from a test directory registers', () => {
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
    ).toEqual(['helpers/home.ts → afterEach → removeTree']);
  });

  it('sees one registered by a private function inside the helper', () => {
    expect(
      removals(
        `import { tempHomeEach } from '../helpers/home.ts';\nconst newHome = tempHomeEach('x');`,
        {
          '/virtual/web-ui/test/helpers/home.ts': `function install(dirs: string[]) { afterEach(() => { removeTrees(dirs.splice(0)); }); }
            export function tempHomeEach(p: string) { const dirs: string[] = []; install(dirs); return () => make(p); }`,
        },
      ),
    ).toEqual(['helpers/home.ts → afterEach → removeTrees']);
  });

  it('sees one behind an export * barrel', () => {
    expect(
      removals(
        `import { tempHomeEach } from '../helpers/index.ts';\nconst newHome = tempHomeEach('x');`,
        {
          '/virtual/web-ui/test/helpers/index.ts': `export * from './home.ts';`,
          '/virtual/web-ui/test/helpers/home.ts': `export function tempHomeEach(p: string) { afterEach(() => { removeTree(d); }); return () => d; }`,
        },
      ),
    ).toEqual(['helpers/home.ts → afterEach → removeTree']);
  });

  it('sees one in a suite body handed to describe by reference', () => {
    expect(
      removals(`import { homeSuite } from '../helpers/suite.ts';\ndescribe('home', homeSuite);`, {
        '/virtual/web-ui/test/helpers/suite.ts': `export function homeSuite() { afterEach(() => { removeTree(home); }); }`,
      }),
    ).toEqual(['helpers/suite.ts → afterEach → removeTree']);
  });

  it('sees a fixture defined on a shared test in a helper', () => {
    expect(
      removals(
        `import { test } from '../helpers/fixtures.ts';\ntest('renders', ({ home }) => { osHome.dir = home; });`,
        {
          '/virtual/web-ui/test/helpers/fixtures.ts': `import { test as base } from 'vitest';
            export const test = base.extend({ home: async ({}, use) => { const d = make(); await use(d); removeTree(d); } });`,
        },
      ),
    ).toEqual(['helpers/fixtures.ts → fixture home → removeTree']);
  });

  it('reports the line of the import that brings the helper in', () => {
    const [removal] = scanTeardowns(
      SUITE,
      `\nimport { tempHomeEach } from '../helpers/home.ts';\nconst h = tempHomeEach('x');`,
      options({
        '/virtual/web-ui/test/helpers/home.ts': `export function tempHomeEach() { afterAll(() => removeTree(d)); }`,
      }),
    ).removals;
    expect(removal?.line).toBe(2);
  });

  it('does not walk a module outside a test directory for hooks', () => {
    expect(
      removals(`import { render } from '../../app/page.tsx';\nrender();`, {
        '/virtual/web-ui/app/page.tsx': `export function render() { afterEach(() => removeTree(d)); }`,
      }),
    ).toEqual([]);
  });
});

describe('scanTeardowns — the sanctioned tempHomes', () => {
  const helper = `export function tempHomes(prefix: string) {
    afterAll(async () => { await releaseLocalStore(); removeTrees(made); });
    return () => make(prefix);
  }`;

  // The sanctioned teardown. Its removal lives inside `tempHomes`, registered
  // when the factory is created — not in anything the suite's hooks call.
  it('accepts a suite on tempHomes', () => {
    expect(
      removals(
        `import { tempHomes } from '../helpers/temp-home.ts';
        const newHome = tempHomes('aka-x-');
        beforeEach(() => { osHome.dir = newHome(); });
        afterEach(() => { resetSingleton(); });`,
        { [SANCTIONED.file]: helper },
      ),
    ).toEqual([]);
  });

  it('exempts it by its exact file, not by a filename that matches', () => {
    expect(
      removals(
        `import { tempHomes } from '../helpers/other-home.ts';\nconst h = tempHomes('a-');`,
        {
          '/virtual/web-ui/test/helpers/other-home.ts': helper,
        },
      ),
    ).toEqual(['helpers/other-home.ts → afterAll → removeTrees']);
    expect(
      removals(
        `import { tempHomes } from '../../../test/helpers/temp-home.ts';\nconst h = tempHomes('a-');`,
        { '/virtual/test/helpers/temp-home.ts': helper },
      ),
    ).toEqual(['helpers/temp-home.ts → afterAll → removeTrees']);
  });

  it('exempts only the named function, not the rest of its file', () => {
    expect(
      removals(`import { tempHomes } from '../helpers/temp-home.ts';\nconst h = tempHomes('a-');`, {
        [SANCTIONED.file]: `${helper}\nexport function sloppy() { afterEach(() => removeTree(d)); }`,
      }),
    ).toEqual(['helpers/temp-home.ts → afterEach → removeTree']);
  });

  // Case-insensitive filesystems (Windows, and macOS by default) resolve an
  // import whatever its casing, so the exemption must too.
  it('matches the exempt file whatever the casing of the import', () => {
    expect(
      removals(`import { tempHomes } from '../Helpers/Temp-Home.ts';\nconst h = tempHomes('a-');`, {
        '/virtual/web-ui/test/Helpers/Temp-Home.ts': helper,
      }),
    ).toEqual([]);
  });

  // The exempt file goes through the same `resolve()` every import does. A
  // spelling that differs only in `..` segments names the same file, and so does
  // one that differs only in the drive letter `resolve()` adds on Windows — which
  // no POSIX run can produce, so this case is what pins the normalisation here.
  it('resolves the exempt file the way it resolves an import', () => {
    const scan = scanTeardowns(
      SUITE,
      `import { tempHomes } from '../helpers/temp-home.ts';\nconst h = tempHomes('a-');`,
      {
        host: host({ [SANCTIONED.file]: helper }),
        sanctioned: {
          file: '/virtual/web-ui/test/pages/../helpers/temp-home.ts',
          name: 'tempHomes',
        },
      },
    );
    expect(scan.removals).toEqual([]);
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

  it('follows a callback wrapped in a cast', () => {
    expect(
      removals(
        `afterEach(() => { dirs.forEach(((d: string) => removeTree(d)) as (d: string) => void); });`,
      ),
    ).toEqual(['afterEach → removeTree']);
  });

  it('sees removeTree handed over by reference', () => {
    expect(removals(`afterEach(() => { [home, target].forEach(removeTree); });`)).toEqual([
      'afterEach → removeTree',
    ]);
  });

  it('follows a function assigned to a let later, including with ??=', () => {
    expect(
      removals(`
        let cleanup: () => void = () => {};
        let other: (() => void) | undefined;
        beforeEach(() => {
          cleanup = () => { resetSingleton(); removeTree(home); };
          other ??= () => removeTree(scratch);
        });
        afterEach(() => { cleanup(); other?.(); });
      `),
    ).toEqual(['afterEach → cleanup → removeTree', 'afterEach → other → removeTree']);
  });

  it('follows a wrapper made with vi.fn', () => {
    expect(
      removals(`
        const cleanup = vi.fn(() => { removeTree(home); });
        afterEach(() => { cleanup(); });
      `),
    ).toEqual(['afterEach → cleanup → removeTree']);
  });

  it('follows the disposer a factory returned, locally and imported', () => {
    expect(
      removals(
        `import { makeHome } from '../helpers/home.ts';
        function makeScratch() { const d = make(); return () => rmSync(d, { recursive: true }); }
        let dispose: () => void;
        const disposeHome = makeHome();
        beforeEach(() => { dispose = makeScratch(); });
        afterEach(() => { dispose(); });
        afterAll(() => disposeHome());`,
        {
          '/virtual/web-ui/test/helpers/home.ts': `export function makeHome() { const dir = make(); return () => removeTree(dir); }`,
        },
      ),
    ).toEqual(['afterEach → dispose → rmSync', 'afterAll → disposeHome → removeTree']);
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

  it('follows a named re-export and an export * barrel', () => {
    expect(
      removals(
        `import { clean, wipe } from '../helpers/index.ts';\nafterAll(() => clean());\nafterEach(() => wipe());`,
        {
          '/virtual/web-ui/test/helpers/index.ts': `export { wipe as clean } from './wipe.ts';\nexport * from './wipe.ts';`,
          '/virtual/web-ui/test/helpers/wipe.ts': `export function wipe(): void { removeTree(dir); }`,
        },
      ),
    ).toEqual(['afterAll → clean → removeTree', 'afterEach → wipe → removeTree']);
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

  // A chain it cannot follow to the end is reported, not passed. Before this, a
  // deep enough chain overflowed the stack and took the whole guard down.
  it('fails closed on a call chain too deep to follow', () => {
    const wrappers = Array.from(
      { length: 1500 },
      (_, i) => `function w${String(i)}(): void { w${String(i + 1)}(); }`,
    ).join('\n');
    const found = removals(
      `${wrappers}\nfunction w1500(): void { removeTree(h); }\nafterEach(() => w0());`,
    );
    expect(found).toHaveLength(1);
    expect(found[0]).toContain('too deep to follow');
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

  it('ignores removal named only in a comment or a string', () => {
    expect(
      removals(`afterEach(() => {
        // removeTree(home) used to live here
        log('rmSync(home, { recursive: true })');
      });`),
    ).toEqual([]);
  });

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

  it('reads an imported const options object that does not say recursive', () => {
    expect(
      removals(
        `import { RM_FILE } from '../helpers/rm.ts';\nafterEach(() => { for (const f of sidecars) rmSync(f, RM_FILE); });`,
        {
          '/virtual/web-ui/test/helpers/rm.ts': `export const RM_FILE = { force: true, maxRetries: 10, retryDelay: 50 };`,
        },
      ),
    ).toEqual([]);
  });

  it('still counts a let options object, which could be anything by then', () => {
    expect(
      removals(`let opts = { force: true };\nafterEach(() => { rmSync(home, opts); });`),
    ).toEqual(['afterEach → rmSync']);
  });

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

  it('does not credit an outer let with an assignment to a shadowing inner one', () => {
    expect(
      removals(`
        let cleanup = () => {};
        describe('a', () => {
          let cleanup: () => void;
          beforeEach(() => { cleanup = () => removeTree(scratch); });
          it('x', () => cleanup());
        });
        afterEach(() => cleanup());
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

  it('does not treat removeTree named in an inspection as running it', () => {
    expect(
      removals(`afterEach(() => {
        vi.mocked(removeTree).mockReset();
        expect(removeTrees).not.toHaveBeenCalled();
      });`),
    ).toEqual([]);
  });

  it('does not take custom matchers in expect.extend for fixtures', () => {
    const scan = scanTeardowns(
      SUITE,
      `expect.extend({ toBeCleanable(dir) { rmSync(dir, { recursive: true }); return { pass: true, message: () => '' }; } });`,
      options(),
    );
    expect(scan).toMatchObject({ hooks: 0, removals: [] });
  });

  // The call to `cleanup` really runs here — forEach invokes the callback — so
  // the only thing standing between it and the outer wrapper is the parameter
  // that shadows it. The control below is the same shape without the parameter,
  // which proves that is what the first case is testing.
  it('does not follow a name a parameter shadows', () => {
    expect(
      removals(`
        const cleanup = () => removeTree(home);
        afterEach(() => { [noop].forEach((cleanup) => cleanup()); });
      `),
    ).toEqual([]);
  });

  it('does follow the same call when nothing shadows it', () => {
    expect(
      removals(`
        const cleanup = () => removeTree(home);
        afterEach(() => { [noop].forEach((fn) => cleanup()); });
      `),
    ).toEqual(['afterEach → cleanup → removeTree']);
  });
});

describe('scanTeardowns — hook count', () => {
  // What lets the guard tell "these suites remove nothing" from "the parse saw
  // no hooks": a blind scan reports zero hooks, not merely zero removals.
  it('counts teardowns at any depth, and only teardowns', () => {
    expect(
      hooks(`
        beforeEach(() => {});
        afterEach(() => {});
        describe('x', () => {
          afterAll(() => {});
          describe('y', () => { afterEach(() => {}); aroundEach(async (run) => { await run(); }); });
        });
      `),
    ).toBe(4);
  });

  it('reports the hook line', () => {
    const [removal] = scanTeardowns(
      SUITE,
      `\n\nafterAll(() => removeTree(home));`,
      options(),
    ).removals;
    expect(removal).toEqual({ hook: 'afterAll', line: 3, path: 'afterAll → removeTree' });
  });
});
