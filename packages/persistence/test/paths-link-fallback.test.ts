import type * as FsModule from 'node:fs';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The no-hard-link fallback inside publishByLink, which nothing else reaches.
//
// It needs its own file because the seam is a `vi.mock` of `node:fs`, which is
// file-scoped — and it has to be that rather than an assignment to the default
// export's property, which is the obvious thing and does not work: `paths.ts`
// binds `linkSync` through a NAMED import, so patching `fsModule.linkSync`
// leaves it pointing at the real syscall. A test written that way still passes
// every assertion below, because the real `link` succeeds and then reports
// EEXIST on the second call — the fallback is never entered and the suite goes
// green having proved nothing. `linkControl.fired` is the guard against exactly
// that: every case asserts the interception actually happened.
const linkControl = vi.hoisted(() => ({ code: '', fired: 0 }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof FsModule>();
  const linkSyncMaybeUnsupported = ((...args: Parameters<typeof actual.linkSync>) => {
    if (linkControl.code) {
      linkControl.fired += 1;
      const err = new Error(`${linkControl.code} (simulated)`) as NodeJS.ErrnoException;
      err.code = linkControl.code;
      throw err;
    }
    actual.linkSync(...args);
  }) as typeof actual.linkSync;
  return { ...actual, linkSync: linkSyncMaybeUnsupported };
});

const { createOwnerOnlyFileSync, DATA_FILE_MODE } = await import('../src/paths.ts');

// Pinned by hand rather than imported from the source. Deriving it from the set
// under test would make a DELETION invisible — drop ENOTSUP there and the loop
// would simply stop driving it, staying green while macOS on exFAT regressed to
// "cannot mint a key at all". These are the codes a filesystem that cannot
// hard-link is known to report.
const LINK_UNSUPPORTED_CODES = ['EPERM', 'ENOSYS', 'ENOTSUP', 'EOPNOTSUPP', 'EINVAL'];

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-link-fallback-'));
  linkControl.code = '';
  linkControl.fired = 0;
});

afterEach(() => {
  linkControl.code = '';
  rmSync(base, { recursive: true, force: true });
});

const file = (): string => join(base, 'exception.key');

describe('createOwnerOnlyFileSync where hard links are unavailable', () => {
  // A code missing from the set makes createOwnerOnlyFileSync RETHROW, so this
  // case goes red by throwing rather than by a failed assertion — which is the
  // whole point: it is what turns that hand-maintained set into something CI
  // enforces. ENOTSUP is the one measured on macOS/exFAT.
  it.for(LINK_UNSUPPORTED_CODES)('falls back to an exclusive create on %s', (code) => {
    linkControl.code = code;

    const created = createOwnerOnlyFileSync(file(), 'first\n');

    // The positive control: without it, a seam that silently stopped
    // intercepting would leave every assertion here passing on the link path.
    expect(linkControl.fired).toBe(1);
    expect(created).toBe(true);
    expect(readFileSync(file(), 'utf8')).toBe('first\n');
  });

  it('still picks exactly one winner, and leaves the incumbent untouched', () => {
    linkControl.code = 'ENOTSUP';

    expect(createOwnerOnlyFileSync(file(), 'first\n')).toBe(true);
    expect(createOwnerOnlyFileSync(file(), 'second\n')).toBe(false);

    expect(linkControl.fired).toBe(2);
    expect(readFileSync(file(), 'utf8')).toBe('first\n');
  });

  it('strands no tmp on either outcome', () => {
    linkControl.code = 'ENOTSUP';

    createOwnerOnlyFileSync(file(), 'first\n');
    createOwnerOnlyFileSync(file(), 'second\n');

    expect(linkControl.fired).toBe(2);
    expect(readdirSync(base).sort()).toEqual(['exception.key']);
  });

  it.skipIf(process.platform === 'win32')('still writes the file owner-only', () => {
    linkControl.code = 'ENOTSUP';

    createOwnerOnlyFileSync(file(), 'data\n');

    expect(linkControl.fired).toBe(1);
    expect(statSync(file()).mode & 0o777).toBe(DATA_FILE_MODE);
  });

  it('rethrows a link failure that does NOT mean "cannot hard-link"', () => {
    // The counterpart to the list above: the fallback is for a filesystem
    // without hard links, not a way to swallow every link error. EACCES is a
    // real failure and must reach the caller rather than being written around.
    linkControl.code = 'EACCES';

    const err = errorFrom(() => createOwnerOnlyFileSync(file(), 'first\n'));

    expect(linkControl.fired).toBe(1);
    expect((err as NodeJS.ErrnoException | undefined)?.code).toBe('EACCES');
    expect(readdirSync(base)).toEqual([]);
  });
});

// The error a thunk threw, captured OUTSIDE its own catch — a try/catch in the
// test body asserts on the test's own guard error when the call stops throwing.
function errorFrom(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return undefined;
}
