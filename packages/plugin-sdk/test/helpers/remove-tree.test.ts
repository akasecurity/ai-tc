// The suite for `test/helpers/remove-tree.ts`, which sits at the repo root
// because nine packages' teardowns share it. It lives HERE rather than beside
// that file because the repo root is not a workspace package: `turbo run test`
// runs per-package scripts, so a root-level suite would be run by nothing, and
// it would sit outside both the no-network setupFile every package wires and
// the guard that enumerates vitest packages.
//
// Four properties are load-bearing, and none of them is observable from a call
// site — a caller sees a tree removed either way, so the retry, the platform
// split and the code set could each be weakened with all 35 callers staying
// green. That is what this file exists to stop.
//
// `node:fs` is mocked wholesale: the helper imports `rmSync` alone, and the
// point is to drive the branch on an error the real filesystem will not produce
// on demand. That the helper really removes a tree is covered by every one of
// those callers.
import { rmSync } from 'node:fs';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';

vi.mock('node:fs', () => ({ rmSync: vi.fn() }));

// Captured as a descriptor rather than a value: `process.platform` is a
// non-writable own property, so the stub has to redefine it and the restore has
// to put the original definition back, not merely assign the old string.
const realPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
if (!realPlatform) {
  // Refuse rather than restore nothing: a stub that is never undone leaks a
  // fake platform into every suite sharing this worker.
  throw new Error('process.platform has no own property descriptor to restore');
}

function stubPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, 'platform', { value, configurable: true });
}

function rmSyncThrows(code: string): void {
  vi.mocked(rmSync).mockImplementation(() => {
    throw Object.assign(new Error(`rmSync failed: ${code}`), { code });
  });
}

afterEach(() => {
  Object.defineProperty(process, 'platform', realPlatform);
  vi.mocked(rmSync).mockReset();
});

describe('removeTree', () => {
  it('asks rmSync to retry rather than removing once', () => {
    removeTree('/tmp/aka-test');

    // The retry window is the whole point on Windows: a handle on its way out
    // clears in milliseconds, so a single attempt fails a test whose assertions
    // have already passed.
    expect(vi.mocked(rmSync)).toHaveBeenCalledWith('/tmp/aka-test', {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 50,
    });
  });

  it.each(['EPERM', 'EBUSY', 'EACCES', 'ENOTEMPTY'])(
    'tolerates %s on win32, leaving the tree to the OS temp sweeper',
    (code) => {
      stubPlatform('win32');
      rmSyncThrows(code);

      expect(() => {
        removeTree('/tmp/aka-test');
      }).not.toThrow();
    },
  );

  it('still throws on win32 for an error carrying no code at all', () => {
    stubPlatform('win32');
    vi.mocked(rmSync).mockImplementation(() => {
      throw new Error('rmSync failed with no code');
    });

    // This pins the OUTCOME — a codeless error is not a handle on its way out,
    // so it rethrows — not any particular guard producing it. There is no
    // `code === undefined` check to cover: a miss on the set already rethrows,
    // which is why the helper carries none. What this case does catch is
    // `undefined` being admitted to STILL_HELD.
    expect(() => {
      removeTree('/tmp/aka-test');
    }).toThrow('no code');
  });

  it('still throws on win32 for a code outside the still-held set', () => {
    stubPlatform('win32');
    rmSyncThrows('ENOSPC');

    // A full disk is not a handle on its way out. Swallowing every win32 error
    // would turn this helper into a silent `catch {}`.
    expect(() => {
      removeTree('/tmp/aka-test');
    }).toThrow('ENOSPC');
  });

  it.each(['EPERM', 'EBUSY', 'EACCES', 'ENOTEMPTY'])(
    'still throws %s on POSIX, where it means a cleanup did not run',
    (code) => {
      stubPlatform('linux');
      rmSyncThrows(code);

      // POSIX unlinks an open file happily, so these codes here are a defect in
      // the test — a store left unclosed — not a property of the platform.
      expect(() => {
        removeTree('/tmp/aka-test');
      }).toThrow(code);
    },
  );
});
