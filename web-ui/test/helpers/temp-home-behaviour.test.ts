import { existsSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { tempHomes } from './temp-home.ts';

// The guard exempts tempHomes() from the rule every other suite follows, on the
// strength of two properties of its teardown: it removes when the FILE (here, the
// describe) finishes rather than after each test, and it releases the store
// before it removes anything. Nothing else pins either one. A change to either
// would reintroduce the Windows failure in every suite that relies on it, and the
// guard would stay green, since it does not read the exempted body.
//
// Both are pinned by behaviour rather than by reading the source. The store
// handle is a stand-in whose `close` records whether the directory still exists
// at that moment — which is what makes the ORDER observable on POSIX, where the
// removal would succeed either way.

const cache = globalThis as unknown as { __akaDb?: { close(): void } };

let dir = '';
let existedAtRelease: boolean | undefined;

describe('a describe using tempHomes', () => {
  const newDir = tempHomes('aka-temp-home-behaviour-');

  it('hands out a directory that exists', () => {
    dir = newDir();
    expect(existsSync(dir)).toBe(true);
    cache.__akaDb = {
      close() {
        existedAtRelease = existsSync(dir);
      },
    };
  });

  it('keeps it through the next test, rather than removing after each one', () => {
    expect(existsSync(dir)).toBe(true);
    expect(existedAtRelease).toBeUndefined();
  });
});

describe('once that describe has finished', () => {
  it('released the store while the directory was still there, then removed it', () => {
    expect(existedAtRelease).toBe(true);
    expect(cache.__akaDb).toBeUndefined();
    expect(existsSync(dir)).toBe(false);
  });
});
