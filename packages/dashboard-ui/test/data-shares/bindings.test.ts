import { describe, expect, it, vi } from 'vitest';

import { bindId, bindTwoIds } from '../../src/data-shares/bindings.ts';

describe('bindId', () => {
  it('returns a closure that calls fn with the bound id', () => {
    const fn = vi.fn();
    const bound = bindId(fn, 'dest-1');
    expect(fn).not.toHaveBeenCalled();
    bound();
    expect(fn).toHaveBeenCalledExactlyOnceWith('dest-1');
  });
});

describe('bindTwoIds', () => {
  it('returns a closure that calls fn with both bound ids', () => {
    const fn = vi.fn();
    const bound = bindTwoIds(fn, 'dest-1', 'ep-1');
    bound();
    expect(fn).toHaveBeenCalledExactlyOnceWith('dest-1', 'ep-1');
  });
});
