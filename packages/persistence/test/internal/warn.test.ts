import { describe, expect, it, vi } from 'vitest';

import { akaWarn } from '../../src/internal/warn.ts';

describe('akaWarn', () => {
  it('writes exactly one [aka]-prefixed, newline-terminated line to stderr', () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      akaWarn('detection pack update failed');
      expect(write).toHaveBeenCalledTimes(1);
      expect(write).toHaveBeenCalledWith('[aka] detection pack update failed\n');
    } finally {
      write.mockRestore();
    }
  });
});
