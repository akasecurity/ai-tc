import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { akaWarn } from '../src/internal/warn.ts';
import { tightenFile } from '../src/paths.ts';

// Mock the warn channel so we can assert it fires exactly once, without leaning
// on vitest's per-test process.stderr capture (a raw stderr spy is swallowed in a
// multi-test file). Hoisted above the imports by vitest, so paths.ts's own
// `akaWarn` import resolves to this mock too.
vi.mock('../src/internal/warn.ts', () => ({ akaWarn: vi.fn() }));

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-warn-'));
  vi.mocked(akaWarn).mockClear();
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('chmodBestEffort warn dedupe', () => {
  it('surfaces a genuine (non-ENOENT) chmod failure exactly once per path, not on every call', () => {
    if (process.platform === 'win32') return;
    // Fault injection: chmod a path whose parent is a FILE → ENOTDIR (a real
    // failure, distinct from the benign ENOENT / win32 cases). On a filesystem
    // that rejects chmod this is what every hook would hit; it must warn once,
    // then dedupe, rather than spamming stderr per hook.
    const notADir = join(base, 'afile');
    writeFileSync(notADir, '');
    const target = join(notADir, 'settings.json');

    tightenFile(target);
    tightenFile(target);
    tightenFile(target);

    expect(vi.mocked(akaWarn)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(akaWarn).mock.calls[0]?.[0]).toContain('could not set owner-only permissions');
  });

  it('does not warn on the benign ENOENT case (an absent parent)', () => {
    tightenFile(join(base, 'nope', 'missing.json'));
    expect(vi.mocked(akaWarn)).not.toHaveBeenCalled();
  });
});
