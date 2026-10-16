import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { collectFiles } from '../src/fs-scan.ts';

// Eighty levels stays well inside a Windows path limit while being far deeper
// than any constant number of frames.
const DEPTH = 80;

function stackFrames(): number {
  const limit = Error.stackTraceLimit;
  Error.stackTraceLimit = Number.POSITIVE_INFINITY;
  try {
    return (new Error().stack ?? '').split('\n').length;
  } finally {
    Error.stackTraceLimit = limit;
  }
}

describe('collectFiles — call stack depth', () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aka-fs-scan-stack-'));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('does not grow the call stack with the depth of the tree', () => {
    let deepest = tmp;
    for (let level = 0; level < DEPTH; level++) deepest = join(deepest, 'd');
    mkdirSync(join(tmp, 'd', '.git'), { recursive: true });
    mkdirSync(join(deepest, '.git'), { recursive: true });
    writeFileSync(join(deepest, 'leaf.ts'), 'export {};\n');

    const frames = new Map<number, number>();
    const walked = [
      ...collectFiles(tmp, {
        home: tmp,
        akaHome: join(tmp, 'aka-home'),
        onNestedRepository: (dir) => {
          frames.set(relative(tmp, dir).split(sep).length, stackFrames());
        },
      }),
    ];
    expect(walked.length).toBeGreaterThan(0);

    const shallow = frames.get(1);
    const deep = frames.get(DEPTH);
    expect(shallow).toBeDefined();
    expect(deep).toBeDefined();
    expect((deep ?? 0) - (shallow ?? 0)).toBeLessThan(10);
  });
});
