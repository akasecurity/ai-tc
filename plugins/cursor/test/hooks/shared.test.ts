/**
 * The stdio wrapper every hook entry delegates its fail-open contract to, and
 * the capture-attribution helpers.
 *
 * `runHookFailOpen` ends in `process.exit(0)`, so `exit` and `stdout.write`
 * are stubbed; the real emit, race and watchdog run. Each silence case is
 * paired with a case that writes, so an absence is told apart from a harness
 * that sees nothing.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';
import {
  callScopeKey,
  captureScopeKey,
  countFailOpen,
  denyOutput,
  emit,
  parseJson,
  runHookFailOpen,
  spawnFailOpenCount,
  writeNotice,
} from '../../src/hooks/shared.ts';

const DENY: HookOutput = denyOutput('seam');

interface WrapperRun {
  writes: string[];
  exits: (number | undefined)[];
  counts: number;
}

async function driveWrapper(
  main: () => Promise<HookOutput | undefined>,
  failOpen?: HookOutput,
  watchdogMs?: number,
): Promise<WrapperRun> {
  const writes: string[] = [];
  const exits: (number | undefined)[] = [];
  let counts = 0;
  const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((
    code?: string | number | null,
  ): undefined => {
    exits.push(typeof code === 'number' ? code : undefined);
    return undefined;
  }) as unknown as (code?: string | number | null) => never);
  const writeSpy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array, cb?: unknown): boolean => {
      writes.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
      if (typeof cb === 'function') (cb as () => void)();
      return true;
    });
  const listenersBefore = new Set(process.stdout.listeners('error'));
  try {
    await runHookFailOpen(main, failOpen, watchdogMs, () => {
      counts += 1;
    });
  } finally {
    writeSpy.mockRestore();
    exitSpy.mockRestore();
    for (const listener of process.stdout.listeners('error')) {
      if (!listenersBefore.has(listener)) {
        process.stdout.off('error', listener as (...args: unknown[]) => void);
      }
    }
  }
  return { writes, exits, counts };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('runHookFailOpen', () => {
  it('emits the body’s decision as one JSON object and exits 0', async () => {
    const run = await driveWrapper(() => Promise.resolve(DENY));
    expect(run.writes.map((w) => JSON.parse(w) as unknown)).toEqual([DENY]);
    expect(run.exits).toEqual([0]);
    expect(run.counts).toBe(0);
  });

  it('writes nothing and exits 0 when the body declines', async () => {
    const run = await driveWrapper(() => Promise.resolve(undefined));
    expect(run.writes).toEqual([]);
    expect(run.exits).toEqual([0]);
    expect(run.counts).toBe(0);
  });

  it('writes nothing, exits 0 and counts a fail-open when the body throws', async () => {
    const run = await driveWrapper(() => Promise.reject(new Error('boom')));
    expect(run.writes).toEqual([]);
    expect(run.exits).toEqual([0]);
    expect(run.counts).toBe(1);
  });

  it('writes nothing, exits 0 and counts a fail-open when the body outruns the watchdog', async () => {
    const run = await driveWrapper(
      () => new Promise<HookOutput | undefined>(() => undefined),
      undefined,
      5,
    );
    expect(run.writes).toEqual([]);
    expect(run.exits).toEqual([0]);
    expect(run.counts).toBe(1);
  });

  it('writes the given fail-open payload when the body throws', async () => {
    const run = await driveWrapper(() => Promise.reject(new Error('boom')), DENY);
    expect(run.writes.map((w) => JSON.parse(w) as unknown)).toEqual([DENY]);
  });

  it('still exits 0 when stdout throws', async () => {
    const exits: (number | undefined)[] = [];
    vi.spyOn(process, 'exit').mockImplementation(((code?: number): undefined => {
      exits.push(code);
      return undefined;
    }) as unknown as (code?: string | number | null) => never);
    vi.spyOn(process.stdout, 'write').mockImplementation(() => {
      throw new Error('EPIPE');
    });
    await runHookFailOpen(
      () => Promise.resolve(DENY),
      undefined,
      undefined,
      () => {
        throw new Error('count failed');
      },
    );
    expect(exits).toEqual([0]);
  });
});

describe('emit', () => {
  it('resolves when stdout reports an error instead of flushing', async () => {
    let onError: (() => void) | undefined;
    vi.spyOn(process.stdout, 'on').mockImplementation(((event: string, fn: () => void) => {
      if (event === 'error') onError = fn;
      return process.stdout;
    }) as never);
    vi.spyOn(process.stdout, 'write').mockImplementation(() => {
      onError?.();
      return false;
    });
    await expect(emit(DENY)).resolves.toBeUndefined();
  });
});

describe('writeNotice', () => {
  it('writes the message with a newline', () => {
    const written: string[] = [];
    writeNotice('hello', (text) => written.push(text));
    expect(written).toEqual(['hello\n']);
  });

  it('swallows a writer that throws', () => {
    expect(() => {
      writeNotice('hello', () => {
        throw new Error('closed');
      });
    }).not.toThrow();
  });
});

describe('the fail-open tally', () => {
  it('countFailOpen swallows a counter that throws', () => {
    expect(() => {
      countFailOpen(() => {
        throw new Error('no');
      });
    }).not.toThrow();
  });

  it('spawnFailOpenCount survives a script that does not exist', () => {
    const root = mkdtempSync(join(tmpdir(), 'aka-cursor-count-'));
    try {
      expect(() => {
        spawnFailOpenCount(pathToFileURL(join(root, 'missing.js')));
      }).not.toThrow();
    } finally {
      removeTrees([root]);
    }
  });
});

describe('parseJson', () => {
  it('accepts an object and nothing else', () => {
    expect(parseJson('{"a":1}')).toEqual({ a: 1 });
    expect(parseJson('[1]')).toBeNull();
    expect(parseJson('null')).toBeNull();
    expect(parseJson('nope')).toBeNull();
  });
});

describe('scope keys', () => {
  it('attribute a file write to the file’s own repository and other calls to cwd', () => {
    const root = mkdtempSync(join(tmpdir(), 'aka-cursor-scope-'));
    try {
      const cwd = join(root, 'a');
      const other = join(root, 'b');
      for (const [dir, remote] of [
        [cwd, 'https://example.test/a.git'],
        [other, 'https://example.test/b.git'],
      ] as const) {
        mkdirSync(dir);
        execFileSync('git', ['init', '-q', dir]);
        execFileSync('git', ['-C', dir, 'remote', 'add', 'origin', remote]);
      }
      const input = { cwd };
      const byCwd = captureScopeKey(input);
      expect(byCwd).toBeDefined();
      expect(captureScopeKey(input, join(other, 'f.txt'))).not.toBe(byCwd);
      expect(
        callScopeKey('code_change', input, {
          name: 'Write',
          args: { file_path: join(other, 'f.txt') },
        }),
      ).toBe(captureScopeKey(input, join(other, 'f.txt')));
      expect(
        callScopeKey('code_change', input, { name: 'Write', args: { file_path: 'rel.txt' } }),
      ).toBe(byCwd);
      expect(callScopeKey('tool_use', input, { name: 'Shell', args: {} })).toBe(byCwd);
      expect(captureScopeKey({})).toBeUndefined();
    } finally {
      removeTrees([root]);
    }
  });
});
