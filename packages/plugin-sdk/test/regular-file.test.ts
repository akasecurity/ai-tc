import { execFileSync, spawnSync } from 'node:child_process';
import type * as FsModule from 'node:fs';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { readRegularFile } from '../src/regular-file.ts';
import { withNamedPipe } from './helpers/named-pipe.ts';

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof FsModule>();
  return {
    ...actual,
    readFileSync: vi.fn(actual.readFileSync),
    statSync: vi.fn(actual.statSync),
  };
});

const WINDOWS = process.platform === 'win32';
const CHILD_TIMEOUT_MS = 10_000;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-regular-file-'));
});

afterEach(() => {
  removeTree(dir);
});

describe('readRegularFile', () => {
  it('returns the text of a regular file', () => {
    const path = join(dir, 'file');
    writeFileSync(path, 'hello');

    expect(readRegularFile(path)).toBe('hello');
  });

  it('passes through the ENOENT of a missing path', () => {
    expect(() => readRegularFile(join(dir, 'missing'))).toThrow(
      expect.objectContaining({ code: 'ENOENT' }),
    );
  });

  it.skipIf(WINDOWS)('refuses a directory', () => {
    expect(() => readRegularFile(dir)).toThrow('not a regular file');
  });

  it('reads a file of exactly maxBytes and refuses one byte more', () => {
    const path = join(dir, 'file');
    writeFileSync(path, 'x'.repeat(16));
    expect(readRegularFile(path, 16)).toHaveLength(16);

    writeFileSync(path, 'x'.repeat(17));
    expect(() => readRegularFile(path, 16)).toThrow('file too large');
  });

  it.skipIf(WINDOWS)('refuses a named pipe that has a writer', () => {
    const path = join(dir, 'pipe');

    withNamedPipe(path, 'hello', () => {
      expect(() => readRegularFile(path)).toThrow('not a regular file');
    });
  });

  // Runs in a child process with a timeout: a blocking open of this pipe would never return, and
  // would hang this worker where no vitest timeout can reach it.
  it.skipIf(WINDOWS)('refuses a named pipe that has no writer without waiting', () => {
    const path = join(dir, 'pipe');
    execFileSync('mkfifo', [path]);
    const source = new URL('../src/regular-file.ts', import.meta.url).href;
    const script = `
      import { readRegularFile } from ${JSON.stringify(source)};
      try { readRegularFile(process.argv[1]); } catch (err) { console.log(err.message); }
    `;

    const child = spawnSync(process.execPath, ['--input-type=module', '-e', script, path], {
      encoding: 'utf8',
      timeout: CHILD_TIMEOUT_MS,
    });

    expect(child.signal).toBeNull();
    expect(child.stdout).toContain('not a regular file');
  });

  it('checks and reads through one descriptor, never the path a second time', () => {
    const path = join(dir, 'file');
    writeFileSync(path, 'hello');
    vi.mocked(statSync).mockClear();
    vi.mocked(readFileSync).mockClear();

    readRegularFile(path);

    expect(statSync).not.toHaveBeenCalled();
    expect(vi.mocked(readFileSync).mock.calls.map(([target]) => typeof target)).toEqual(['number']);
  });
});

describe('withNamedPipe', () => {
  it.skipIf(WINDOWS)('serves every read, so a second read cannot hang', () => {
    const path = join(dir, 'pipe');
    const read = (): string =>
      execFileSync('cat', [path], { encoding: 'utf8', timeout: CHILD_TIMEOUT_MS });

    withNamedPipe(path, 'hello', () => {
      expect(read()).toContain('hello');
      expect(read()).toContain('hello');
    });
  });
});
