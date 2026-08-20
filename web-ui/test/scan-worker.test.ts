import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SCAN_WORKER_RELATIVE_PATH, scanWorkerUrl } from '../app/lib/scan-worker.ts';

/**
 * `scanWorkerUrl()` is the one place that decides between the real worker and
 * the degraded (rules-dropped) path — see the file's own comment on why a
 * `next dev`/`next build`/`next start` invocation that bypasses turbo can reach
 * the missing-file branch. This pins that branch's one externally visible
 * effect: a line on stderr a developer staring at that terminal will see,
 * naming the path and how to fix it, without turning the missing worker into
 * a thrown error.
 */

let cwd: string;
let restoreStderr: (() => void) | undefined;

/** Every chunk written to stderr, joined — so `toContain` is a substring test. */
function captureStderr(): { lines: () => string; writes: () => number } {
  const written: string[] = [];
  const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  });
  restoreStderr = () => {
    spy.mockRestore();
  };
  return { lines: () => written.join(''), writes: () => written.length };
}

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'aka-web-scan-worker-'));
  vi.spyOn(process, 'cwd').mockReturnValue(cwd);
});

afterEach(() => {
  restoreStderr?.();
  restoreStderr = undefined;
  vi.restoreAllMocks();
});

describe('scanWorkerUrl', () => {
  it('resolves the built worker and writes nothing to stderr when it exists', () => {
    const stderr = captureStderr();
    const parts = SCAN_WORKER_RELATIVE_PATH.split('/');
    const file = parts.pop() ?? '';
    const dir = join(cwd, ...parts);
    mkdirSync(dir, { recursive: true });
    const path = join(dir, file);
    writeFileSync(path, '');

    expect(scanWorkerUrl()).toEqual(pathToFileURL(path));
    expect(stderr.writes()).toBe(0);
  });

  it('returns undefined and warns on stderr when it is missing', () => {
    const stderr = captureStderr();

    const result = scanWorkerUrl();

    expect(result).toBeUndefined();
    expect(stderr.writes()).toBe(1);
    expect(stderr.lines()).toContain(SCAN_WORKER_RELATIVE_PATH);
    expect(stderr.lines()).toContain('build:worker');
    expect(stderr.lines()).toContain('turbo run');
  });
});
