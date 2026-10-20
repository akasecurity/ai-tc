import { afterEach, describe, expect, it, vi } from 'vitest';

import { captureStderr } from './stderr-capture.ts';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('captureStderr', () => {
  it('drops node runtime warnings from the filtered read and keeps them in the raw one', () => {
    const capture = captureStderr();
    process.stderr.write('(node:1) ExperimentalWarning: something\n');
    process.stderr.write('--trace-warnings ...\n');
    process.stderr.write('[aka] a line of our own\n');
    expect(capture.filtered()).toBe('[aka] a line of our own\n');
    expect(capture.raw()).toBe(
      '(node:1) ExperimentalWarning: something\n--trace-warnings ...\n[aka] a line of our own\n',
    );
  });

  it('keeps a chunk that only mentions the hint mid-line in the filtered read', () => {
    // Anchored: a hook line quoting the flag is not a node warning.
    const capture = captureStderr();
    process.stderr.write('[aka] run with --trace-warnings\n');
    expect(capture.filtered()).toBe('[aka] run with --trace-warnings\n');
  });

  it('forgets what was written on reset', () => {
    const capture = captureStderr();
    process.stderr.write('before\n');
    capture.reset();
    process.stderr.write('after\n');
    expect(capture.raw()).toBe('after\n');
  });
});
