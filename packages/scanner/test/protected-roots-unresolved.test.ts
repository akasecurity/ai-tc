import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { scanWorktree } from '../src/scan.ts';
import { walkSourceFiles } from '../src/walk.ts';

vi.mock('@akasecurity/plugin-sdk', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    protectedScanRoots: () => {
      throw new Error('no home directory');
    },
  };
});

let tmp: string;
let repo: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'aka-scan-no-home-'));
  repo = join(tmp, 'repo');
  mkdirSync(repo, { recursive: true });
  writeFileSync(join(repo, 'app.ts'), 'export const answer = 42;\n');
});

afterEach(() => {
  removeTree(tmp);
});

describe('a scan whose protected paths cannot be resolved', () => {
  it('throws from the walk instead of yielding nothing', () => {
    expect(() => [...walkSourceFiles({ rootDir: repo })]).toThrow(/nothing was scanned/);
  });

  it('rejects the worktree scan, which the scan command reports as not completed', async () => {
    await expect(
      scanWorktree(loadConfig(join(tmp, 'aka-home')), { sourceTool: 'claude-code', rootDir: repo }),
    ).rejects.toThrow(/nothing was scanned/);
  });
});
