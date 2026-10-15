import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { dbPath, loadConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { scanWorktree } from '../src/scan.ts';

// Built at runtime so no credential-shaped literal sits in the source.
const fakeToken = (): string => ['gh', 'p_'].join('') + 'a1B2c3D4e5F6'.repeat(3);

function storedCaptureAttributes(): unknown[] {
  const db = new DatabaseSync(dbPath(home), { readOnly: true });
  try {
    const rows = db
      .prepare(`SELECT attributes FROM audit_events WHERE event_type = 'code_change'`)
      .all() as { attributes: string | null }[];
    return rows.map((row): unknown => JSON.parse(row.attributes ?? '{}'));
  } finally {
    db.close();
  }
}

let tmp: string;
let home: string;
let repo: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'aka-scan-secret-bearing-'));
  home = join(tmp, 'aka-home');
  repo = join(tmp, 'repo');
  mkdirSync(repo, { recursive: true });
});

afterEach(() => {
  removeTree(tmp);
});

describe('scanWorktree on secret-bearing files', () => {
  it('finds a secret planted in a dotenv file', async () => {
    writeFileSync(join(repo, '.env'), ['GITHUB', 'TOKEN'].join('_') + '=' + fakeToken() + '\n');
    writeFileSync(join(repo, 'app.ts'), 'export const answer = 42;\n');

    const summary = await scanWorktree(loadConfig(home), {
      sourceTool: 'claude-code',
      rootDir: repo,
    });

    expect(summary.scanned).toBe(2);
    expect(summary.byRule['secrets/github-pat']).toBe(1);
  });

  it('stores a dotenv capture as a whole-file snapshot, the mark that keeps it local', async () => {
    writeFileSync(join(repo, '.env'), ['GITHUB', 'TOKEN'].join('_') + '=' + fakeToken() + '\n');

    await scanWorktree(loadConfig(home), { sourceTool: 'claude-code', rootDir: repo });

    expect(storedCaptureAttributes()).toEqual([
      expect.objectContaining({ file_path: join(repo, '.env'), whole_file: true }),
    ]);
  });

  it('never reads AKA’s own home, even when it sits under the scanned root', async () => {
    const config = loadConfig(join(repo, 'nested-aka'));
    mkdirSync(join(repo, 'nested-aka'), { recursive: true });
    writeFileSync(
      join(repo, 'nested-aka', '.env'),
      ['GITHUB', 'TOKEN'].join('_') + '=' + fakeToken() + '\n',
    );

    const summary = await scanWorktree(config, { sourceTool: 'claude-code', rootDir: repo });

    expect(summary.findings).toBe(0);
  });
});
