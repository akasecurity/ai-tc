import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { findAgent } from '@akasecurity/local-ops';
import { MANAGED_PLUGIN_ADVICE } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runPlugins } from '../../src/commands/plugins.ts';

// `aka plugins list` on a machine where an organization's managed settings
// installed the Claude Code plugin.
//
// The list's installed column comes from the comparison reader, which drops a
// managed record that names no version. Such a row read `available`, and the
// footer pointed at `aka plugins install`, which refuses it as already
// installed. These cases hold the row to what the report and the refusals say.
//
// A controlled home: the list reads Claude Code's ledger and Codex's plugin
// cache out of it, and `--home` points at a directory with no store, so no
// store is opened or created. `os.homedir()` reads these two variables, and
// `n/no-process-env` is why the write goes through vitest.
let home: string;
let akaHome: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-plugins-list-'));
  akaHome = join(home, '.aka');
  vi.stubEnv('HOME', home);
  vi.stubEnv('USERPROFILE', home);
});

afterEach(() => {
  vi.unstubAllEnvs();
  removeTree(home);
});

function writeLedger(records: unknown[]): void {
  const dir = join(home, '.claude', 'plugins');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'ai-tc@akasecurity': records } }),
  );
}

async function list(): Promise<string> {
  let out = '';
  const spy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  try {
    await runPlugins(['list', '--home', akaHome]);
  } finally {
    spy.mockRestore();
  }
  return out;
}

const CLAUDE_CODE_NAME = findAgent('claude-code')?.name ?? 'claude-code agent missing';

/**
 * The state column of the Claude Code row: everything between the padded id
 * and the agent's name. Not a fixed-width slice, because a state longer than
 * its column (`installed v0.9.14`) pushes the name along rather than being cut.
 */
function claudeCodeState(out: string): string {
  const row = out.split('\n').find((line) => line.startsWith('  claude-code '));
  expect(row).toBeDefined();
  const rest = (row ?? '').slice(2 + 16 + 1);
  expect(rest.endsWith(` ${CLAUDE_CODE_NAME}`)).toBe(true);
  return rest.slice(0, -CLAUDE_CODE_NAME.length).trim();
}

describe('aka plugins list — an install an organization manages', () => {
  it('reads a managed record that names no version as managed, not available', async () => {
    writeLedger([{ scope: 'managed' }]);

    const out = await list();

    expect(claudeCodeState(out)).toBe('managed');
    expect(out).toContain(MANAGED_PLUGIN_ADVICE);
  });

  it('names the version a managed record carries', async () => {
    writeLedger([{ scope: 'managed', version: '0.9.14' }]);

    const out = await list();

    expect(claudeCodeState(out)).toBe('managed v0.9.14');
    expect(out).toContain(MANAGED_PLUGIN_ADVICE);
  });

  it('reads a user-scope install as installed (positive control)', async () => {
    writeLedger([{ scope: 'user', version: '0.9.14' }]);

    const out = await list();

    expect(claudeCodeState(out)).toBe('installed v0.9.14');
    expect(out).not.toContain(MANAGED_PLUGIN_ADVICE);
  });

  it('reads no install as available (positive control)', async () => {
    const out = await list();

    expect(claudeCodeState(out)).toBe('available');
    expect(out).not.toContain(MANAGED_PLUGIN_ADVICE);
  });
});
