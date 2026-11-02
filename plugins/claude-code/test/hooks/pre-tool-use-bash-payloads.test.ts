/**
 * What a Bash command writes to a file is scanned as code under that file, and
 * the command line itself drops the code_flaw rules only when such a payload
 * was found. Driven through the PreToolUse pipeline IN-PROCESS on a real store
 * in a temp home, under a block policy for the code-flaws pack.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, shippedRegexMatchers } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';

const pack = bundledDetections().find((p) =>
  p.rules.some((r) => r.id === 'code-flaws/deser-pickle'),
);

describe('a Bash command that writes code to a file', () => {
  let home: string;
  let dataDir: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-bash-payload-'));
    dataDir = join(home, '.aka', 'data');
    // Both variables, so no platform resolves the developer's own ~/.aka.
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    expect(pack, 'the code-flaws pack ships in the bundle').toBeDefined();
    const db = openLocalDatabase(dataDir, { shippedRegexMatchers: shippedRegexMatchers() });
    try {
      db.installedPacks.recordInventory(bundledDetections());
      if (pack) db.installedPacks.setPolicy(pack.namespace, pack.packId, 'block');
    } finally {
      db.close();
    }
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    removeTree(home);
  });

  async function run(tool: string, toolInput: Record<string, unknown>): Promise<HookOutput[]> {
    const out: HookOutput[] = [];
    await runPreToolUse(
      { tool_name: tool, tool_input: toolInput, session_id: 'payload-test', cwd: home },
      (output) => {
        out.push(output);
        return Promise.resolve();
      },
      { mode: 'hook' },
    );
    return out;
  }

  const denies = (outputs: readonly HookOutput[]): boolean =>
    outputs.some(
      (o) =>
        'hookSpecificOutput' in o &&
        (o.hookSpecificOutput as { permissionDecision?: string }).permissionDecision === 'deny',
    );

  async function findings(): Promise<{ ruleId: string; actionTaken: string }[]> {
    const db = openLocalDatabase(dataDir, { shippedRegexMatchers: shippedRegexMatchers() });
    try {
      const recent = await db.findings.recentFindings({ limit: 50 });
      return recent.map((f) => ({ ruleId: f.ruleId, actionTaken: f.actionTaken }));
    } finally {
      db.close();
    }
  }

  // The files findings are attributed to, as the findings page lists them.
  async function files(): Promise<string[]> {
    const db = openLocalDatabase(dataDir, { shippedRegexMatchers: shippedRegexMatchers() });
    try {
      return (await db.findings.listFindingLocations({})).items.map((l) => l.file);
    } finally {
      db.close();
    }
  }

  it('blocks a heredoc whose body carries a flaw, under the file the redirect names', async () => {
    const command = "cat > app.py <<'EOF'\nimport pickle\nobj = pickle.loads(blob)\nEOF\n";
    expect(denies(await run('Bash', { command }))).toBe(true);
    const hit = (await findings()).filter((f) => f.ruleId === 'code-flaws/deser-pickle');
    expect(hit).toHaveLength(1);
    expect(hit[0]?.actionTaken).toBe('block');
    expect(await files()).toEqual(['app.py']);
  });

  it('control: the same heredoc without a flaw passes', async () => {
    const command = "cat > app.py <<'EOF'\nx = 1\nEOF\n";
    expect(denies(await run('Bash', { command }))).toBe(false);
    expect(await findings()).toEqual([]);
  });

  it('still scans the command line when no payload was extracted from it', async () => {
    const command = "printf '%s\\n' 'obj = pickle.loads(blob)' > app.py";
    expect(denies(await run('Bash', { command }))).toBe(true);
    expect((await findings()).map((f) => f.ruleId)).toContain('code-flaws/deser-pickle');
  });

  it('keeps the code_flaw rules for an MCP tool argument that carries code', async () => {
    const out = await run('mcp__fs__write_file', {
      path: 'notes.txt',
      content: 'obj = pickle.loads(blob)',
    });
    expect(denies(out)).toBe(true);
    expect((await findings()).map((f) => f.ruleId)).toContain('code-flaws/deser-pickle');
  });
});
