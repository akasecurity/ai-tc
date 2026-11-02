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

  it('drops code_flaw rules only inside the written payload, not on the rest of the command', async () => {
    // The echo into a .txt is a payload (judged as .txt, so no .py rule); the
    // python -c after it is code on the command line and keeps its rules.
    const mixed = 'echo "x" > a.txt; python -c "import pickle; pickle.loads(b)"';
    expect(denies(await run('Bash', { command: mixed }))).toBe(true);
    expect((await findings()).map((f) => f.ruleId)).toContain('code-flaws/deser-pickle');
  });

  it('control: a pure file write whose text only looks like code on the command line passes', async () => {
    const command = 'echo "obj = pickle.loads(blob)" > notes.txt';
    expect(denies(await run('Bash', { command }))).toBe(false);
    expect(await findings()).toEqual([]);
  });

  it('extracts both heredocs opened on one marker line', async () => {
    const command = 'cat <<A > a.txt; cat <<B > b.py\nx = 1\nA\nobj = pickle.loads(blob)\nB\n';
    expect(denies(await run('Bash', { command }))).toBe(true);
    expect(await files()).toEqual(['b.py']);
  });

  it('names the file past a stderr or /dev/null redirect on the marker line', async () => {
    const command = 'cat <<EOF 2>/dev/null > app.py\nobj = pickle.loads(blob)\nEOF\n';
    expect(denies(await run('Bash', { command }))).toBe(true);
    expect(await files()).toEqual(['app.py']);
  });

  it('scans a heredoc fed to an interpreter as the command, not as the file its stdout goes to', async () => {
    const command = 'python - <<EOF > out.txt\nimport pickle\npickle.loads(b)\nEOF\n';
    expect(denies(await run('Bash', { command }))).toBe(true);
  });

  it('scans a body written to a name it cannot resolve as code with no extension scope', async () => {
    const command = 'cat > "$F" <<EOF\nobj = pickle.loads(blob)\nEOF\n';
    expect(denies(await run('Bash', { command }))).toBe(true);
  });

  it('keeps the rules on the whole command when a cap is hit', async () => {
    const writes = Array.from({ length: 33 }, (_, i) => `echo "a" > f${String(i)}.txt`).join('\n');
    const command = `${writes}\npython -c "import pickle; pickle.loads(b)"`;
    expect(denies(await run('Bash', { command }))).toBe(true);
  });

  it('keeps the rules on a command whose heredoc it cannot follow', async () => {
    const command = 'cat <<$D > a.txt\nx\n$D\npython -c "pickle.loads(b)"';
    expect(denies(await run('Bash', { command }))).toBe(true);
  });
});
