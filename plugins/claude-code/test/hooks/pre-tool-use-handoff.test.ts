/**
 * What the PreToolUse pipeline does with a handoff note, driven IN-PROCESS so the
 * lines that decide it are measured (the e2e suite drives the same cases through
 * the built scripts, where v8 collects nothing). The pipeline is imported
 * directly: unlike a hook entry it runs nothing on import.
 *
 * A note stands in for a decision the mod's helper made and a grant it spent. It
 * is a file, so the hook keeps looking at the fields that execute: a planted note
 * for a value the policy blocks, or for a call holding a pointer, does not let the
 * call through, while the note the helper leaves for a value it let through does.
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
import { authorizeValues, recordToolHandoff } from '../../src/mod/handoff.ts';

const RULE_ID = 'secrets/twilio-key';
const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
const SECRET = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0] ?? '';
// Spelled by joining so no pointer-shaped literal sits in the source.
const POINTER = ['[[aka:secret:', 'AB.', 'C'.repeat(26), '.', 'D'.repeat(16), ']]'].join('');

describe('a handoff note is not taken at its word for the fields that execute', () => {
  let home: string;
  let dataDir: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-pre-tool-use-note-'));
    dataDir = join(home, '.aka', 'data');
    // Both variables, so no platform resolves the developer's own ~/.aka.
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    expect(pack, 'the twilio rule ships in a bundled pack').toBeDefined();
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
      { tool_name: tool, tool_input: toolInput, session_id: 'note-test', cwd: home },
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

  const bash = { command: `deploy --key ${SECRET}` };

  it('control: with no note the blocked value is denied', async () => {
    expect(denies(await run('Bash', bash))).toBe(true);
  });

  it('a planted note for a blocked value in a command does not bypass the deny', async () => {
    recordToolHandoff(dataDir, 'Bash', bash);

    expect(denies(await run('Bash', bash))).toBe(true);
  });

  it('a note that names another value does not vouch for this one', async () => {
    recordToolHandoff(
      dataDir,
      'Bash',
      bash,
      Date.now(),
      authorizeValues(dataDir, ['something-else']),
    );

    expect(denies(await run('Bash', bash))).toBe(true);
  });

  it('the note the helper leaves for the value it let through is honoured, once', async () => {
    recordToolHandoff(dataDir, 'Bash', bash, Date.now(), authorizeValues(dataDir, [SECRET]));

    expect(await run('Bash', bash)).toEqual([]);
    // Spent: the same call again is an ordinary call.
    expect(denies(await run('Bash', bash))).toBe(true);
  });

  it('a pointer left in a command voids the note, and the pointer is denied', async () => {
    const withPointer = { command: `deploy --token ${POINTER}` };
    recordToolHandoff(dataDir, 'Bash', withPointer);

    expect(denies(await run('Bash', withPointer))).toBe(true);
  });

  it('a call with nothing that executes is taken from the note', async () => {
    const write = { file_path: join(home, 'notes.txt'), content: 'plain text' };
    recordToolHandoff(dataDir, 'Write', write);

    expect(await run('Write', write)).toEqual([]);
  });
});
