import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { COMMAND_SPECS, commandsHelp, GLOBAL_FLAGS } from '../../src/command-manifest.ts';
import { completionHint, completionScript } from '../../src/commands/completion.ts';

const commandNames = COMMAND_SPECS.map((s) => s.name);

describe('completionScript', () => {
  it('returns undefined for unsupported shells', () => {
    expect(completionScript('fish')).toBeUndefined();
    expect(completionScript('')).toBeUndefined();
  });

  it('includes the `completion` command itself', () => {
    // Regression guard: `completion` originally shipped missing from its own
    // scripts because the command list was hand-maintained separately.
    expect(commandNames).toContain('completion');
    for (const shell of ['zsh', 'bash'] as const) {
      const script = completionScript(shell) ?? '';
      expect(script).toContain('completion');
      expect(script).toContain('zsh');
      expect(script).toContain('bash');
    }
  });

  it('lists every manifest command in both shells', () => {
    for (const shell of ['zsh', 'bash'] as const) {
      const script = completionScript(shell) ?? '';
      for (const name of commandNames) expect(script).toContain(name);
    }
  });

  it('emits a zsh script that guards compinit and registers _aka', () => {
    const zsh = completionScript('zsh') ?? '';
    expect(zsh).toContain('#compdef aka');
    expect(zsh).toContain('$+functions[compdef]'); // stock-zsh guard (no compinit)
    expect(zsh).toContain('compdef _aka aka');
  });

  it('emits a bash script that defers file completion to readline', () => {
    const bash = completionScript('bash') ?? '';
    expect(bash).toContain('complete -o default -F _aka aka');
    // No hand-rolled `compgen -f` — it word-split filenames and skipped dir slashes.
    expect(bash).not.toContain('compgen -f');
  });

  it('completes global flags after any command in both shells', () => {
    for (const shell of ['zsh', 'bash'] as const) {
      const script = completionScript(shell) ?? '';
      for (const flag of ['--home', '--version', '--help']) expect(script).toContain(flag);
    }
  });

  /**
   * A flag one command owns is offered after THAT command and nowhere else.
   * Derived from the manifest, so a second such flag joins these assertions by
   * being declared rather than by somebody remembering this file.
   *
   * The negative half is the point: `GLOBAL_FLAGS` is what every command
   * honours, and a command-only flag that leaked into that list would be
   * suggested after `aka stats`, where `parseArgs` rejects it outright.
   */
  const COMMAND_FLAGS = COMMAND_SPECS.flatMap((s) => (s.flags ?? []).map((f) => [s.name, f.name]));

  it('has at least one command-owned flag to check', () => {
    expect(COMMAND_FLAGS.length).toBeGreaterThan(0);
  });

  it.each(COMMAND_FLAGS)('offers %s its own %s, scoped to that command', (command, flag) => {
    expect(GLOBAL_FLAGS).not.toContain(flag);
    for (const shell of ['zsh', 'bash'] as const) {
      const script = completionScript(shell) ?? '';
      // The arm carries the command name and the flag together, so a flag added
      // to the unconditional list would not satisfy this.
      const arm = script.split('\n').find((line) => line.includes(flag));
      expect(arm).toBeDefined();
      expect(arm).toContain(`${command})`);
    }
  });

  it.each(COMMAND_FLAGS)("documents %s's %s under that command in the help", (command, flag) => {
    const lines = commandsHelp().split('\n');
    const at = lines.findIndex((line) => line.trimStart().startsWith(`${command} `));
    expect(at).toBeGreaterThanOrEqual(0);
    // Directly under its command, not filed anywhere else in the block.
    expect(lines[at + 1]).toContain(flag);
  });

  it('completes the exception verbs in both shells', () => {
    for (const shell of ['zsh', 'bash'] as const) {
      const script = completionScript(shell) ?? '';
      for (const verb of ['approve', 'add', 'list', 'show', 'revoke', 'rotate-key']) {
        expect(script).toContain(verb);
      }
    }
  });
});

describe('completionHint', () => {
  it('points at the right rc file and the load-once command for each shell', () => {
    expect(completionHint('zsh')).toContain('~/.zshrc');
    expect(completionHint('zsh')).toContain('source <(aka completion zsh)');
    expect(completionHint('bash')).toContain('~/.bashrc');
    expect(completionHint('bash')).toContain('source <(aka completion bash)');
  });
});

describe('the emitted scripts parse in their shells', () => {
  // A substring assertion cannot see a quoting bug; only the shell can. The
  // scripts are written out and handed to the shell's own parser. Skipped,
  // never failed, where the shell is absent (Windows CI has neither).
  const dirs: string[] = [];
  afterEach(() => {
    removeTrees(dirs.splice(0));
  });

  it.each(['zsh', 'bash'] as const)('%s -n accepts the emitted script', (shell) => {
    const probe = spawnSync(shell, ['-c', 'true'], { stdio: 'ignore' });
    if (probe.error !== undefined || probe.status !== 0) return;
    const dir = mkdtempSync(join(tmpdir(), 'aka-completion-'));
    dirs.push(dir);
    const file = join(dir, `aka.${shell}`);
    writeFileSync(file, completionScript(shell) ?? '');
    const check = spawnSync(shell, ['-n', file], { encoding: 'utf8' });
    expect(check.status, check.stderr).toBe(0);
  });
});
