import { describe, expect, it } from 'vitest';

import { COMMAND_SPECS } from '../command-manifest.ts';
import { completionHint, completionScript } from './completion.ts';

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
