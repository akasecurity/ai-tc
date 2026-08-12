import { describe, expect, it } from 'vitest';

import { createCliPluginManager } from '../src/cli-plugin-manager.ts';

// The two host CLIs share the `<bin> plugin …` SHAPE and nothing else. Treating
// their verbs as interchangeable is what shipped `codex plugin install
// aka-codex@ai-tc` to users, which Codex rejects with "unrecognized subcommand"
// — every install and update through the Codex path failed. Pin each host's
// verbs against its real CLI, and pin that the hint copy and the spawned
// command are the same string: hint copy is the surface the user retypes, so a
// hint that drifts from the spawn fails in the user's terminal rather than here.

describe('claude verbs', () => {
  const claude = createCliPluginManager('claude');

  it('installs with `plugin install <ref>`', () => {
    expect(claude.installSteps('ai-tc@akasecurity')).toEqual([
      ['plugin', 'install', 'ai-tc@akasecurity'],
    ]);
  });

  it('updates with `plugin update <ref>`, ignoring the marketplace name', () => {
    expect(claude.updateSteps('ai-tc@akasecurity', 'akasecurity')).toEqual([
      ['plugin', 'update', 'ai-tc@akasecurity'],
    ]);
  });
});

describe('codex verbs', () => {
  const codex = createCliPluginManager('codex');

  it('installs with `plugin add <ref>` — codex has no `install` subcommand', () => {
    expect(codex.installSteps('aka-codex@ai-tc')).toEqual([['plugin', 'add', 'aka-codex@ai-tc']]);
  });

  it('updates by refreshing the snapshot then re-adding — codex has no `update` subcommand', () => {
    expect(codex.updateSteps('aka-codex@ai-tc', 'ai-tc')).toEqual([
      ['plugin', 'marketplace', 'upgrade', 'ai-tc'],
      ['plugin', 'add', 'aka-codex@ai-tc'],
    ]);
  });

  it('skips the snapshot refresh when no marketplace name is known', () => {
    expect(codex.updateSteps('aka-codex@ai-tc')).toEqual([['plugin', 'add', 'aka-codex@ai-tc']]);
  });
});

describe('no host emits a verb its CLI does not have', () => {
  // Verified against codex-cli 0.147.0 (`codex plugin --help`): add, list,
  // marketplace, remove — and `codex plugin marketplace`: add, list, upgrade,
  // remove. Claude Code's `claude plugin --help` carries install and update.
  const KNOWN_VERBS: Record<'claude' | 'codex', Set<string>> = {
    claude: new Set(['install', 'update', 'uninstall', 'marketplace', 'list', 'enable', 'disable']),
    codex: new Set(['add', 'remove', 'marketplace', 'list']),
  };

  for (const bin of ['claude', 'codex'] as const) {
    it(bin, () => {
      const manager = createCliPluginManager(bin);
      const steps = [
        ...manager.installSteps('p@m'),
        ...manager.updateSteps('p@m', 'm'),
        ['plugin', 'marketplace', 'add', 'owner/repo'],
      ];
      expect(steps.length).toBeGreaterThan(0);
      for (const args of steps) {
        expect(args[0]).toBe('plugin');
        expect(KNOWN_VERBS[bin]).toContain(args[1]);
      }
    });
  }
});

describe('hint copy is the command that runs', () => {
  for (const bin of ['claude', 'codex'] as const) {
    it(bin, () => {
      const manager = createCliPluginManager(bin);
      expect(manager.installCommands('p@m')).toEqual(
        manager.installSteps('p@m').map((args) => `${bin} ${args.join(' ')}`),
      );
      expect(manager.updateCommands('p@m', 'm')).toEqual(
        manager.updateSteps('p@m', 'm').map((args) => `${bin} ${args.join(' ')}`),
      );
    });
  }
});
